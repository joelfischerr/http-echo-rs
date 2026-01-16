use anyhow::Result;
use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{self, HeaderMap, HeaderName, StatusCode, Version},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use clap::Parser;
use futures_util::StreamExt;
use std::{collections::HashMap, str::FromStr, sync::Arc, sync::Mutex, time::Duration};
use tokio::signal::unix::{signal, SignalKind};

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};

use modsecurity::{transaction::Transaction, ModSecurity, Rules};

use albedo_rust::build_router;

// #[derive(Clone)]
struct AppState {
    ms: ModSecurity,
    rules: Rules,
    log_file: Arc<Mutex<BufWriter<File>>>,
}

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    address: String,

    #[arg(short = 'H', long = "header")]
    headers: Option<Vec<String>>,

    #[arg(short = 'e', long = "echo-header")]
    header_echos: Option<Vec<String>>,

    #[arg(short = 'd', long = "us-delay", default_value = "0")]
    delay_us: u64,

    #[arg(short = 'c', long = "config", num_args = 1.., value_delimiter = ' ')]
    rules_vec: Vec<String>,

    #[arg(long = "useWAF")]
    use_waf: bool,
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let Args {
        address,
        headers,
        header_echos,
        delay_us,
        rules_vec,
        use_waf,
    } = Args::parse();

    // let headers = headers
    //     .unwrap_or(vec![])
    //     .iter()
    //     .map(|h| {
    //         let hs: Vec<&str> = h.split_terminator(":").map(|s| s.trim()).collect();
    //         (hs[0].to_string(), hs[1].to_string())
    //     })
    //     .collect::<HashMap<String, String>>();
    // let header_echos = header_echos.unwrap_or_default();

    // let echo = post(move |req_hdrs: HeaderMap, body: Bytes| {
    //     log::trace!("Received request: {:?}", req_hdrs);
    //     // this helps simulating slower backends
    //     if delay_us > 0 {
    //         std::thread::sleep(Duration::from_micros(delay_us));
    //     }

    //     let mut res_hdrs = HeaderMap::new();
    //     for (key, val) in headers.into_iter() {
    //         let key = HeaderName::from_str(key.as_str()).unwrap();
    //         res_hdrs.insert(key, val.parse().unwrap());
    //     }

    //     req_hdrs
    //         .iter()
    //         .filter(|(k, _)| header_echos.contains(&k.to_string()))
    //         .for_each(|(k, v)| {
    //             res_hdrs.insert(k, v.clone());
    //         });

    //     echo(res_hdrs, body)
    // });

    let state: Arc<AppState> = configure_modsecurity_to_state(rules_vec);

    // build our application with a route
    // let mut app: Router = Router::new()
    //     .route("/", echo.clone())
    //     // This only matches one level of nesting!
    //     // .route("/{path}", echo)
    //     .route("/speed", post(reply_200()))
    //     .route("/", get(reply_200()))
    //     .route("/speed", get(reply_200()))
    //     .route("/{*path}", get(reply_200()));

    let mut app: axum::routing::Router = build_router();

    if use_waf {
        println!("Use WAF flag set, configure modsecurity as middleware");
        app = app.layer(middleware::from_fn_with_state(
            state.clone(),
            execute_modsecurity,
        ));
    }

    let app = app;

    let listener = tokio::net::TcpListener::bind(address.clone())
        .await
        .unwrap();
    log::info!("Listening on {}", address);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

fn reply_200() -> StatusCode {
    StatusCode::OK
}

// TODO: Actually load the configured rules
fn configure_modsecurity_to_state(rules_vec: Vec<String>) -> Arc<AppState> {
    let file: File = OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/audit/audit.log")
        .unwrap();

    let writer: BufWriter<File> = BufWriter::new(file);

    let ms = ModSecurity::builder().with_log_callbacks().build();

    let mut rules = Rules::new();

    rules
        .add_plain(
            r#"SecAction "id:900005,\
      phase:1,\
      nolog,\
      pass,\
      ctl:ruleEngine=DetectionOnly,\
      ctl:ruleRemoveById=910000,\
      setvar:tx.blocking_paranoia_level=4,\
      setvar:tx.crs_validate_utf8_encoding=1,\
      setvar:tx.arg_name_length=100,\
      setvar:tx.arg_length=400,\
      setvar:tx.total_arg_length=64000,\
      setvar:tx.max_num_args=255,\
      setvar:tx.max_file_size=64100,\
      setvar:tx.combined_file_sizes=65535"#,
        )
        .unwrap();

    rules
        .add_plain(
            r#"
           SecResponseBodyMimeType text/plain
           SecDefaultAction "phase:3,log,auditlog,pass"
           SecDefaultAction "phase:4,log,auditlog,pass"
           SecDefaultAction "phase:5,log,auditlog,pass"

           # Rule 900005 from https://github.com/coreruleset/coreruleset/blob/v4.0/dev/tests/regression/README.md#requirements
           SecAction "id:900005,\
             phase:1,\
             nolog,\
             pass,\
             ctl:ruleEngine=DetectionOnly,\
             ctl:ruleRemoveById=910000,\
             setvar:tx.blocking_paranoia_level=4,\
             setvar:tx.crs_validate_utf8_encoding=1,\
             setvar:tx.arg_name_length=100,\
             setvar:tx.arg_length=400,\
             setvar:tx.total_arg_length=64000,\
             setvar:tx.max_num_args=255,\
             setvar:tx.max_file_size=64100,\
             setvar:tx.combined_file_sizes=65535"

           # Write the value from the X-CRS-Test header as a marker to the log
           # Requests with X-CRS-Test header will not be matched by any rule. See https://github.com/coreruleset/go-ftw/pull/133
           SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
             "id:999999,\
             phase:1,\
             pass,\
             t:none,\
             log,\
             auditlog,\
             msg:'X-CRS-Test %{MATCHED_VAR}',\
             ctl:ruleRemoveById=1-999999"
           "#,
        )
        .expect("Failed to add rules");

    // rules
    //     .add_plain("SecAuditLog logs/audit/audit-2.log")
    //     .expect("Failed to add rules");

    // rules
    //     .add_plain(
    //         r#"
    //     SecDebugLog logs/audit/debug.log
    //     SecDebugLogLevel 9
    //     "#,
    //     )
    //     .unwrap();

    rules
        .add_plain(
            r#"# Force Reporting Level to 5 (Unconditional)
    SecAction \
        "id:999998,\
        phase:1,\
        pass,\
        nolog,\
        setvar:tx.reporting_level=5"

        # Inbound and outbound - all requests
        SecAction \
            "id:999996,\
            phase:5,\
            pass,\
            t:none,\
            noauditlog,\
            severity:'CRITICAL',\
            msg:'Anomaly Scores: \
        (Inbound Scores: blocking=%{tx.blocking_inbound_anomaly_score}, detection=%{tx.detection_inbound_anomaly_score}, per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4}, threshold=%{tx.inbound_anomaly_score_threshold}) - \
        (Outbound Scores: blocking=%{tx.blocking_outbound_anomaly_score}, detection=%{tx.detection_outbound_anomaly_score}, per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4}, threshold=%{tx.outbound_anomaly_score_threshold}) - \
        (SQLI=%{tx.sql_injection_score}, XSS=%{tx.xss_score}, RFI=%{tx.rfi_score}, LFI=%{tx.lfi_score}, RCE=%{tx.rce_score}, PHPI=%{tx.php_injection_score}, HTTP=%{tx.http_violation_score}, SESS=%{tx.session_fixation_score}, COMBINED_SCORE=%{tx.anomaly_score})',\
            tag:'reporting',\
            tag:'OWASP_CRS',\
            ver:'OWASP_CRS/4.21.0'"
        "#,
        )
        .unwrap();

    for rule in rules_vec.iter() {
        println!("Adding rules from file: {}", rule);
        rules.add_file(rule).expect("Adding rules failed!");
    }

    let state = Arc::new(AppState {
        ms: ms,
        rules: rules,
        log_file: Arc::new(Mutex::new(writer)),
    });

    return state;
}

async fn execute_modsecurity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    println!("Processing request with headers {:#?}", headers);
    log::trace!("Processing request with headers {:#?}", headers);
    let movablestate = state.clone();

    log::trace!("Processing request");

    let mut transaction: Transaction = state
        .ms
        .transaction_builder()
        .with_rules(&state.rules)
        .with_logging(move |_msg| {
            log::trace!("Log callback called!");
            println!("002 Received log: {}", _msg.unwrap_or_default());

            let mut log_file_writer = movablestate.log_file.lock().unwrap();
            writeln!(
                log_file_writer,
                "002 Received log: {}",
                _msg.unwrap_or_default()
            )
            .unwrap();

            // TODO: This is super inefficient. We should flush opportunistically after the response.
            log_file_writer.flush().unwrap();
        })
        .build()
        .unwrap();

    let request_http_version = map_http_version(request.version());

    println!(
        "Processing request with http version {}",
        request_http_version
    );

    log::trace!("Process connection");
    transaction
        .process_connection("127.0.0.1", 1234, "127.0.0.1", 8080)
        .unwrap();

    log::trace!("Process uri");
    transaction
        .process_uri(
            &request.uri().to_string(),
            &request.method().as_str(),
            &request_http_version,
        )
        .unwrap();

    for (key, val) in headers.iter() {
        let key_str = key.as_str();

        if http::HeaderValue::from_bytes(val.as_bytes()).is_err() {
            return Err(StatusCode::BAD_REQUEST);
        }

        // If we we can create a valid header value it is also valid utf-8
        let val_str = str::from_utf8(val.as_bytes()).unwrap();
        transaction.add_request_header(key_str, val_str).unwrap();
    }

    log::trace!("Process request headers");
    transaction.process_request_headers().unwrap();

    {
        let mut log_file_writer = state.log_file.lock().unwrap();
        if let Some(raw_status_code) =
            check_for_intervention(&mut transaction, &mut log_file_writer)
        {
            process_logging(&mut transaction, &mut log_file_writer);
            check_for_intervention(&mut transaction, &mut log_file_writer);
            return Err(raw_status_code);
        }
    }

    let (parts, body) = request.into_parts();

    let mut body_chunks = Vec::new();
    let mut stream = body.into_data_stream();

    while let Some(result) = stream.next().await {
        if let Ok(chunk) = result {
            transaction.append_request_body(&chunk[..]).unwrap();
            body_chunks.push(chunk);
        }
    }

    // The idea for the body is to get the whole body, do ModSecurity and then copy the body back into the request.
    // This seems super wasteful, but is what axum has in their examples: https://github.com/tokio-rs/axum/blob/3b92cd7593a900d3c79c2aeb411f90be052a9a5c/examples/consume-body-in-extractor-or-middleware/src/main.rs#L58
    // transaction.append_request_body(&bytes).unwrap();
    log::trace!("Process request body");
    transaction.process_request_body().unwrap();

    {
        let mut log_file_writer = state.log_file.lock().unwrap();
        if let Some(raw_status_code) =
            check_for_intervention(&mut transaction, &mut log_file_writer)
        {
            process_logging(&mut transaction, &mut log_file_writer);
            check_for_intervention(&mut transaction, &mut log_file_writer);
            return Err(raw_status_code);
        }
    }

    let stream_body = Body::from_stream(tokio_stream::iter(
        body_chunks.into_iter().map(Ok::<Bytes, axum::Error>),
    ));
    let reassembled_request = Request::from_parts(parts, stream_body);

    let response = next.run(reassembled_request).await;

    let response_http_version = map_http_version(response.version());

    for (key, val) in response.headers().iter() {
        let key_str = key.as_str();
        let val_str = val.to_str().unwrap();
        log::trace!("Adding response header: {}={}", key_str, val_str);
        transaction.add_response_header(key_str, val_str).unwrap();
    }

    if !response.headers().contains_key("Content-Type") {
        transaction
            .add_response_header("Content-Type", "text/plain")
            .unwrap();
    }

    log::trace!("Process response headers: {}", response.headers().len());
    transaction
        .process_response_headers(response.status().as_u16().into(), &response_http_version)
        .unwrap();

    {
        let mut log_file_writer = state.log_file.lock().unwrap();
        if let Some(raw_status_code) =
            check_for_intervention(&mut transaction, &mut log_file_writer)
        {
            process_logging(&mut transaction, &mut log_file_writer);
            check_for_intervention(&mut transaction, &mut log_file_writer);
            return Err(raw_status_code);
        }
    }

    let (parts, body) = response.into_parts();

    let mut body_chunks = Vec::new();
    let mut stream = body.into_data_stream();

    while let Some(result) = stream.next().await {
        if let Ok(chunk) = result {
            log::trace!("Processing body chunk {}", String::from_utf8_lossy(&chunk));
            transaction.append_response_body(&chunk[..]).unwrap();
            body_chunks.push(chunk);
        }
    }

    log::trace!("Start process response body");
    transaction.process_response_body().unwrap();

    {
        let mut log_file_writer = state.log_file.lock().unwrap();
        if let Some(raw_status_code) =
            check_for_intervention(&mut transaction, &mut log_file_writer)
        {
            log::trace!(
                "Intervention generated when processing response body {}",
                raw_status_code
            );
            process_logging(&mut transaction, &mut log_file_writer);
            check_for_intervention(&mut transaction, &mut log_file_writer);
            return Err(raw_status_code);
        } else {
            log::trace!("No intervention generated when processing response body");
        }
    }

    log::trace!("Finish process response body");

    // Phase 5: Logging
    // Execute the phase 5 rules
    // We also do this before the premature returns if there were
    // previous interventions that cause the request to be
    // immediately dismissed.
    {
        let mut log_file_writer = state.log_file.lock().unwrap();
        process_logging(&mut transaction, &mut log_file_writer);
    }

    let new_body = Body::from_stream(tokio_stream::iter(
        body_chunks.into_iter().map(Ok::<Bytes, axum::Error>),
    ));

    let new_response = Response::from_parts(parts, new_body);
    return std::result::Result::Ok(new_response);
}

fn map_http_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => panic!("This is not allowed!"),
    }
}

fn process_logging(transaction: &mut modsecurity::Transaction, writer: &mut BufWriter<File>) {
    log::trace!("Start process logging!");
    transaction.process_logging().unwrap();
    // Apparently this triggers the log callback ...
    if let Some(intervention) = transaction.intervention() {
        if let Some(log) = intervention.log() {
            println!("004 Received log: {}", log);

            writeln!(writer, "004 Received log: {}", log).unwrap();
            // TODO: This is super inefficient. We should flush opportunistically after the response.
            writer.flush().unwrap();
        } else {
            log::trace!("No log when processing logging")
        }
    } else {
        log::trace!("No intervention when processing logging")
    }
    log::trace!("Finish process logging!")
}

fn check_for_intervention(
    transaction: &mut modsecurity::Transaction,
    writer: &mut BufWriter<File>,
) -> Option<StatusCode> {
    log::trace!("Start process intervention!");
    if let Some(intervention) = transaction.intervention() {
        println!(
            "001 Received log: {}",
            intervention.log().expect("Expected log")
        );

        writeln!(writer, "001 Received log: {}", intervention.log().unwrap()).unwrap();
        // TODO: This is super inefficient. We should flush opportunistically after the response.
        writer.flush().unwrap();

        if intervention.disruptive() {
            let status_code = intervention.status() as u16;
            return StatusCode::from_u16(status_code).ok();
        } else {
            log::trace!("Non-disruptive intervention");
        }
    } else {
        log::trace!("No intervention when processing intervention")
    }
    log::trace!("Finish process intervention!");
    return None;
}

fn test_modsecurity(ms: &ModSecurity, rules: &Rules) {
    let mut transaction = ms
        .transaction_builder()
        .with_rules(&rules)
        .build()
        .expect("Error building transaction");

    transaction
        .process_uri("http://example.com/admin", "GET", "1.1")
        .expect("Error processing URI");
    transaction
        .process_request_headers()
        .expect("Error processing request headers");

    let intervention = transaction.intervention().expect("Expected intervention");

    assert_eq!(intervention.status(), 401);
}

async fn echo(headers: HeaderMap, body: Bytes) -> Result<impl IntoResponse, StatusCode> {
    if let std::result::Result::Ok(body) = String::from_utf8(body.to_vec()) {
        std::result::Result::Ok((headers, body))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn shutdown_signal() {
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}
