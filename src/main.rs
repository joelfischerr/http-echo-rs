use anyhow::Result;
use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{self, HeaderMap, StatusCode, Version},
    middleware::{self, Next},
    response::Response,
};
use clap::Parser;
use crossbeam::channel::Sender;
use futures_util::StreamExt;
use std::{sync::Arc, thread};
use tokio::signal::unix::{signal, SignalKind};

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};

use modsecurity::{transaction::Transaction, ModSecurity, Rules};

use albedo_rs::build_router;

type InnerChannelType = Box<str>;

// #[derive(Clone)]
struct AppState {
    ms: ModSecurity,
    rules: Rules,
    log_file: Arc<Sender<InnerChannelType>>,
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

    let log_file_location = "logs/audit/audit.log";

    // let (tx, rx) = mpsc::channel::<InnerChannelType();
    let (tx, rx) = crossbeam::channel::bounded::<InnerChannelType>(100_000);

    thread::spawn(move || {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file_location)
            .unwrap();
        // Increasing the capacity can increase performance, but increasing it too much will break the go-ftw tests.
        let mut writer = BufWriter::with_capacity(8 * 1024, file);

        // blocks until messages arrive
        // when tx is dropped this exists
        for msg in rx {
            // let _ = writeln!(writer, "Log: {}", msg);
            let _ = writer.write_all(msg.as_bytes());
        }
        writer.flush().unwrap();
    });

    let Args {
        address,
        headers: _,
        header_echos: _,
        delay_us: _,
        rules_vec,
        use_waf,
    } = Args::parse();

    let state: Arc<AppState> = configure_modsecurity_to_state(tx, rules_vec);

    let mut app: axum::routing::Router = build_router();

    if use_waf {
        // log::trace!("Use WAF flag set, configure modsecurity as middleware");
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

fn configure_modsecurity_to_state(
    tx: Sender<InnerChannelType>,
    rules_vec: Vec<String>,
) -> Arc<AppState> {
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
        // log::trace!("Adding rules from file: {}", rule);
        rules.add_file(rule).expect("Adding rules failed!");
    }

    let state = Arc::new(AppState {
        ms: ms,
        rules: rules,
        // log_file: Arc::new(Mutex::new(tx)),
        log_file: Arc::new(tx),
    });

    return state;
}

async fn execute_modsecurity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    // log::trace!("Processing request with headers {:#?}", headers);
    let movablestate = state.clone();
    let movedstate = state.clone();

    let mut transaction: Transaction = movablestate
        .ms
        .transaction_builder()
        .with_rules(&movablestate.rules)
        .with_logging(move |_msg: Option<&str>| {
            if let Some(_msg) = _msg {
                let _ = movedstate.log_file.send(_msg.into());
            }
        })
        .build()
        .unwrap();

    let request_http_version = map_http_version(request.version());

    // log::trace!(
    // "Processing request with http version {}",
    // request_http_version
    // );

    // log::trace!("Process connection");
    transaction
        .process_connection("127.0.0.1", 1234, "127.0.0.1", 8080)
        .unwrap();

    // log::trace!("Process uri");
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

    // log::trace!("Process request headers");
    transaction.process_request_headers().unwrap();

    {
        // let mut log_file_writer = state;
        if let Some(raw_status_code) = check_for_intervention(&mut transaction, &state) {
            process_logging(&mut transaction, &state);
            check_for_intervention(&mut transaction, &state);
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
    // log::trace!("Process request body");
    transaction.process_request_body().unwrap();

    {
        // let mut log_file_writer = state.log_file;
        if let Some(raw_status_code) = check_for_intervention(&mut transaction, &state) {
            process_logging(&mut transaction, &state);
            check_for_intervention(&mut transaction, &state);
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
        // log::trace!("Adding response header: {}={}", key_str, val_str);
        transaction.add_response_header(key_str, val_str).unwrap();
    }

    if !response.headers().contains_key("Content-Type") {
        transaction
            .add_response_header("Content-Type", "text/plain")
            .unwrap();
    }

    // log::trace!("Process response headers: {}", response.headers().len());
    transaction
        .process_response_headers(response.status().as_u16().into(), &response_http_version)
        .unwrap();

    {
        if let Some(raw_status_code) = check_for_intervention(&mut transaction, &state) {
            process_logging(&mut transaction, &state);
            check_for_intervention(&mut transaction, &state);
            return Err(raw_status_code);
        }
    }

    let (parts, body) = response.into_parts();

    let mut body_chunks = Vec::new();
    let mut stream = body.into_data_stream();

    while let Some(result) = stream.next().await {
        if let Ok(chunk) = result {
            // log::trace!("Processing body chunk {}", String::from_utf8_lossy(&chunk));
            transaction.append_response_body(&chunk[..]).unwrap();
            body_chunks.push(chunk);
        }
    }

    // log::trace!("Start process response body");
    transaction.process_response_body().unwrap();

    {
        if let Some(raw_status_code) = check_for_intervention(&mut transaction, &state) {
            // log::trace!(
            // "Intervention generated when processing response body {}",
            // raw_status_code
            // );
            process_logging(&mut transaction, &state);
            check_for_intervention(&mut transaction, &state);
            return Err(raw_status_code);
        } else {
            // log::trace!("No intervention generated when processing response body");
        }
    }

    // log::trace!("Finish process response body");

    // Phase 5: Logging
    // Execute the phase 5 rules
    // We also do this before the premature returns if there were
    // previous interventions that cause the request to be
    // immediately dismissed.
    {
        process_logging(&mut transaction, &state);
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

fn process_logging(transaction: &mut modsecurity::Transaction, app_state: &Arc<AppState>) {
    // log::trace!("Start process logging!");
    transaction.process_logging().unwrap();
    // Apparently this triggers the log callback ...
    if let Some(intervention) = transaction.intervention() {
        if let Some(log) = intervention.log() {
            // log::trace!("004 Received log: {}", log);

            let _ = app_state.log_file.send(log.into());
        } else {
            // log::trace!("No log when processing logging")
        }
    } else {
        // log::trace!("No intervention when processing logging")
    }
    // log::trace!("Finish process logging!")
}

fn check_for_intervention(
    transaction: &mut modsecurity::Transaction,
    app_state: &Arc<AppState>,
) -> Option<StatusCode> {
    // log::trace!("Start process intervention!");
    if let Some(intervention) = transaction.intervention() {
        // log::trace!(
        // "001 Received log: {}",
        // intervention.log().expect("Expected log")
        // );

        if let Some(log) = intervention.log() {
            let _ = app_state.log_file.send(log.into());
        }

        if intervention.disruptive() {
            let status_code = intervention.status() as u16;
            return StatusCode::from_u16(status_code).ok();
        } else {
            // log::trace!("Non-disruptive intervention");
        }
    } else {
        // log::trace!("No intervention when processing intervention")
    }
    // log::trace!("Finish process intervention!");
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

async fn shutdown_signal() {
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}
