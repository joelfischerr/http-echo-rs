use anyhow::Result;
use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, StatusCode, Version},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    routing::post,
    Router,
};
use clap::Parser;
use futures_util::StreamExt;
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use tokio::signal::unix::{signal, SignalKind};

use modsecurity::{ModSecurity, Rules};

// #[derive(Clone)]
struct AppState {
    ms: ModSecurity,
    rules: Rules,
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

    let headers = headers
        .unwrap_or(vec![])
        .iter()
        .map(|h| {
            let hs: Vec<&str> = h.split_terminator(":").map(|s| s.trim()).collect();
            (hs[0].to_string(), hs[1].to_string())
        })
        .collect::<HashMap<String, String>>();
    let header_echos = header_echos.unwrap_or_default();

    let echo = post(move |req_hdrs: HeaderMap, body: Bytes| {
        log::trace!("Received request: {:?}", req_hdrs);
        // this helps simulating slower backends
        if delay_us > 0 {
            std::thread::sleep(Duration::from_micros(delay_us));
        }

        let mut res_hdrs = HeaderMap::new();
        for (key, val) in headers.into_iter() {
            let key = HeaderName::from_str(key.as_str()).unwrap();
            res_hdrs.insert(key, val.parse().unwrap());
        }

        req_hdrs
            .iter()
            .filter(|(k, _)| header_echos.contains(&k.to_string()))
            .for_each(|(k, v)| {
                res_hdrs.insert(k, v.clone());
            });

        echo(res_hdrs, body)
    });

    let state: Arc<AppState> = configure_modsecurity_to_state(rules_vec);

    // build our application with a route
    let mut app: Router = Router::new()
        .route("/", echo.clone())
        .route("/{path}", echo)
        .route("/speed", post(reply_200()))
        .route("/", get(reply_200()))
        .route("/speed", get(reply_200()))
        .route("/{path}", get(reply_200()));

    if use_waf {
        app = app.route_layer(middleware::from_fn_with_state(
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
    let ms = ModSecurity::builder().with_log_callbacks().build();

    let mut rules = Rules::new();
    rules
        .add_plain(
            r#"
    SecRuleEngine On

    SecRule REQUEST_URI "@rx admin" "id:1101,phase:1,deny,status:401"
"#,
        )
        .expect("Failed to add rules");

    test_modsecurity(&ms, &rules);

    for rule in rules_vec.iter() {
        rules.add_file(rule).expect("Adding rules failed!");
    }

    let state: Arc<AppState> = Arc::new(AppState {
        ms: ms,
        rules: rules,
    });

    return state;
}

async fn execute_modsecurity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let mut transaction = state
        .ms
        .transaction_builder()
        .with_rules(&state.rules)
        .with_logging(|_msg| {})
        .build()
        .unwrap();

    let request_http_version = map_http_version(request.version());

    transaction
        .process_connection("127.0.0.1", 1234, "127.0.0.1", 8080)
        .unwrap();
    transaction
        .process_uri(
            &request.uri().to_string(),
            &request.method().as_str(),
            &request_http_version,
        )
        .unwrap();
    for (key, val) in headers.iter() {
        let key_str = key.as_str();
        let val_str = val.to_str().unwrap();
        transaction.add_request_header(key_str, val_str).unwrap();
    }
    transaction.process_request_headers().unwrap();
    if let Some(raw_status_code) = check_for_intervention(&mut transaction) {
        return Err(raw_status_code);
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
    transaction.process_request_body().unwrap();

    if let Some(raw_status_code) = check_for_intervention(&mut transaction) {
        return Err(raw_status_code);
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
        transaction.add_response_header(key_str, val_str).unwrap();
    }
    transaction
        .process_response_headers(response.status().as_u16().into(), &response_http_version)
        .unwrap();

    if let Some(raw_status_code) = check_for_intervention(&mut transaction) {
        return Err(raw_status_code);
    }

    let (parts, body) = response.into_parts();

    let mut body_chunks = Vec::new();
    let mut stream = body.into_data_stream();

    while let Some(result) = stream.next().await {
        if let Ok(chunk) = result {
            transaction.append_request_body(&chunk[..]).unwrap();
            body_chunks.push(chunk);
        }
    }

    transaction.process_response_body().unwrap();

    if let Some(raw_status_code) = check_for_intervention(&mut transaction) {
        return Err(raw_status_code);
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

fn check_for_intervention(transaction: &mut modsecurity::Transaction) -> Option<StatusCode> {
    if let Some(intervention) = transaction.intervention() {
        if intervention.disruptive() {
            let status_code = intervention.status() as u16;
            return StatusCode::from_u16(status_code).ok();
        }
    }
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
