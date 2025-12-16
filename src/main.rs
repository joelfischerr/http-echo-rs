use anyhow::Result;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use clap::Parser;
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use tokio::signal::unix::{SignalKind, signal};

use modsecurity::{ModSecurity, Rules};

// #[derive(Clone)]
struct AppState {
    ms: ModSecurity,
    rules: Rules,
}

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8000")]
    address: String,

    #[arg(short = 'H', long = "header")]
    headers: Option<Vec<String>>,

    #[arg(short = 'e', long = "echo-header")]
    header_echos: Option<Vec<String>>,

    #[arg(short = 'd', long = "us-delay", default_value = "0")]
    delay_us: u64,
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

    let ms = ModSecurity::default();

    let mut rules = Rules::new();
    rules
        .add_plain(
            r#"
        SecRuleEngine On

        SecRule REQUEST_URI "@rx admin" "id:1,phase:1,deny,status:401"
    "#,
        )
        .expect("Failed to add rules");

    test_modsecurity(&ms, &rules);

    let state: Arc<AppState> = Arc::new(AppState {
        ms: ms,
        rules: rules,
    });

    // build our application with a route
    let app = Router::new()
        .route("/", echo.clone())
        .route("/{path}", echo)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            execute_modsecurity,
        ));

    let listener = tokio::net::TcpListener::bind(address.clone())
        .await
        .unwrap();
    log::info!("Listening on {}", address);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn execute_modsecurity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    _next: Next,
) -> Result<Response<Body>, StatusCode> {
    let mut transaction = state
        .ms
        .transaction_builder()
        .with_rules(&state.rules)
        .build()
        .unwrap();

    let request_http_version = format!("{:?}", request.version()).to_string();

    transaction
        .process_connection("127.0.0.1", 1234, "127.0.0.1", 8080)
        .unwrap();
    transaction
        .process_uri(
            &request.uri().to_string(),
            &request.method().to_string(),
            &request_http_version,
        )
        .unwrap();
    for (key, val) in headers.iter() {
        transaction
            .add_request_header(&key.to_string(), &val.to_str().unwrap())
            .unwrap();
    }
    transaction.process_request_headers().unwrap();

    // let body_bytes =

    // The idea for the body is to get the whole body, do ModSecurity and then copy the body back into the request.
    // This seems super wasteful, but is what axum has in their examples: https://github.com/tokio-rs/axum/blob/3b92cd7593a900d3c79c2aeb411f90be052a9a5c/examples/consume-body-in-extractor-or-middleware/src/main.rs#L58
    // transaction.append_request_body(request.body().into_data_stream();
    transaction.process_request_body().unwrap();

    Err(StatusCode::UNAUTHORIZED)
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
    if let Ok(body) = String::from_utf8(body.to_vec()) {
        Ok((headers, body))
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
