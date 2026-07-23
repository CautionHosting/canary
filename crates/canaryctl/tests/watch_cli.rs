use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use canary_core::canonical::canonicalize;
use canary_core::config::Config;
use canary_core::keys::{KeySet, MasterSeed};
use canary_core::node::ConfigDocument;
use canary_core::statement::{sign_statement, Payload, Status, CLAIM_TYPE};
use chrono::{SecondsFormat, Timelike as _, Utc};
use hmac::{Hmac, Mac as _};
use serde_json::{json, Value};
use sha2::Sha256;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "canaryctl-watch-cli-{label}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[derive(Clone)]
struct Request {
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Response {
    status: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Response {
    fn ok_json(body: Vec<u8>) -> Self {
        Self {
            status: "200 OK",
            headers: Vec::new(),
            body,
        }
    }

    fn redirect(location: String) -> Self {
        Self {
            status: "302 Found",
            headers: vec![("Location", location)],
            body: Vec::new(),
        }
    }

    fn server_error() -> Self {
        Self {
            status: "500 Internal Server Error",
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn not_found() -> Self {
        Self {
            status: "404 Not Found",
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

struct LocalServer {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Request>>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl LocalServer {
    fn start(handler: impl Fn(Request) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let thread_received = Arc::clone(&received);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = thread::spawn(move || {
            while !thread_shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if let Some(request) = read_request(&mut stream) {
                            let response = handler(request.clone());
                            thread_received.lock().unwrap().push(request);
                            write_response(&mut stream, response);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            received,
            shutdown,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<Request> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn start(command: &mut Command) -> Self {
        Self(Some(command.spawn().unwrap()))
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            child.wait().unwrap();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

struct MockCanary {
    server: LocalServer,
    statement: Value,
}

impl MockCanary {
    fn start(directory: &TempDir) -> Self {
        Self::start_with(directory, |_| {})
    }

    fn start_with_tampered_signature(directory: &TempDir) -> Self {
        Self::start_with(directory, |statement| {
            let signature = statement["signers"][0]["signatures"][0]["sig"]
                .as_str()
                .unwrap();
            let mut bytes = signature.as_bytes().to_vec();
            bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
            statement["signers"][0]["signatures"][0]["sig"] =
                Value::String(String::from_utf8(bytes).unwrap());
        })
    }

    fn start_with(directory: &TempDir, mutate_statement: impl FnOnce(&mut Value)) -> Self {
        let config: Config = serde_json::from_value(json!({
            "version": 0,
            "node_id": "canary-test",
            "targets": [{
                "id": "payments-prod",
                "name": "Payments production",
                "attestation_url": "https://payments.example.com/attestation",
                "expected_pcrs": {
                    "0": "a".repeat(96),
                    "1": "b".repeat(96),
                    "2": "c".repeat(96)
                }
            }]
        }))
        .unwrap();
        let document = ConfigDocument::new(config).unwrap();
        let seed = MasterSeed::from_base64(&STANDARD.encode([0x42; 32])).unwrap();
        let keyset = KeySet::derive(&seed, "canary-test").unwrap();
        let keys_bytes = canonicalize(&keyset.keys_document()).unwrap();
        std::fs::write(directory.join("canary-keys.json"), &keys_bytes).unwrap();

        let issued = Utc::now().with_nanosecond(0).unwrap();
        let statement = sign_statement(
            Payload {
                claim_type: CLAIM_TYPE.to_owned(),
                target_id: "payments-prod".to_owned(),
                target_origin: "https://payments.example.com".to_owned(),
                status: Status::Pending,
                reason: "STARTUP_PENDING".to_owned(),
                config_digest: document.config_digest.clone(),
                evidence_digest: None,
                observed_at: None,
                issued_at: issued.to_rfc3339_opts(SecondsFormat::Secs, true),
                expires_at: (issued + chrono::Duration::seconds(180))
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
                verifier_id: "canary-test".to_owned(),
                key_epoch: 0,
            },
            &keyset,
        )
        .unwrap();
        let mut statement_value = serde_json::to_value(statement).unwrap();
        mutate_statement(&mut statement_value);
        let statement_bytes = serde_json::to_vec(&statement_value).unwrap();
        let config_bytes = serde_json::to_vec(&document).unwrap();
        let server = LocalServer::start(move |request| match request.path.as_str() {
            "/config.json" => Response::ok_json(config_bytes.clone()),
            "/keys.json" => Response::ok_json(keys_bytes.clone()),
            "/targets/payments-prod/statement" => Response::ok_json(statement_bytes.clone()),
            _ => Response::not_found(),
        });
        Self {
            server,
            statement: statement_value,
        }
    }
}

struct WebhookRoute {
    id: &'static str,
    url: String,
    secret_env: String,
    secret: [u8; 32],
}

fn secret_env(label: &str) -> String {
    format!(
        "CANARY_WATCH_{label}_SECRET_{}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn start_watcher(directory: &TempDir, canary: &MockCanary, routes: &[WebhookRoute]) -> ChildGuard {
    start_watcher_with_poll(directory, canary, routes, 60)
}

fn start_watcher_with_poll(
    directory: &TempDir,
    canary: &MockCanary,
    routes: &[WebhookRoute],
    poll_interval_seconds: u64,
) -> ChildGuard {
    let watcher_path = directory.join("canary-watch.json");
    let webhooks = routes
        .iter()
        .map(|route| json!({"id": route.id, "url": route.url, "secret_env": route.secret_env}))
        .collect::<Vec<_>>();
    std::fs::write(
        &watcher_path,
        serde_json::to_vec(&json!({
            "version": 1,
            "canary": {"url": canary.server.url(), "keys": "canary-keys.json"},
            "poll_interval_seconds": poll_interval_seconds,
            "heartbeat_interval_seconds": 300,
            "failure_threshold": 3,
            "targets": [{"id": "payments-prod", "webhooks": webhooks}]
        }))
        .unwrap(),
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_canaryctl"));
    command
        .args([
            "watch",
            "--config",
            watcher_path.to_str().unwrap(),
            "--insecure-canary",
            "--allow-http-webhooks",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for route in routes {
        command.env(&route.secret_env, STANDARD.encode(route.secret));
    }
    ChildGuard::start(&mut command)
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?;
    let path = request_line.split_whitespace().nth(1)?.to_owned();
    let mut headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':')?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let body_len = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < header_end + body_len {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Some(Request {
        path,
        headers,
        body: bytes[header_end..header_end + body_len].to_vec(),
    })
}

fn write_response(stream: &mut TcpStream, response: Response) {
    let mut header = format!("HTTP/1.1 {}\r\n", response.status);
    header.push_str("Content-Type: application/json\r\n");
    for (name, value) in response.headers {
        header.push_str(name);
        header.push_str(": ");
        header.push_str(&value);
        header.push_str("\r\n");
    }
    header.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    ));
    if stream.write_all(header.as_bytes()).is_err() {
        return;
    }
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

fn wait_for_webhooks(first: &LocalServer, second: &LocalServer) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !first.requests().is_empty() && !second.requests().is_empty() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "timed out waiting for webhooks: receiver counts are {} and {}",
        first.requests().len(),
        second.requests().len()
    );
}

fn wait_for_webhook(receiver: &LocalServer, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !receiver.requests().is_empty() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for webhook receiver");
}

fn wait_for_canary_polls(canary: &MockCanary, expected: usize, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let polls = canary
            .server
            .requests()
            .iter()
            .filter(|request| request.path == "/config.json")
            .count();
        if polls >= expected {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {expected} Canary polls");
}

fn assert_webhook_hmac(request: &Request, secret: &[u8; 32]) -> Value {
    let timestamp = request.headers.get("x-canary-timestamp").unwrap();
    let signature = request.headers.get("x-canary-signature").unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(&request.body);
    assert_eq!(
        signature,
        &format!("v1={}", hex::encode(mac.finalize().into_bytes()))
    );

    serde_json::from_slice(&request.body).unwrap()
}

fn assert_signed_target_event(request: &Request, secret: &[u8; 32], statement: &Value) {
    let body = assert_webhook_hmac(request, secret);
    let event_id = request.headers.get("x-canary-event-id").unwrap();
    let timestamp = request.headers.get("x-canary-timestamp").unwrap();
    assert_eq!(body["event"], "target.status_changed");
    assert_eq!(body["event_id"].as_str(), Some(event_id.as_str()));
    assert_eq!(body["timestamp"].as_str(), Some(timestamp.as_str()));
    assert_eq!(body["data"]["target"]["id"], "payments-prod");
    assert_eq!(body["data"]["result"]["status"], "PENDING");
    assert_eq!(body["data"]["result"]["statement"], *statement);
}

#[test]
fn watch_fans_out_initial_pending_target_to_each_signed_webhook() {
    let directory = TempDir::new("fanout");
    let canary = MockCanary::start(&directory);
    let first_receiver = LocalServer::start(|_| Response::ok_json(Vec::new()));
    let second_receiver = LocalServer::start(|_| Response::ok_json(Vec::new()));

    let first_secret = [0x11; 32];
    let second_secret = [0x22; 32];
    let routes = [
        WebhookRoute {
            id: "payments-ops",
            url: first_receiver.url(),
            secret_env: secret_env("FIRST"),
            secret: first_secret,
        },
        WebhookRoute {
            id: "payments-oncall",
            url: second_receiver.url(),
            secret_env: secret_env("SECOND"),
            secret: second_secret,
        },
    ];
    let mut child = start_watcher(&directory, &canary, &routes);
    wait_for_webhooks(&first_receiver, &second_receiver);
    child.stop();

    let first = first_receiver.requests();
    let second = second_receiver.requests();
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert_signed_target_event(&first[0], &first_secret, &canary.statement);
    assert_signed_target_event(&second[0], &second_secret, &canary.statement);
}

#[test]
fn watch_does_not_follow_webhook_redirects() {
    let directory = TempDir::new("redirect");
    let canary = MockCanary::start(&directory);
    let sink = LocalServer::start(|_| Response::ok_json(Vec::new()));
    let sink_url = sink.url();
    let redirector = LocalServer::start(move |_| Response::redirect(sink_url.clone()));
    let secret = [0x33; 32];
    let routes = [WebhookRoute {
        id: "redirector",
        url: redirector.url(),
        secret_env: secret_env("REDIRECT"),
        secret,
    }];

    let mut child = start_watcher(&directory, &canary, &routes);
    wait_for_webhook(&redirector, Duration::from_secs(5));
    thread::sleep(Duration::from_millis(200));
    child.stop();

    assert_eq!(redirector.requests().len(), 1);
    assert!(
        sink.requests().is_empty(),
        "webhook client followed an untrusted redirect"
    );
}

#[test]
fn failing_webhook_does_not_delay_healthy_webhook_delivery() {
    let directory = TempDir::new("receiver-isolation");
    let canary = MockCanary::start(&directory);
    let failing = LocalServer::start(|_| Response::server_error());
    let healthy = LocalServer::start(|_| Response::ok_json(Vec::new()));
    let failing_secret = [0x44; 32];
    let healthy_secret = [0x55; 32];
    let routes = [
        WebhookRoute {
            id: "failing",
            url: failing.url(),
            secret_env: secret_env("FAIL"),
            secret: failing_secret,
        },
        WebhookRoute {
            id: "healthy",
            url: healthy.url(),
            secret_env: secret_env("HEALTHY"),
            secret: healthy_secret,
        },
    ];

    let started = Instant::now();
    let mut child = start_watcher_with_poll(&directory, &canary, &routes, 1);
    wait_for_webhook(&healthy, Duration::from_secs(2));
    wait_for_canary_polls(&canary, 2, Duration::from_secs(3));
    let delivered_after = started.elapsed();
    child.stop();

    assert!(
        delivered_after < Duration::from_secs(2),
        "healthy webhook delivery was delayed by the failed receiver: {delivered_after:?}"
    );
    assert!(!failing.requests().is_empty());
    let healthy_requests = healthy.requests();
    assert_signed_target_event(&healthy_requests[0], &healthy_secret, &canary.statement);
}

#[test]
fn tampered_target_signature_immediately_reports_canary_verification_failure() {
    let directory = TempDir::new("tampered-signature");
    let canary = MockCanary::start_with_tampered_signature(&directory);
    let receiver = LocalServer::start(|_| Response::ok_json(Vec::new()));
    let secret = [0x66; 32];
    let routes = [WebhookRoute {
        id: "alerts",
        url: receiver.url(),
        secret_env: secret_env("TAMPERED"),
        secret,
    }];

    let started = Instant::now();
    let mut child = start_watcher(&directory, &canary, &routes);
    wait_for_webhook(&receiver, Duration::from_secs(2));
    let reported_after = started.elapsed();
    child.stop();

    assert!(
        reported_after < Duration::from_secs(2),
        "signature failure was delayed instead of reported immediately: {reported_after:?}"
    );
    let requests = receiver.requests();
    assert_eq!(requests.len(), 1);
    let body = assert_webhook_hmac(&requests[0], &secret);
    assert_eq!(body["event"], "canary.verification_failed");
    assert!(
        body["data"]["affected_target_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "payments-prod"),
        "verification failure omitted its affected target: {}",
        body
    );
}
