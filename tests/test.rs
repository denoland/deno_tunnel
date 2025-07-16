use deno_tunnel::Authentication;
use deno_tunnel::Error;
use deno_tunnel::Event;
use deno_tunnel::Metadata;
use deno_tunnel::TunnelConnection;
use std::io::Cursor;
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::process::Child;
use tokio::process::Command;

struct Server {
  _child: Child,
  qaddr: SocketAddr,
  taddr: SocketAddr,
  tls_config: quinn::rustls::ClientConfig,
}

async fn server() -> Server {
  let mut child = Command::new("deno")
    .arg("run")
    .arg("--unstable-net")
    .arg("-A")
    .arg("./tests/server.ts")
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit())
    .kill_on_drop(true)
    .spawn()
    .unwrap();

  let mut r = BufReader::new(child.stdout.as_mut().unwrap());
  let mut out = vec![];
  r.read_until(b'\n', &mut out).await.unwrap();
  let out = String::from_utf8_lossy(&out[..out.len() - 1]);
  let mut i = out.split(' ');
  assert_eq!(i.next().unwrap(), "LISTEN");
  let qaddr = i.next().unwrap().parse().unwrap();
  let taddr = i.next().unwrap().parse().unwrap();

  let mut cstdout = child.stdout.take().unwrap();
  tokio::spawn(async move {
    let _ = tokio::io::copy(&mut cstdout, &mut tokio::io::stdout()).await;
  });

  let mut reader = Cursor::new(include_bytes!("./RootCA.crt"));
  let certs = rustls_pemfile::certs(&mut reader)
    .filter_map(|v| v.ok())
    .collect::<Vec<_>>();
  let mut root_store = quinn::rustls::RootCertStore::empty();
  root_store.add_parsable_certificates(certs);

  let tls_config = quinn::rustls::ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  Server {
    _child: child,
    qaddr,
    taddr,
    tls_config,
  }
}

enum Mode {
  Tunnel,
  Migrate,
  Disconnect,
}

async fn connect_for(stream: &mut TcpStream, routing_id: &str, mode: Mode) {
  stream.write_u32_le(routing_id.len() as _).await.unwrap();
  stream.write_all(routing_id.as_bytes()).await.unwrap();
  stream
    .write_all(&[match mode {
      Mode::Tunnel => 0,
      Mode::Migrate => 1,
      Mode::Disconnect => 2,
    }])
    .await
    .unwrap();
}

#[tokio::test]
async fn test_basic() {
  let server = server().await;

  let (c, mut events) = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config,
    Authentication::App {
      token: "1234".into(),
      org: "org".into(),
      app: "app".into(),
    },
  )
  .await
  .unwrap();

  assert_eq!(
    c.metadata().unwrap(),
    Metadata {
      env: Default::default(),
      hostnames: vec!["org-app.localhost".into()],
      metadata: Default::default()
    }
  );

  assert_eq!(events.next().await.unwrap(), Event::Routed);

  let t = tokio::spawn(async move {
    let mut stream = TcpStream::connect(server.taddr).await.unwrap();

    connect_for(&mut stream, "org-app", Mode::Tunnel).await;

    stream.write_all(b"hello!").await.unwrap();

    let mut data = [0; 32];
    let n = stream.read(&mut data).await.unwrap();

    assert_eq!(&data[0..n], b"meow back");
  });

  let q = tokio::spawn(async move {
    let (mut stream, ..) = c.accept().await.unwrap();

    let mut data = [0; 32];
    let n = stream.read(&mut data).await.unwrap();
    assert_eq!(&data[0..n], b"hello!");

    stream.write_all(b"meow back").await.unwrap();
  });

  t.await.unwrap();
  q.await.unwrap();
}

#[tokio::test]
async fn test_unauthorized() {
  let server = server().await;

  let r = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config,
    Authentication::App {
      token: "invalid".into(),
      org: "org".into(),
      app: "app".into(),
    },
  )
  .await;

  assert!(matches!(r, Err(Error::Unauthorized)));
}

#[tokio::test]
async fn test_not_found() {
  let server = server().await;

  let r = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config,
    Authentication::App {
      token: "1234".into(),
      org: "unknown".into(),
      app: "app".into(),
    },
  )
  .await;

  assert!(matches!(r, Err(Error::NotFound)));
}

#[tokio::test]
async fn test_disconnect() {
  let server = server().await;

  let (_, mut events) = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config,
    Authentication::App {
      token: "1234".into(),
      org: "org".into(),
      app: "app".into(),
    },
  )
  .await
  .unwrap();

  assert_eq!(events.next().await.unwrap(), Event::Routed);

  let mut stream = TcpStream::connect(server.taddr).await.unwrap();
  connect_for(&mut stream, "org-app", Mode::Disconnect).await;

  assert_eq!(
    events.next().await.unwrap(),
    Event::Reconnect(Duration::from_secs(3))
  );

  assert_eq!(events.next().await.unwrap(), Event::Routed);
}

#[tokio::test]
async fn test_migrate() {
  let server = server().await;

  let (_, mut events) = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config,
    Authentication::App {
      token: "1234".into(),
      org: "org".into(),
      app: "app".into(),
    },
  )
  .await
  .unwrap();

  assert_eq!(events.next().await.unwrap(), Event::Routed);

  let mut stream = TcpStream::connect(server.taddr).await.unwrap();
  connect_for(&mut stream, "org-app", Mode::Migrate).await;

  assert_eq!(events.next().await.unwrap(), Event::Routed);
}
