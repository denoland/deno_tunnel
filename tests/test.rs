use deno_tunnel::Authentication;
use deno_tunnel::CLOSE_GENERIC;
use deno_tunnel::CLOSE_MIGRATE;
use deno_tunnel::CLOSE_NOT_FOUND;
use deno_tunnel::CLOSE_PROTOCOL;
use deno_tunnel::CLOSE_UNAUTHORIZED;
use deno_tunnel::ControlMessage;
use deno_tunnel::Error;
use deno_tunnel::Event;
use deno_tunnel::Metadata;
use deno_tunnel::StreamHeader;
use deno_tunnel::TunnelConnection;
use deno_tunnel::VERSION;
use deno_tunnel::read_message;
use deno_tunnel::write_message;
use std::collections::HashMap;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;

struct Server {
  events: (
    tokio::sync::mpsc::Sender<Event>,
    AsyncMutex<tokio::sync::mpsc::Receiver<Event>>,
  ),
  endpoint: quinn::Endpoint,
  qaddr: SocketAddr,
  #[allow(clippy::type_complexity)]
  connections: Arc<
    Mutex<
      HashMap<
        String,
        (quinn::Connection, tokio::sync::mpsc::Sender<ControlMessage>),
      >,
    >,
  >,
}

impl Server {
  async fn stream(
    &self,
    routing_id: &str,
  ) -> tokio::io::Join<quinn::RecvStream, quinn::SendStream> {
    let c = self
      .connections
      .lock()
      .unwrap()
      .get(routing_id)
      .unwrap()
      .0
      .clone();
    let mut s = c.open_bi().await.unwrap();
    write_message(
      &mut s.0,
      StreamHeader::Stream {
        local_addr: self.qaddr,
        remote_addr: self.qaddr,
      },
    )
    .await
    .unwrap();
    tokio::io::join(s.1, s.0)
  }

  async fn migrate(&self, routing_id: &str) {
    let (c, tx) = self
      .connections
      .lock()
      .unwrap()
      .get(routing_id)
      .unwrap()
      .clone();
    tokio::spawn(async move {
      tokio::time::sleep(Duration::from_secs(2)).await;
      c.close(CLOSE_MIGRATE.into(), b"migrate pls");
    });
    let _ = tx.send(ControlMessage::Migrate {}).await;
  }

  async fn disconnect(&self, routing_id: &str) {
    let c = self
      .connections
      .lock()
      .unwrap()
      .get(routing_id)
      .unwrap()
      .0
      .clone();
    c.close(CLOSE_GENERIC.into(), b"explicit close");
  }

  async fn accept_agent(
    &self,
    routing_id: &str,
  ) -> tokio::io::Join<quinn::RecvStream, quinn::SendStream> {
    let c = self
      .connections
      .lock()
      .unwrap()
      .get(routing_id)
      .unwrap()
      .0
      .clone();

    let mut s = c.accept_bi().await.unwrap();

    let StreamHeader::Agent {} = read_message(&mut s.1).await.unwrap() else {
      panic!()
    };

    tokio::io::join(s.1, s.0)
  }

  fn on_event(self: &Arc<Self>) -> impl Fn(Event) + use<> {
    let this = self.clone();
    move |event: Event| {
      let this = this.clone();
      tokio::spawn(async move { this.events.0.send(event).await });
    }
  }

  async fn next_event(&self) -> Option<Event> {
    self.events.1.lock().await.recv().await
  }

  fn tls_config(&self) -> quinn::rustls::ClientConfig {
    let mut reader = Cursor::new(include_bytes!("./RootCA.crt"));
    let certs = rustls_pemfile::certs(&mut reader)
      .filter_map(|v| v.ok())
      .collect::<Vec<_>>();
    let mut root_store = quinn::rustls::RootCertStore::empty();
    root_store.add_parsable_certificates(certs);
    quinn::rustls::ClientConfig::builder()
      .with_root_certificates(root_store)
      .with_no_client_auth()
  }
}

impl Drop for Server {
  fn drop(&mut self) {
    self.endpoint.close(0u32.into(), b"ended");
  }
}

async fn server() -> Arc<Server> {
  let mut reader = Cursor::new(include_bytes!("./localhost.crt"));
  let cert_chain = rustls_pemfile::certs(&mut reader)
    .filter_map(|v| v.ok())
    .collect::<Vec<_>>();
  let mut reader = Cursor::new(include_bytes!("./localhost.key"));
  let key_der = rustls_pemfile::private_key(&mut reader).unwrap().unwrap();
  let mut crypto = quinn::rustls::server::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(cert_chain, key_der)
    .unwrap();
  crypto.alpn_protocols = vec!["🦕🕳️".into()];

  let mut transport_config = quinn::TransportConfig::default();
  transport_config
    .max_idle_timeout(Some(Duration::from_secs(15).try_into().unwrap()));

  let crypto = Arc::new(
    quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
  );
  let mut config = quinn::ServerConfig::with_crypto(crypto);
  config.transport_config(Arc::new(transport_config));

  let endpoint =
    quinn::Endpoint::server(config, "[::]:0".parse().unwrap()).unwrap();

  let qaddr = SocketAddr::new(
    "::1".parse().unwrap(),
    endpoint.local_addr().unwrap().port(),
  );

  let connections = Arc::new(Mutex::new(HashMap::new()));

  tokio::spawn({
    let endpoint = endpoint.clone();
    let connections = connections.clone();
    async move {
      while let Some(incoming) = endpoint.accept().await {
        let connections = connections.clone();
        tokio::spawn(async move {
          let conn = incoming.await.unwrap();

          let mut control = conn.accept_bi().await.unwrap();

          let version = control.1.read_u32_le().await.unwrap();
          if version != VERSION {
            conn.close(CLOSE_PROTOCOL.into(), b"invalid version");
            return;
          }
          control.0.write_u32_le(version).await.unwrap();

          let StreamHeader::Control { metadata } =
            read_message(&mut control.1).await.unwrap()
          else {
            conn.close(CLOSE_PROTOCOL.into(), b"unexpected header");
            return;
          };

          let routing_id = match read_message(&mut control.1).await.unwrap() {
            ControlMessage::AuthenticateApp { org, app, token } => {
              if token == "invalid" {
                conn.close(CLOSE_UNAUTHORIZED.into(), b"invalid token");
                return;
              }
              if org == "unknown" || app == "unknown" {
                conn.close(CLOSE_NOT_FOUND.into(), b"unknown app or org");
                return;
              }
              format!("{org}-{app}")
            }
            ControlMessage::AuthenticateCluster { token } => {
              if token == "invalid" {
                conn.close(CLOSE_UNAUTHORIZED.into(), b"invalid token");
                return;
              }
              if token == "unknown" {
                conn.close(CLOSE_NOT_FOUND.into(), b"unknown cluster");
                return;
              }
              token
            }
            _ => {
              conn.close(CLOSE_PROTOCOL.into(), b"unexpected message");
              return;
            }
          };

          write_message(
            &mut control.0,
            ControlMessage::Authenticated {
              metadata: metadata.unwrap_or_default(),
              addr: qaddr,
              hostnames: vec![format!("{routing_id}.localhost")],
              env: Default::default(),
            },
          )
          .await
          .unwrap();

          let (tx, mut rx) = tokio::sync::mpsc::channel(1);

          connections
            .lock()
            .unwrap()
            .insert(routing_id, (conn.clone(), tx));

          if let ControlMessage::Listening {} =
            read_message(&mut control.1).await.unwrap()
          {
            write_message(&mut control.0, ControlMessage::Routed {})
              .await
              .unwrap();
          }

          while let Some(msg) = rx.recv().await {
            write_message(&mut control.0, msg).await.unwrap();
          }
        });
      }
    }
  });

  let (tx, rx) = tokio::sync::mpsc::channel(1);
  Arc::new(Server {
    events: (tx, AsyncMutex::new(rx)),
    endpoint,
    qaddr,
    connections,
  })
}

#[tokio::test]
async fn test_basic() {
  let server = server().await;

  let mut metadata = HashMap::new();
  metadata.insert("a".into(), "1".into());
  metadata.insert("b".into(), "2".into());

  let c = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config(),
    Authentication::App {
      token: "1234".into(),
      org: "org".into(),
      app: "app".into(),
    },
    metadata.clone(),
    server.on_event(),
  )
  .await
  .unwrap();

  assert_eq!(
    c.metadata().unwrap(),
    Metadata {
      env: Default::default(),
      hostnames: vec!["org-app.localhost".into()],
      metadata,
    }
  );

  let server2 = server.clone();
  let t = tokio::spawn(async move {
    let mut stream = server2.stream("org-app").await;

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

  assert!(matches!(
    server.next_event().await.unwrap(),
    Event::Routed(_)
  ));

  t.await.unwrap();
  q.await.unwrap();
}

#[tokio::test]
async fn test_unauthorized() {
  let server = server().await;

  let r = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config(),
    Authentication::App {
      token: "invalid".into(),
      org: "org".into(),
      app: "app".into(),
    },
    Default::default(),
    server.on_event(),
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
    server.tls_config(),
    Authentication::App {
      token: "1234".into(),
      org: "unknown".into(),
      app: "app".into(),
    },
    Default::default(),
    server.on_event(),
  )
  .await;

  assert!(matches!(r, Err(Error::NotFound)));
}

#[tokio::test]
async fn test_disconnect() {
  let server = server().await;

  let conn = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config(),
    Authentication::App {
      token: "1234".into(),
      org: "org".into(),
      app: "app".into(),
    },
    Default::default(),
    server.on_event(),
  )
  .await
  .unwrap();

  tokio::spawn(async move { while conn.accept().await.is_ok() {} });

  assert!(matches!(
    server.next_event().await.unwrap(),
    Event::Routed(_)
  ));

  server.disconnect("org-app").await;

  let duration = Duration::from_secs(3);
  assert!(matches!(
    server.next_event().await.unwrap(),
    Event::Reconnect(d, Some(_)) if d == duration
  ));

  assert!(matches!(
    server.next_event().await.unwrap(),
    Event::Routed(_)
  ));
}

#[tokio::test]
async fn test_migrate() {
  let server = server().await;

  let conn = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config(),
    Authentication::App {
      token: "1234".into(),
      org: "org".into(),
      app: "app".into(),
    },
    Default::default(),
    server.on_event(),
  )
  .await
  .unwrap();

  tokio::spawn(async move { while conn.accept().await.is_ok() {} });

  assert!(matches!(
    server.next_event().await.unwrap(),
    Event::Routed(_)
  ));

  server.migrate("org-app").await;

  assert!(matches!(
    server.next_event().await.unwrap(),
    Event::Routed(_)
  ));
}

#[tokio::test]
async fn test_agent() {
  let server = server().await;

  let conn = TunnelConnection::connect(
    server.qaddr,
    "localhost".into(),
    server.tls_config(),
    Authentication::App {
      token: "1234".into(),
      org: "org".into(),
      app: "app".into(),
    },
    Default::default(),
    server.on_event(),
  )
  .await
  .unwrap();

  let t = tokio::spawn(async move {
    let mut stream = server.accept_agent("org-app").await;
    let mut data = [0; 32];
    let n = stream.read(&mut data).await.unwrap();
    assert_eq!(&data[0..n], b"hello agent!");
  });

  let q = tokio::spawn(async move {
    let mut stream = conn.create_agent_stream().await.unwrap();
    stream.write_all(b"hello agent!").await.unwrap();
  });

  t.await.unwrap();
  q.await.unwrap();
}
