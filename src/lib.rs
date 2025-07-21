// Copyright 2018-2025 the Deno authors. MIT license.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

pub use quinn;

pub const VERSION: u32 = 1;

pub const CLOSE_GENERIC: u32 = 0;
pub const CLOSE_PROTOCOL: u32 = 1;
pub const CLOSE_UNAUTHORIZED: u32 = 2;
pub const CLOSE_NOT_FOUND: u32 = 3;
pub const CLOSE_MIGRATE: u32 = 4;

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
  #[error(transparent)]
  StdIo(Arc<std::io::Error>),
  #[error(transparent)]
  SerdeJson(Arc<serde_json::Error>),
  #[error(transparent)]
  QuinnConnect(#[from] quinn::ConnectError),
  #[error(transparent)]
  QuinnConnection(quinn::ConnectionError),
  #[error(transparent)]
  QuinnRead(quinn::ReadError),
  #[error(transparent)]
  QuinnReadExact(quinn::ReadExactError),
  #[error(transparent)]
  QuinnWrite(quinn::WriteError),

  #[error("Unsupported version")]
  UnsupportedVersion,
  #[error("Unexpected header")]
  UnexpectedHeader,
  #[error("Protocol violation")]
  Protocol,
  #[error("Unauthorized")]
  Unauthorized,
  #[error("Not found")]
  NotFound,
  #[error("Migrate")]
  Migrate,
}

impl From<quinn::ConnectionError> for Error {
  fn from(value: quinn::ConnectionError) -> Self {
    match value {
      quinn::ConnectionError::ApplicationClosed(ref e) => {
        match e.error_code.into_inner() as u32 {
          CLOSE_PROTOCOL => Self::Protocol,
          CLOSE_UNAUTHORIZED => Self::Unauthorized,
          CLOSE_NOT_FOUND => Self::NotFound,
          CLOSE_MIGRATE => Self::Migrate,
          _ => Self::QuinnConnection(value),
        }
      }
      _ => Self::QuinnConnection(value),
    }
  }
}

impl From<quinn::ReadExactError> for Error {
  fn from(value: quinn::ReadExactError) -> Self {
    match value {
      quinn::ReadExactError::FinishedEarly(..) => Self::QuinnReadExact(value),
      quinn::ReadExactError::ReadError(e) => Self::from(e),
    }
  }
}

impl From<quinn::ReadError> for Error {
  fn from(value: quinn::ReadError) -> Self {
    if let quinn::ReadError::ConnectionLost(e) = value {
      Self::from(e)
    } else {
      Self::QuinnRead(value)
    }
  }
}

impl From<quinn::WriteError> for Error {
  fn from(value: quinn::WriteError) -> Self {
    if let quinn::WriteError::ConnectionLost(e) = value {
      Self::from(e)
    } else {
      Self::QuinnWrite(value)
    }
  }
}

impl From<std::io::Error> for Error {
  fn from(value: std::io::Error) -> Self {
    Self::StdIo(Arc::new(value))
  }
}

impl From<serde_json::Error> for Error {
  fn from(value: serde_json::Error) -> Self {
    Self::SerdeJson(Arc::new(value))
  }
}

/// Essentially a SocketAddr, except we prefer a human
/// readable hostname to identify the remote endpoint.
#[derive(Debug, Clone)]
pub struct TunnelAddr {
  socket: SocketAddr,
  hostname: Option<String>,
}

impl TunnelAddr {
  pub fn hostname(&self) -> String {
    self
      .hostname
      .clone()
      .unwrap_or_else(|| self.socket.ip().to_string())
  }

  pub fn ip(&self) -> IpAddr {
    self.socket.ip()
  }

  pub fn port(&self) -> u16 {
    self.socket.port()
  }
}

impl From<TunnelAddr> for SocketAddr {
  fn from(addr: TunnelAddr) -> Self {
    addr.socket
  }
}

/// Data obtained from the server handshake
#[derive(Debug, Clone, PartialEq)]
pub struct Metadata {
  pub hostnames: Vec<String>,
  pub env: HashMap<String, String>,
  pub metadata: HashMap<String, String>,
}

/// Server event
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Event {
  /// All endpoints are routed
  Routed,
  /// Client will reconnect after the given duration
  Reconnect(Duration),
}

enum InternalEvent {
  Routed,
  Migrate,
}

/// Events from the server
#[derive(Debug)]
pub struct Events {
  event_rx: tokio::sync::mpsc::Receiver<Event>,
}

impl Events {
  pub async fn next(&mut self) -> Option<Event> {
    self.event_rx.recv().await
  }
}

#[derive(Debug, Clone)]
pub enum Authentication {
  App {
    token: String,
    org: String,
    app: String,
  },
  Cluster {
    token: String,
  },
}

#[derive(Debug)]
struct InnerConnection {
  connection: quinn::Connection,
  local_addr: TunnelAddr,
  metadata: Metadata,
}

impl InnerConnection {
  async fn connect(
    outer: TunnelConnection,
  ) -> Result<(Self, tokio::sync::mpsc::Receiver<InternalEvent>), Error> {
    let connecting = outer
      .endpoint
      .connect(outer.connect_info.addr, &outer.connect_info.server_name)?;

    let connection = connecting.await?;

    let mut control = connection.open_bi().await?;
    write_u32_le(&mut control.0, VERSION).await?;
    if read_u32_le(&mut control.1).await? != VERSION {
      return Err(Error::UnsupportedVersion);
    }

    write_message(
      &mut control.0,
      StreamHeader::Control {
        metadata: Some(outer.connect_info.metadata.clone()),
      },
    )
    .await?;
    write_message(
      &mut control.0,
      match outer.connect_info.authentication.clone() {
        Authentication::App { token, org, app } => {
          ControlMessage::AuthenticateApp { token, org, app }
        }
        Authentication::Cluster { token } => {
          ControlMessage::AuthenticateCluster { token }
        }
      },
    )
    .await?;

    let ControlMessage::Authenticated {
      addr,
      hostnames,
      env,
      metadata,
    } = read_message(&mut control.1).await?
    else {
      return Err(Error::UnexpectedHeader);
    };

    let (event_tx, event_rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
      while let Ok(message) = read_message(&mut control.1).await {
        let event = match message {
          ControlMessage::Routed {} => InternalEvent::Routed,
          ControlMessage::Migrate {} => InternalEvent::Migrate,
          _ => {
            continue;
          }
        };
        if event_tx.send(event).await.is_err() {
          break;
        }
      }
    });

    let local_addr = TunnelAddr {
      socket: addr,
      hostname: hostnames.first().cloned(),
    };

    let metadata = Metadata {
      hostnames,
      env,
      metadata,
    };

    Ok((
      Self {
        connection,
        local_addr,
        metadata,
      },
      event_rx,
    ))
  }
}

#[derive(Debug)]
struct ConnectInfo {
  authentication: Authentication,
  metadata: HashMap<String, String>,
  addr: SocketAddr,
  server_name: String,
}

#[derive(Debug, Clone)]
pub struct TunnelConnection {
  endpoint: quinn::Endpoint,
  connect_info: Arc<ConnectInfo>,
  active:
    tokio::sync::watch::Sender<Option<Result<Arc<InnerConnection>, Error>>>,
}

impl TunnelConnection {
  pub async fn connect(
    addr: std::net::SocketAddr,
    server_name: String,
    tls_config: quinn::rustls::ClientConfig,
    authentication: Authentication,
    metadata: HashMap<String, String>,
  ) -> Result<(Self, Events), Error> {
    Self::connect_with(
      UdpSocket::bind(("::", 0))?,
      addr,
      server_name,
      tls_config,
      authentication,
      metadata,
    )
    .await
  }

  pub async fn connect_with(
    socket: UdpSocket,
    addr: std::net::SocketAddr,
    server_name: String,
    mut tls_config: quinn::rustls::ClientConfig,
    authentication: Authentication,
    metadata: HashMap<String, String>,
  ) -> Result<(Self, Events), Error> {
    let config = quinn::EndpointConfig::default();
    let mut endpoint = quinn::Endpoint::new(
      config,
      None,
      socket,
      quinn::default_runtime().unwrap(),
    )?;

    tls_config.alpn_protocols = vec!["🦕🕳️".into()];
    tls_config.enable_early_data = true;

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    transport_config
      .max_idle_timeout(Some(Duration::from_secs(15).try_into().unwrap()));

    let client_config =
      QuicClientConfig::try_from(tls_config).expect("TLS13 supported");
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_config));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config);

    let (event_tx, event_rx) = tokio::sync::mpsc::channel(1);

    let this = Self {
      endpoint,
      connect_info: Arc::new(ConnectInfo {
        authentication,
        metadata,
        addr,
        server_name,
      }),
      active: tokio::sync::watch::channel(None).0,
    };

    tokio::spawn({
      let this = this.clone();
      async move {
        let this2 = this.clone();
        let r = async move {
          let mut retries = 0;
          let mut watch = this.active.subscribe();

          'outer: loop {
            if matches!(this.active.borrow().as_ref(), Some(Err(_))) {
              break;
            }

            if retries > 0 {
              let d = Duration::from_secs((retries * 3).min(30));
              let event_tx = event_tx.clone();
              tokio::spawn(async move {
                let _ = event_tx.send(Event::Reconnect(d)).await;
              });
              let s = tokio::time::sleep(d);
              tokio::pin!(s);
              loop {
                tokio::select! {
                  _ = &mut s => break,
                  _ = watch.changed() => {
                    if matches!(watch.borrow().as_ref(), Some(Err(_))) {
                      break 'outer;
                    }
                  }
                }
              }
            }

            let (inner, mut event_rx) =
              match InnerConnection::connect(this.clone()).await {
                Ok(r) => r,
                Err(e) => {
                  if let Error::QuinnConnection(qe) = &e {
                    if is_retry_error(qe) {
                      retries += 1;
                      continue;
                    } else {
                      return Err(e);
                    }
                  } else {
                    return Err(e);
                  }
                }
              };

            let existing = this.active.borrow().clone();
            if matches!(existing.as_ref(), Some(Err(_))) {
              inner.connection.close(0u32.into(), b"");
              break;
            }

            let c = inner.connection.clone();
            this.active.send_replace(Some(Ok(Arc::new(inner))));

            if let Some(Ok(existing)) = existing.as_ref() {
              existing.connection.close(CLOSE_MIGRATE.into(), b"migrated");
            }

            retries = 0;

            let e = loop {
              tokio::select! {
                e = c.closed() => break e,
                Some(event) = event_rx.recv() => {
                  match event {
                    InternalEvent::Migrate => {
                      retries = 0;
                      continue 'outer;
                    }
                    InternalEvent::Routed => {
                      let event_tx = event_tx.clone();
                      tokio::spawn(async move {
                        let _ = event_tx.send(Event::Routed).await;
                      });
                    }
                  }
                }
                _ = watch.changed() => {
                  if matches!(this.active.borrow().as_ref(), Some(Err(_))) {
                    break 'outer;
                  }
                }
              }
            };

            if is_retry_error(&e) {
              this.active.send_replace(None);
              retries += 1;
            } else {
              return Err(e.into());
            }
          }

          Ok(())
        };

        if let Err(e) = r.await {
          this2.active.send_replace(Some(Err(e)));
        }
      }
    });

    this.active().await?;

    let events = Events { event_rx };

    Ok((this, events))
  }
}

impl TunnelConnection {
  // compat method with other common connection types, keep signature the same
  pub fn local_addr(&self) -> Result<TunnelAddr, std::io::Error> {
    if let Some(Ok(inner)) = self.active.borrow().as_ref() {
      return Ok(inner.local_addr.clone());
    }
    let socket = self.endpoint.local_addr()?;
    Ok(TunnelAddr {
      hostname: None,
      socket,
    })
  }

  async fn active(&self) -> Result<Arc<InnerConnection>, Error> {
    // fast path, check without subscribing
    if let Some(inner) = self.active.borrow().as_ref() {
      match inner {
        Ok(inner) => match inner.connection.close_reason() {
          None => return Ok(inner.clone()),
          Some(e) => {
            if !is_retry_error(&e) {
              return Err(e.into());
            }
          }
        },
        Err(e) => {
          return Err(e.clone());
        }
      }
    }

    let mut w = self.active.subscribe();
    loop {
      let _ = w.changed().await;

      if let Some(inner) = w.borrow().as_ref() {
        match inner {
          Ok(inner) => match inner.connection.close_reason() {
            None => return Ok(inner.clone()),
            Some(e) => {
              if !is_retry_error(&e) {
                return Err(e.into());
              }
            }
          },
          Err(e) => {
            return Err(e.clone());
          }
        }
      }
    }
  }

  // compat method with other common connection types, keep signature the same
  pub async fn accept(
    &self,
  ) -> Result<(TunnelStream, TunnelAddr), std::io::Error> {
    loop {
      let inner = self.active().await.map_err(std::io::Error::other)?;

      let (tx, mut rx) = match inner.connection.accept_bi().await {
        Ok(c) => c,
        Err(e) => {
          if is_retry_error(&e) {
            continue;
          }
          return Err(e.into());
        }
      };

      match read_message(&mut rx).await {
        Ok(StreamHeader::Stream {
          remote_addr,
          local_addr,
        }) => {
          return Ok((
            TunnelStream {
              tx,
              rx,
              local_addr,
              remote_addr,
            },
            TunnelAddr {
              hostname: None,
              socket: remote_addr,
            },
          ));
        }
        Err(e) => {
          if let Error::QuinnConnection(qe) = e {
            if is_retry_error(&qe) {
              continue;
            }
            return Err(qe.into());
          }
          return Err(std::io::Error::other(e));
        }
        _ => {
          return Err(std::io::Error::other(Error::UnexpectedHeader));
        }
      }
    }
  }

  pub fn metadata(&self) -> Option<Metadata> {
    self
      .active
      .borrow()
      .as_ref()
      .and_then(|b| b.as_ref().ok())
      .map(|c| c.metadata.clone())
  }

  pub async fn create_agent_stream(&self) -> Result<TunnelStream, Error> {
    let ((mut tx, rx), remote_addr) = loop {
      let inner = self.active().await?;
      match inner.connection.open_bi().await {
        Ok(c) => break (c, inner.connection.remote_address()),
        Err(e) => {
          if is_retry_error(&e) {
            continue;
          }
          return Err(e.into());
        }
      };
    };

    write_message(&mut tx, StreamHeader::Agent {}).await?;
    Ok(TunnelStream {
      tx,
      rx,
      local_addr: self.endpoint.local_addr()?,
      remote_addr,
    })
  }

  pub async fn close(&self, code: impl Into<quinn::VarInt>, reason: &[u8]) {
    self.active.send_replace(Some(Err(Error::QuinnConnection(
      quinn::ConnectionError::LocallyClosed,
    ))));
    self.endpoint.close(code.into(), reason);
    self.endpoint.wait_idle().await;
  }
}

fn is_retry_error(e: &quinn::ConnectionError) -> bool {
  match e {
    quinn::ConnectionError::ApplicationClosed(_)
    | quinn::ConnectionError::ConnectionClosed(_)
    | quinn::ConnectionError::TimedOut
    | quinn::ConnectionError::Reset
    | quinn::ConnectionError::LocallyClosed => true,
    quinn::ConnectionError::VersionMismatch
    | quinn::ConnectionError::CidsExhausted
    | quinn::ConnectionError::TransportError(_) => false,
  }
}

#[derive(Debug)]
#[pin_project::pin_project]
pub struct TunnelStream {
  #[pin]
  tx: quinn::SendStream,
  #[pin]
  rx: quinn::RecvStream,

  local_addr: SocketAddr,
  remote_addr: SocketAddr,
}

impl TunnelStream {
  pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
    Ok(self.local_addr)
  }

  pub fn peer_addr(&self) -> Result<SocketAddr, std::io::Error> {
    Ok(self.remote_addr)
  }

  pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
    (
      OwnedReadHalf {
        rx: self.rx,
        local_addr: self.local_addr,
        remote_addr: self.remote_addr,
      },
      OwnedWriteHalf { tx: self.tx },
    )
  }
}

impl AsyncRead for TunnelStream {
  fn poll_read(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    self.project().rx.poll_read(cx, buf)
  }
}

impl AsyncWrite for TunnelStream {
  fn poll_write(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &[u8],
  ) -> std::task::Poll<Result<usize, std::io::Error>> {
    AsyncWrite::poll_write(self.project().tx, cx, buf)
  }

  fn poll_flush(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<(), std::io::Error>> {
    self.project().tx.poll_flush(cx)
  }

  fn poll_shutdown(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<(), std::io::Error>> {
    self.project().tx.poll_shutdown(cx)
  }
}

/// The readable half returned from `into_split`
#[pin_project::pin_project]
pub struct OwnedReadHalf {
  #[pin]
  rx: quinn::RecvStream,

  local_addr: SocketAddr,
  remote_addr: SocketAddr,
}

impl OwnedReadHalf {
  /// Whether this OwnedReadHalf and an OwnedWriteHalf came from the same TunnelStream
  pub fn is_pair_of(&self, write_half: &OwnedWriteHalf) -> bool {
    self.rx.id() == write_half.tx.id()
  }

  /// Re-join a split OwnedReadHalf and OwnedWriteHalf.
  ///
  /// # Panics
  ///
  /// If this OwnedReadHalf and the given OwnedWriteHalf do not originate
  /// from the same split operation this method will panic. This can be
  /// checked ahead of time by calling `is_pair_of()`.
  pub fn unsplit(self, write_half: OwnedWriteHalf) -> TunnelStream {
    if self.is_pair_of(&write_half) {
      TunnelStream {
        tx: write_half.tx,
        rx: self.rx,
        local_addr: self.local_addr,
        remote_addr: self.remote_addr,
      }
    } else {
      panic!("Unrelated `OwnedWriteHalf` passed to `OwnedReadHalf::unsplit`");
    }
  }
}

impl AsyncRead for OwnedReadHalf {
  fn poll_read(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    self.project().rx.poll_read(cx, buf)
  }
}

/// The writable half returned from `into_split`
#[pin_project::pin_project]
pub struct OwnedWriteHalf {
  #[pin]
  tx: quinn::SendStream,
}

impl AsyncWrite for OwnedWriteHalf {
  fn poll_write(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &[u8],
  ) -> std::task::Poll<Result<usize, std::io::Error>> {
    AsyncWrite::poll_write(self.project().tx, cx, buf)
  }

  fn poll_flush(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<(), std::io::Error>> {
    self.project().tx.poll_flush(cx)
  }

  fn poll_shutdown(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<(), std::io::Error>> {
    self.project().tx.poll_shutdown(cx)
  }
}

impl OwnedWriteHalf {
  pub fn reset(
    &mut self,
    code: impl Into<quinn::VarInt>,
  ) -> Result<(), quinn::ClosedStream> {
    self.tx.reset(code.into())
  }
}

/// Header for new streams
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum StreamHeader {
  Control {
    metadata: Option<HashMap<String, String>>,
  },
  Stream {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
  },
  Agent {},
}

/// Messages for control streams
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ControlMessage {
  AuthenticateApp {
    token: String,
    org: String,
    app: String,
  },
  AuthenticateCluster {
    token: String,
  },
  Authenticated {
    metadata: HashMap<String, String>,
    addr: SocketAddr,
    hostnames: Vec<String>,
    env: HashMap<String, String>,
  },
  Routed {},
  Migrate {},
}

// Using this function instead of WriteExt::write_u32_le to avoid std::io::Error
async fn write_u32_le(tx: &mut quinn::SendStream, v: u32) -> Result<(), Error> {
  Ok(tx.write_all(&v.to_le_bytes()).await?)
}

// Using this function instead of WriteExt::read_u32_le to avoid std::io::Error
async fn read_u32_le(rx: &mut quinn::RecvStream) -> Result<u32, Error> {
  let mut data = [0; std::mem::size_of::<u32>()];
  rx.read_exact(&mut data).await?;
  Ok(u32::from_le_bytes(data))
}

pub async fn write_message<T: serde::Serialize>(
  tx: &mut quinn::SendStream,
  message: T,
) -> Result<(), Error> {
  let data = serde_json::to_vec(&message)?;
  write_u32_le(tx, data.len() as _).await?;
  tx.write_all(&data).await?;
  Ok(())
}

pub async fn read_message<T: serde::de::DeserializeOwned>(
  rx: &mut quinn::RecvStream,
) -> Result<T, Error> {
  let length = read_u32_le(rx).await?;
  let mut data = vec![0; length as usize];
  rx.read_exact(&mut data).await?;
  let message = serde_json::from_slice(&data)?;
  Ok(message)
}
