// Copyright 2018-2025 the Deno authors. MIT license.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

pub use quinn;

pub const VERSION: u32 = 1;

pub const CLOSE_GENERIC: u32 = 0;
pub const CLOSE_PROTOCOL: u32 = 1;
pub const CLOSE_UNAUTHORIZED: u32 = 2;
pub const CLOSE_NOT_FOUND: u32 = 3;
pub const CLOSE_MIGRATE: u32 = 4;

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error(transparent)]
  StdIo(#[from] std::io::Error),
  #[error(transparent)]
  SerdeJson(#[from] serde_json::Error),
  #[error(transparent)]
  QuinnConnect(#[from] quinn::ConnectError),
  #[error(transparent)]
  QuinnConnection(quinn::ConnectionError),
  #[error(transparent)]
  QuinnRead(#[from] quinn::ReadError),
  #[error(transparent)]
  QuinnReadExact(#[from] quinn::ReadExactError),
  #[error(transparent)]
  QuinnWrite(#[from] quinn::WriteError),

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

/// Data obtained from the server handshake
#[derive(Debug)]
pub struct Metadata {
  pub hostnames: Vec<String>,
  pub env: HashMap<String, String>,
  pub metadata: HashMap<String, String>,
}

/// Server event
#[derive(Debug)]
pub enum Event {
  /// All endpoints are routed
  Routed,
  /// The client should migrate to a new connection
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

#[derive(Debug)]
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

#[derive(Debug, Clone)]
pub struct TunnelConnection {
  endpoint: quinn::Endpoint,
  connection: quinn::Connection,
  local_addr: TunnelAddr,
}

impl TunnelConnection {
  pub async fn connect(
    addr: std::net::SocketAddr,
    server_name: &str,
    mut tls_config: quinn::rustls::ClientConfig,
    authentication: Authentication,
  ) -> Result<(Self, Metadata, Events), Error> {
    let config = quinn::EndpointConfig::default();
    let socket = std::net::UdpSocket::bind(("::", 0))?;
    let endpoint = quinn::Endpoint::new(
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

    let connecting = endpoint.connect_with(client_config, addr, server_name)?;

    let connection = connecting.await?;

    let mut control = connection.open_bi().await?;
    control.0.write_u32_le(VERSION).await?;
    if control.1.read_u32_le().await? != VERSION {
      return Err(Error::UnsupportedVersion);
    }

    write_message(&mut control.0, StreamHeader::Control {}).await?;
    write_message(
      &mut control.0,
      match authentication {
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
          ControlMessage::Routed {} => Event::Routed,
          ControlMessage::Migrate {} => Event::Migrate,
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
    let routed = Events { event_rx };

    Ok((
      Self {
        endpoint,
        connection,
        local_addr,
      },
      metadata,
      routed,
    ))
  }
}

impl TunnelConnection {
  pub fn local_addr(&self) -> Result<TunnelAddr, std::io::Error> {
    Ok(self.local_addr.clone())
  }

  pub async fn accept(
    &self,
  ) -> Result<(TunnelStream, TunnelAddr), std::io::Error> {
    let (tx, mut rx) = self.connection.accept_bi().await?;

    let StreamHeader::Stream {
      remote_addr,
      local_addr,
    } = read_message(&mut rx).await.map_err(std::io::Error::other)?
    else {
      return Err(std::io::Error::other(Error::UnexpectedHeader));
    };

    Ok((
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
    ))
  }

  pub async fn create_agent_stream(&self) -> Result<TunnelStream, Error> {
    let (mut tx, rx) = self.connection.open_bi().await?;
    write_message(&mut tx, StreamHeader::Agent {}).await?;
    Ok(TunnelStream {
      tx,
      rx,
      local_addr: self.endpoint.local_addr()?,
      remote_addr: self.connection.remote_address(),
    })
  }

  pub async fn close(&self, code: impl Into<quinn::VarInt>, reason: &[u8]) {
    self.connection.close(code.into(), reason);
    self.endpoint.wait_idle().await;
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
pub enum StreamHeader {
  Control {},
  Stream {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
  },
  Agent {},
}

/// Messages for control streams
#[derive(Debug, serde::Serialize, serde::Deserialize)]
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

pub async fn write_message<
  T: serde::Serialize,
  W: tokio::io::AsyncWrite + Unpin,
>(
  tx: &mut W,
  message: T,
) -> Result<(), Error> {
  let data = serde_json::to_vec(&message)?;
  tx.write_u32_le(data.len() as _).await?;
  tx.write_all(&data).await?;
  Ok(())
}

pub async fn read_message<
  T: serde::de::DeserializeOwned,
  R: tokio::io::AsyncRead + Unpin,
>(
  rx: &mut R,
) -> Result<T, Error> {
  let length = rx.read_u32_le().await?;
  let mut data = vec![0; length as usize];
  rx.read_exact(&mut data).await?;
  let message = serde_json::from_slice(&data)?;
  Ok(message)
}
