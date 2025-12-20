//! `async-tls` integration.
use tungstenite::client::{uri_mode, IntoClientRequest};
use tungstenite::handshake::client::{Request, Response};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::Error;

use futures_io::{AsyncRead, AsyncWrite};

use super::{client_async_with_config, WebSocketStream};

use futures_rustls::client::TlsStream;
use futures_rustls::TlsConnector as AsyncTlsConnector;
use futures_rustls::rustls as rustls;
use real_futures_rustls as futures_rustls;

use tungstenite::stream::Mode;

use crate::domain;
use crate::stream::Stream as StreamSwitcher;

type MaybeTlsStream<S> = StreamSwitcher<S, TlsStream<S>>;

pub(crate) type AutoStream<S> = MaybeTlsStream<S>;

async fn wrap_stream<S>(
    socket: S,
    domain: String,
    connector: Option<AsyncTlsConnector>,
    mode: Mode,
) -> Result<AutoStream<S>, Error>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin,
{
    match mode {
        Mode::Plain => Ok(StreamSwitcher::Plain(TokioAdapter::new(socket))),
        Mode::Tls => {
            let stream = {
                let connector = if let Some(connector) = connector {
                    connector
                } else {
                    #[cfg(feature = "rustls-manual-roots")]
                    log::error!("rustls-manual-roots was selected, but no connector was provided! No certificates can be verified in this state.");

                    let config_builder = ClientConfig::builder();

                    let config_builder = {
                        #[cfg(feature = "rustls-native-certs")]
                        {
                            use real_tokio_rustls::rustls::RootCertStore;

                            let mut root_store = RootCertStore::empty();
                            let mut native_certs = rustls_native_certs::load_native_certs();
                            if let Some(err) = native_certs.errors.drain(..).next() {
                                return Err(
                                    std::io::Error::new(std::io::ErrorKind::Other, err).into()
                                );
                            }
                            let native_certs = native_certs.certs;
                            let total_number = native_certs.len();
                            let (number_added, number_ignored) =
                                root_store.add_parsable_certificates(native_certs);
                            log::debug!("Added {number_added}/{total_number} native root certificates (ignored {number_ignored})");
                            config_builder.with_root_certificates(root_store)
                        }
                        #[cfg(feature = "rustls-platform-verifier")]
                        {
                            use rustls_platform_verifier::BuilderVerifierExt;
                            config_builder
                                .with_platform_verifier()
                                .map_err(|err| Error::Tls(TlsError::Rustls(err.into())))?
                        }
                        #[cfg(feature = "rustls-manual-roots")]
                        {
                            use real_tokio_rustls::rustls::RootCertStore;

                            config_builder.with_root_certificates(RootCertStore::empty())
                        }
                        #[cfg(all(
                            feature = "rustls-webpki-roots",
                            not(feature = "rustls-native-certs"),
                            not(feature = "rustls-platform-verifier"),
                            not(feature = "rustls-manual-roots")
                        ))]
                        {
                            use real_tokio_rustls::rustls::RootCertStore;

                            let mut root_store = RootCertStore::empty();
                            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                            config_builder.with_root_certificates(root_store)
                        }
                    };
                    TlsConnector::from(std::sync::Arc::new(config_builder.with_no_client_auth()))
                };
                let domain = ServerName::try_from(domain)
                    .map_err(|_| Error::Tls(TlsError::InvalidDnsName))?;
                connector.connect(domain, socket).await?
            };
            Ok(StreamSwitcher::Tls(TokioAdapter::new(stream)))
        }
    }
}

/// Type alias for the stream type of the `client_async()` functions.
pub type ClientStream<S> = AutoStream<S>;

/// Creates a WebSocket handshake from a request and a stream,
/// upgrading the stream to TLS if required.
pub async fn client_futures_rustls<R, S>(
    request: R,
    stream: S,
) -> Result<(WebSocketStream<ClientStream<S>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
    S: 'static + AsyncRead + AsyncWrite + Unpin,
    AutoStream<S>: Unpin,
{
    client_futures_rustls_with_connector_and_config(request, stream, None, None).await
}

/// Creates a WebSocket handshake from a request and a stream,
/// upgrading the stream to TLS if required and using the given
/// WebSocket configuration.
pub async fn client_futures_rustls_with_config<R, S>(
    request: R,
    stream: S,
    config: Option<WebSocketConfig>,
) -> Result<(WebSocketStream<ClientStream<S>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
    S: 'static + AsyncRead + AsyncWrite + Unpin,
    AutoStream<S>: Unpin,
{
    client_futures_rustls_with_connector_and_config(request, stream, None, config).await
}

/// Creates a WebSocket handshake from a request and a stream,
/// upgrading the stream to TLS if required and using the given
/// connector.
pub async fn client_futures_rustls_with_connector<R, S>(
    request: R,
    stream: S,
    connector: Option<AsyncTlsConnector>,
) -> Result<(WebSocketStream<ClientStream<S>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
    S: 'static + AsyncRead + AsyncWrite + Unpin,
    AutoStream<S>: Unpin,
{
    client_futures_rustls_with_connector_and_config(request, stream, connector, None).await
}

/// Creates a WebSocket handshake from a request and a stream,
/// upgrading the stream to TLS if required and using the given
/// connector and WebSocket configuration.
pub async fn client_futures_rustls_with_connector_and_config<R, S>(
    request: R,
    stream: S,
    connector: Option<AsyncTlsConnector>,
    config: Option<WebSocketConfig>,
) -> Result<(WebSocketStream<ClientStream<S>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
    S: 'static + AsyncRead + AsyncWrite + Unpin,
    AutoStream<S>: Unpin,
{
    let request: Request = request.into_client_request()?;

    let domain = domain(&request)?;

    // Make sure we check domain and mode first. URL must be valid.
    let mode = uri_mode(request.uri())?;

    let stream = wrap_stream(stream, domain, connector, mode).await?;
    client_async_with_config(request, stream, config).await
}
