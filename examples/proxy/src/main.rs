use async_std::net::{TcpListener, TcpStream, ToSocketAddrs};
use async_std::prelude::*;
use async_std::task;
use futures::{
    future::FutureExt,
    io::{AsyncRead, AsyncWrite},
};
use std::net::{IpAddr, SocketAddr};

async fn handshake<Reader, Writer>(
    mut reader: Reader,
    mut writer: Writer,
) -> anyhow::Result<TcpStream>
where
    Reader: AsyncRead + Unpin,
    Writer: AsyncWrite + Unpin,
{
    match socksv5::read_version(&mut reader).await? {
        socksv5::SocksVersion::V5 => {
            let handshake = socksv5::v5::read_handshake_skip_version(&mut reader).await?;

            if let None = handshake
                .methods
                .into_iter()
                .find(|m| *m == socksv5::v5::SocksV5AuthMethod::Noauth)
            {
                return Err(anyhow::anyhow!("this proxy only supports NOAUTH"));
            }

            socksv5::v5::write_auth_method(&mut writer, socksv5::v5::SocksV5AuthMethod::Noauth)
                .await?;

            let request = socksv5::v5::read_request(&mut reader).await?;

            match request.command {
                socksv5::v5::SocksV5Command::Connect => {
                    let host = match request.host {
                        socksv5::v5::SocksV5Host::Ipv4(ip) => {
                            SocketAddr::new(IpAddr::V4(ip.into()), request.port)
                        }
                        socksv5::v5::SocksV5Host::Ipv6(ip) => {
                            SocketAddr::new(IpAddr::V6(ip.into()), request.port)
                        }
                        socksv5::v5::SocksV5Host::Domain(domain) => {
                            let domain = String::from_utf8(domain)?;
                            let mut addr = (&domain as &str, request.port)
                                .to_socket_addrs()
                                .await?
                                .next()
                                .ok_or_else(|| anyhow::anyhow!("failed to resolve domain"))?;
                            addr.set_port(request.port);
                            addr
                        }
                    };

                    let server_socket = TcpStream::connect(host).await;

                    match server_socket {
                        Ok(server_socket) => {
                            socksv5::v5::write_request_status(
                                &mut writer,
                                socksv5::v5::SocksV5RequestStatus::Success,
                                socksv5::v5::SocksV5Host::Ipv4([0, 0, 0, 0]),
                                0,
                            )
                            .await?;
                            return Ok(server_socket);
                        }
                        Err(e) => {
                            socksv5::v5::write_request_status(
                                &mut writer,
                                socksv5::v5::SocksV5RequestStatus::from_io_error(e),
                                socksv5::v5::SocksV5Host::Ipv4([0, 0, 0, 0]),
                                0,
                            )
                            .await?;
                            return Err(anyhow::anyhow!("failed to connect"));
                        }
                    }
                }
                cmd => {
                    socksv5::v5::write_request_status(
                        &mut writer,
                        socksv5::v5::SocksV5RequestStatus::CommandNotSupported,
                        socksv5::v5::SocksV5Host::Ipv4([0, 0, 0, 0]),
                        0,
                    )
                    .await?;
                    return Err(anyhow::anyhow!("unsupported command {:?}", cmd));
                }
            }
        }
        socksv5::SocksVersion::V4 => {
            let request = socksv5::v4::read_request(reader).await?;

            match request.command {
                socksv5::v4::SocksV4Command::Connect => {
                    let host = match request.host {
                        socksv5::v4::SocksV4Host::Ip(ip) => {
                            SocketAddr::new(IpAddr::V4(ip.into()), request.port)
                        }
                        socksv5::v4::SocksV4Host::Domain(domain) => {
                            let domain = String::from_utf8(domain)?;
                            domain
                                .to_socket_addrs()
                                .await?
                                .next()
                                .ok_or_else(|| anyhow::anyhow!("failed to resolve domain"))?
                        }
                    };

                    let server_socket = TcpStream::connect(host).await;

                    match server_socket {
                        Ok(server_socket) => {
                            socksv5::v4::write_request_status(
                                &mut writer,
                                socksv5::v4::SocksV4RequestStatus::Granted,
                                [0, 0, 0, 0],
                                0,
                            )
                            .await?;
                            return Ok(server_socket);
                        }
                        Err(_) => {
                            socksv5::v4::write_request_status(
                                &mut writer,
                                socksv5::v4::SocksV4RequestStatus::Failed,
                                [0, 0, 0, 0],
                                0,
                            )
                            .await?;
                            return Err(anyhow::anyhow!("failed to connect"));
                        }
                    }
                }
                cmd => {
                    socksv5::v4::write_request_status(
                        &mut writer,
                        socksv5::v4::SocksV4RequestStatus::Failed,
                        [0, 0, 0, 0],
                        0,
                    )
                    .await?;
                    return Err(anyhow::anyhow!("unsupported command {:?}", cmd));
                }
            }
        }
    }
}

async fn pipe<Reader, Writer>(mut reader: Reader, mut writer: Writer) -> std::io::Result<()>
where
    Reader: AsyncRead + Unpin,
    Writer: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n > 0 {
            writer.write_all(&buf[..n]).await?;
        } else {
            break Ok(());
        }
    }
}

async fn pipe_multiple<Reader1, Writer1, Reader2, Writer2>(
    reader1: Reader1,
    writer1: Writer1,
    reader2: Reader2,
    writer2: Writer2,
) -> std::io::Result<()>
where
    Reader1: AsyncRead + Unpin,
    Writer1: AsyncWrite + Unpin,
    Reader2: AsyncRead + Unpin,
    Writer2: AsyncWrite + Unpin,
{
    let pipe1 = pipe(reader1, writer2).fuse();
    let pipe2 = pipe(reader2, writer1).fuse();

    futures::pin_mut!(pipe1, pipe2);

    futures::select! {
        res = pipe1 => res,
        res = pipe2 => res
    }
}

async fn server() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:1987").await?;
    let mut incoming = listener.incoming();

    while let Some(client_stream) = incoming.next().await {
        let client_stream = client_stream?;
        log::debug!("incoming request from {}", client_stream.peer_addr().unwrap());

        task::spawn(async move {
            let (client_reader, client_writer) = &mut (&client_stream, &client_stream);

            match handshake(client_reader, client_writer).await {
                Err(err) => log::error!("handshake error: {}", err),
                Ok(server_socket) => {
                    log::debug!("{} initiated connection with {}", client_stream.peer_addr().unwrap(), server_socket.peer_addr().unwrap());

                    let (client_reader, client_writer) = &mut (&client_stream, &client_stream);
                    let (server_reader, server_writer) = &mut (&server_socket, &server_socket);

                    match pipe_multiple(client_reader, client_writer, server_reader, server_writer)
                        .await
                    {
                        Err(err) => log::error!("pipe error: {}", err),
                        Ok(_) => log::debug!{"connection terminated between {} and {}", client_stream.peer_addr().unwrap(), server_socket.peer_addr().unwrap()}
                    }
                }
            }
        });
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    env_logger::init();

    task::block_on(server())
}
