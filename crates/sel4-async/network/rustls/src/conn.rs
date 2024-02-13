//
// Copyright 2023, Colias Group, LLC
//
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
//

// Derived from https://github.com/rustls/rustls/pull/1648 by https://github.com/japaric

use core::marker::PhantomData;
use core::mem;
use core::ops::DerefMut;
use core::pin::{pin, Pin};
use core::task::{self, Poll};

use alloc::sync::Arc;

use embedded_io_async::{Read, ReadReady, Write, WriteReady};
use futures::prelude::*;
use futures::Future;
use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::pki_types::ServerName;
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, UnbufferedStatus,
};
use rustls::{ClientConfig, ServerConfig, SideData, UnbufferedConnectionCommon};

use sel4_async_network_traits::AsyncIO;

use crate::{
    utils::{poll_read, poll_write, try_or_resize_and_retry, Buffer, WriteCursor},
    Error,
};

pub struct ClientConnector {
    config: Arc<ClientConfig>,
}

impl ClientConnector {
    pub fn connect<IO>(
        &self,
        domain: ServerName<'static>,
        stream: IO,
        // FIXME should not return an error but instead hoist it into a `Connect` variant
    ) -> Result<Connect<UnbufferedClientConnection, ClientConnectionData, IO>, Error<IO::Error>>
    where
        IO: Read + ReadReady + Write + WriteReady,
    {
        let conn = UnbufferedClientConnection::new(self.config.clone(), domain)?;

        Ok(Connect::new(conn, stream))
    }
}

impl From<Arc<ClientConfig>> for ClientConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

pub struct ServerConnector {
    config: Arc<ServerConfig>,
}

impl ServerConnector {
    pub fn connect<IO>(
        &self,
        stream: IO,
        // FIXME should not return an error but instead hoist it into a `Connect` variant
    ) -> Result<Connect<UnbufferedServerConnection, ServerConnectionData, IO>, Error<IO::Error>>
    where
        IO: Read + ReadReady + Write + WriteReady,
    {
        let conn = UnbufferedServerConnection::new(self.config.clone())?;

        Ok(Connect::new(conn, stream))
    }
}

impl From<Arc<ServerConfig>> for ServerConnector {
    fn from(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }
}

pub struct Connect<T, D, IO> {
    inner: Option<ConnectInner<T, D, IO>>,
}

impl<T, D, IO> Connect<T, D, IO> {
    fn new(conn: T, io: IO) -> Self {
        Self {
            inner: Some(ConnectInner::new(conn, io)),
        }
    }
}

struct ConnectInner<T, D, IO> {
    conn: T,
    _phantom: PhantomData<D>,
    incoming: Buffer,
    io: IO,
    outgoing: Buffer,
}

impl<T, D, IO> ConnectInner<T, D, IO> {
    fn new(conn: T, io: IO) -> Self {
        Self {
            conn,
            _phantom: PhantomData,
            incoming: Buffer::default(),
            io,
            outgoing: Buffer::default(),
        }
    }
}

impl<T, D, IO> Future for Connect<T, D, IO>
where
    D: Unpin + SideDataAugmented,
    T: Unpin + DerefMut<Target = UnbufferedConnectionCommon<D>>,
    IO: Unpin + Read + ReadReady + Write + WriteReady,
{
    type Output = Result<TlsStream<T, D, IO>, Error<IO::Error>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.inner.take().expect("polled after completion");

        let mut updates = Updates::default();
        let poll = loop {
            let action = inner.advance(&mut updates)?;

            match action {
                Action::Continue => continue,

                Action::Write => {
                    let mut outgoing = mem::take(&mut inner.outgoing);
                    let would_block = poll_write(&mut inner.io, &mut outgoing, cx)?;

                    updates.transmit_complete = outgoing.is_empty();
                    inner.outgoing = outgoing;

                    if would_block {
                        break Poll::Pending;
                    }
                }

                Action::Read => {
                    let mut incoming = mem::take(&mut inner.incoming);
                    let would_block = poll_read(&mut inner.io, &mut incoming, cx)?;

                    inner.incoming = incoming;

                    if would_block {
                        break Poll::Pending;
                    }
                }

                Action::Break => {
                    // XXX should we yield earlier when it's already possible to encrypt
                    // application data? that would reduce the number of round-trips
                    let ConnectInner {
                        conn,
                        _phantom: PhantomData,
                        incoming,
                        io,
                        outgoing,
                    } = inner;

                    return Poll::Ready(Ok(TlsStream {
                        conn,
                        _phantom: PhantomData,
                        incoming,
                        io,
                        outgoing,
                    }));
                }
            }
        };

        self.inner = Some(inner);

        poll
    }
}

#[derive(Default)]
struct Updates {
    transmit_complete: bool,
}

trait SideDataAugmented: SideData + Sized {
    fn process_tls_records_generic<'c, 'i>(
        this: &'c mut UnbufferedConnectionCommon<Self>,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self>;
}

impl SideDataAugmented for ClientConnectionData {
    fn process_tls_records_generic<'c, 'i>(
        this: &'c mut UnbufferedConnectionCommon<Self>,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self> {
        this.process_tls_records(incoming_tls)
    }
}

impl SideDataAugmented for ServerConnectionData {
    fn process_tls_records_generic<'c, 'i>(
        this: &'c mut UnbufferedConnectionCommon<Self>,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self> {
        this.process_tls_records(incoming_tls)
    }
}

impl<T, D, IO> ConnectInner<T, D, IO>
where
    T: DerefMut<Target = UnbufferedConnectionCommon<D>>,
    IO: Read + ReadReady + Write + WriteReady,
    D: SideDataAugmented,
{
    fn advance(&mut self, updates: &mut Updates) -> Result<Action, Error<IO::Error>> {
        log::trace!("incoming buffer has {}B of data", self.incoming.len());

        let UnbufferedStatus { discard, state } = SideDataAugmented::process_tls_records_generic(
            &mut self.conn,
            self.incoming.filled_mut(),
        );

        log::trace!("state: {state:?}");
        let next = match state? {
            ConnectionState::EncodeTlsData(mut state) => {
                try_or_resize_and_retry(
                    |out_buffer| state.encode(out_buffer),
                    |e| {
                        if let EncodeError::InsufficientSize(is) = &e {
                            Ok(*is)
                        } else {
                            Err(e.into())
                        }
                    },
                    &mut self.outgoing,
                )?;

                Action::Continue
            }

            ConnectionState::TransmitTlsData(state) => {
                if updates.transmit_complete {
                    updates.transmit_complete = false;
                    state.done();
                    Action::Continue
                } else {
                    Action::Write
                }
            }

            ConnectionState::BlockedHandshake { .. } => Action::Read,

            ConnectionState::WriteTraffic(_) => Action::Break,

            state => unreachable!("{state:?}"), // due to type state
        };

        self.incoming.discard(discard);

        Ok(next)
    }
}

enum Action {
    Break,
    Continue,
    Read,
    Write,
}

pub struct TlsStream<T, D, IO> {
    conn: T,
    _phantom: PhantomData<D>,
    incoming: Buffer,
    io: IO,
    outgoing: Buffer,
}

impl<T, D, IO> TlsStream<T, D, IO> {
    pub fn into_io(self) -> IO {
        self.io
    }
}

impl<T, D, IO> TlsStream<T, D, IO>
where
    T: DerefMut<Target = UnbufferedConnectionCommon<D>> + Unpin,
    IO: Read + ReadReady + Write + WriteReady + Unpin,
    D: SideDataAugmented + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, <Self as embedded_io_async::ErrorType>::Error>> {
        let mut outgoing = mem::take(&mut self.outgoing);

        // no IO here; just in-memory writes
        match SideDataAugmented::process_tls_records_generic(&mut self.conn, &mut []).state? {
            ConnectionState::WriteTraffic(mut state) => {
                try_or_resize_and_retry(
                    |out_buffer| state.encrypt(buf, out_buffer),
                    |e| {
                        if let EncryptError::InsufficientSize(is) = &e {
                            Ok(*is)
                        } else {
                            Err(e.into())
                        }
                    },
                    &mut outgoing,
                )?;
            }

            ConnectionState::Closed => {
                return Poll::Ready(Err(Error::ConnectionAborted));
            }

            state => unreachable!("{state:?}"),
        }

        // opportunistically try to write data into the socket
        // XXX should this be a loop?
        while !outgoing.is_empty() {
            let would_block = poll_write(&mut self.io, &mut outgoing, cx)?;
            if would_block {
                break;
            }
        }

        self.outgoing = outgoing;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, <Self as embedded_io_async::ErrorType>::Error>> {
        let mut incoming = mem::take(&mut self.incoming);
        let mut cursor = WriteCursor::new(buf);

        while !cursor.is_full() {
            log::trace!("incoming buffer has {}B of data", incoming.len());

            let UnbufferedStatus { mut discard, state } =
                SideDataAugmented::process_tls_records_generic(
                    &mut self.conn,
                    incoming.filled_mut(),
                );

            match state? {
                ConnectionState::ReadTraffic(mut state) => {
                    while let Some(res) = state.next_record() {
                        let AppDataRecord {
                            discard: new_discard,
                            payload,
                        } = res?;
                        discard += new_discard;

                        let remainder = cursor.append(payload);

                        if !remainder.is_empty() {
                            // stash
                            todo!()
                        }
                    }
                }

                ConnectionState::WriteTraffic(_) => {
                    let would_block = poll_read(&mut self.io, &mut incoming, cx)?;

                    if would_block {
                        self.incoming = incoming;
                        // TODO(nspin) new
                        if cursor.used() != 0 {
                            break;
                        }
                        return Poll::Pending;
                    }
                }

                ConnectionState::Closed => break,

                state => unreachable!("{state:?}"),
            }

            incoming.discard(discard);
        }

        Poll::Ready(Ok(cursor.into_used()))
    }

    fn poll_flush_except_io(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Error<IO::Error>>> {
        let mut outgoing = mem::take(&mut self.outgoing);

        // write buffered TLS data into socket
        while !outgoing.is_empty() {
            let would_block = poll_write(&mut self.io, &mut outgoing, cx)?;

            if would_block {
                self.outgoing = outgoing;
                return Poll::Pending;
            }
        }

        self.outgoing = outgoing;

        Poll::Ready(Ok(()))
    }

    #[cfg(any())]
    #[allow(unused_mut)]
    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Error<IO::Error>>> {
        // XXX write out close_notify here?
        Pin::new(&mut self.io)
            .poll_close(cx)
            .map_err(Error::TransitError)
    }
}

impl<T, D, IO> embedded_io_async::ErrorType for TlsStream<T, D, IO>
where
    IO: embedded_io_async::ErrorType,
{
    type Error = Error<IO::Error>;
}

// impl<T, D, IO> Read for TlsStream<T, D, IO>
// where
//     T: DerefMut<Target = UnbufferedConnectionCommon<D>> + Unpin,
//     IO: Read + ReadReady + Write + WriteReady + Unpin,
//     D: SideDataAugmented + Unpin,
// {
//     async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
//         future::poll_fn(move |cx| Pin::new(&mut self).poll_read(cx, buf)).await
//     }
// }

// impl<T, D, IO> Write for TlsStream<T, D, IO>
// where
//     IO: Write + Unpin,
// {
//     async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
//         future::poll_fn(|cx| Pin::new(self).poll_write(cx, buf)).await
//     }

//     async fn flush(&mut self) -> Result<(), Self::Error> {
//         future::poll_fn(|cx| Pin::new(self).poll_flush_except_io(cx)).await?;
//         self.io.flush().await.map_err(Error::TransitError)
//     }
// }
