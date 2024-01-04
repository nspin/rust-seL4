use core::task::{Context, Poll};

use sel4_async_network::{TcpSocket, TcpSocketError};

use super::AsyncIO;

pub struct TcpSocketWrapper {
    inner: TcpSocket,
}

impl TcpSocketWrapper {
    pub fn new(inner: TcpSocket) -> Self {
        Self { inner }
    }

    pub fn inner_mut(&mut self) -> &mut TcpSocket {
        &mut self.inner
    }

    pub fn into_inner(self) -> TcpSocket {
        self.inner
    }
}

impl AsyncIO for TcpSocketWrapper {
    type Error = TcpSocketError;

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>> {
        self.inner_mut().poll_recv(cx, buf)
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Self::Error>> {
        self.inner_mut().poll_send(cx, buf)
    }

    fn poll_flush(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // TODO
        // self.inner_mut().poll_close(cx)
        Poll::Ready(Ok(()))
    }
}
