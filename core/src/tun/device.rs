//! TUN-устройство поверх файлового дескриптора от Android VpnService.

use std::io;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Fd(RawFd);

impl std::os::fd::AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

pub struct TunDevice {
    fd: AsyncFd<Fd>,
}

impl TunDevice {
    /// Дублирует `fd` (оригинал остаётся у Java) и переводит копию в неблокирующий режим.
    pub fn from_fd(fd: RawFd) -> io::Result<Self> {
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            let flags = libc::fcntl(dup, libc::F_GETFL);
            libc::fcntl(dup, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        #[allow(deprecated)]
        let fd = AsyncFd::new(Fd(dup))?;
        Ok(Self { fd })
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| {
                let n = unsafe { libc::read(inner.get_ref().0, unfilled.as_mut_ptr() as *mut _, unfilled.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard.try_io(|inner| {
                let n = unsafe { libc::write(inner.get_ref().0, buf.as_ptr() as *const _, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => return Poll::Ready(r),
                Err(_would_block) => continue,
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
