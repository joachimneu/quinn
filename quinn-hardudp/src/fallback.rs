use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    task::{Context, Poll},
    time::Instant,
    cmp::{min},
    convert::TryInto,
};

use proto::Transmit;
use tokio::io::ReadBuf;

use blake2::{Blake2b512, Digest};

use super::{log_sendmsg_error, RecvMeta, UdpState, IO_ERROR_LOG_INTERVAL};

/// Tokio-compatible UDP socket with some useful specializations.
///
/// Unlike a standard tokio UDP socket, this allows ECN bits to be read and written on some
/// platforms.
#[derive(Debug)]
pub struct UdpSocket {
    io: tokio::net::UdpSocket,
    last_send_error: Instant,
}

impl UdpSocket {
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<UdpSocket> {
        socket.set_nonblocking(true)?;
        let now = Instant::now();
        Ok(UdpSocket {
            io: tokio::net::UdpSocket::from_std(socket)?,
            last_send_error: now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now),
        })
    }

    pub fn poll_send(
        &mut self,
        _state: &UdpState,
        cx: &mut Context,
        transmits: &[Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        let mut sent = 0;
        for transmit in transmits {


            // HARDEN UDP

            // println!("sending: {:?} len: {:?}", transmit, transmit.contents.len());

            assert!(transmit.contents.len() <= 1200);
            assert!(Blake2b512::output_size() == 64);

            let mut hasher = Blake2b512::new();
            hasher.update(b"my key goes here");   // TODO: pick key based on (src, dst) IP pair ...

            let mut buf = [0u8; 1200 + 78 + 2 + 64];
            buf[0..min(transmit.contents.len(), 1200)].clone_from_slice(&transmit.contents);
            buf[1278..1280].clone_from_slice(&(transmit.contents.len() as u16).to_be_bytes());
            hasher.update(&buf[0..1280]);
            buf[1280..1344].clone_from_slice(&hasher.finalize());

            // println!("sending: {:?} len: {:?}", buf, buf.len());

            // HARDEN UDP (END)


            match self
                .io
                // .poll_send_to(cx, &transmit.contents, transmit.destination)
                .poll_send_to(cx, &buf, transmit.destination)
            {
                Poll::Ready(Ok(_)) => {
                    sent += 1;
                }
                // We need to report that some packets were sent in this case, so we rely on
                // errors being either harmlessly transient (in the case of WouldBlock) or
                // recurring on the next call.
                Poll::Ready(Err(_)) | Poll::Pending if sent != 0 => return Poll::Ready(Ok(sent)),
                Poll::Ready(Err(e)) => {
                    // WouldBlock is expected to be returned as `Poll::Pending`
                    debug_assert!(e.kind() != io::ErrorKind::WouldBlock);

                    // Errors are ignored, since they will ususally be handled
                    // by higher level retransmits and timeouts.
                    // - PermissionDenied errors have been observed due to iptable rules.
                    //   Those are not fatal errors, since the
                    //   configuration can be dynamically changed.
                    // - Destination unreachable errors have been observed for other
                    log_sendmsg_error(&mut self.last_send_error, e, transmit);
                    sent += 1;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(sent))
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty());
        let mut buf = ReadBuf::new(&mut bufs[0]);
        let addr = ready!(self.io.poll_recv_from(cx, &mut buf))?;


        // HARDEN UDP

        // println!("received: {:?} len: {:?}", buf.filled(), buf.filled().len());

        let mut hasher = Blake2b512::new();
        hasher.update(b"my key goes here");   // TODO: pick key based on (src, dst) IP pair ...

        assert!(buf.filled().len() == 1344);

        hasher.update(&buf.filled()[0..1280]);
        let hash_bytes: [u8; 64] = hasher.finalize().into();
        assert!(hash_bytes == buf.filled()[1280..1344]);

        let len = u16::from_be_bytes(buf.filled()[1278..1280].try_into().unwrap()) as usize;
        buf.set_filled(len);

        // println!("received: {:?} len: {:?}", buf.filled(), buf.filled().len());

        // HARDEN UDP (END)


        meta[0] = RecvMeta {
            len: buf.filled().len(),
            addr,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

/// Returns the platforms UDP socket capabilities
pub fn udp_state() -> super::UdpState {
    super::UdpState {
        max_gso_segments: std::sync::atomic::AtomicUsize::new(1),
    }
}

pub const BATCH_SIZE: usize = 1;
