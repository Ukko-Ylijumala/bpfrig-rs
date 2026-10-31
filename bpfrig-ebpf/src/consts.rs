// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! Kernel constants a BPF program compares against; there is no libc under
    no_std. Values from the Linux UAPI headers named in each group.

    Types follow where the value usually comes from: an address family is
    `sa_family_t` (u16) as read from `sock`, so widen it where it is
    compared against a hook's `int family`. Flag words and socket fields
    in `bpf_sock` are u32. Errnos are positive, as in errno.h: deny with
    `-EPERM`.
*/

/* Address families (linux/socket.h). */
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_VSOCK: u16 = 40;

/* Socket types (linux/net.h). */
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_SEQPACKET: u32 = 5;

/* IP protocols (linux/in.h). */
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;
pub const IPPROTO_SCTP: u32 = 132;

/* Message flags (linux/socket.h). */
pub const MSG_PEEK: u32 = 0x2;
pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_ZEROCOPY: u32 = 0x0400_0000;

/* Errnos (asm-generic/errno-base.h, asm-generic/errno.h). */
pub const EPERM: i32 = 1;
pub const EAGAIN: i32 = 11;
pub const EPROTONOSUPPORT: i32 = 93;
pub const EOPNOTSUPP: i32 = 95;
pub const EAFNOSUPPORT: i32 = 97;

/* Signals (asm/signal.h), as `bpf_send_signal` takes them. */
pub const SIGKILL: u32 = 9;

/* TC verdicts (linux/pkt_cls.h). */
pub const TC_ACT_OK: i32 = 0;
pub const TC_ACT_SHOT: i32 = 2;
/** Continue with the next program or classifier. Under TCX a 0
    (`TC_ACT_OK`) is `TCX_PASS`, which ends the hook chain and skips
    later programs and classic filters, so a program that only observes
    returns this.
*/
pub const TC_ACT_UNSPEC: i32 = -1;
