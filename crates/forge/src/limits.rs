//! Abuse limits: password-attempt backoff, the global Argon2 concurrency cap,
//! and trusted-proxy source resolution.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Counting gate that bounds concurrent password verifications.
pub struct Gate {
    free: Mutex<usize>,
    cv: Condvar,
}

/// A held slot in a [`Gate`]; released on drop.
pub struct Permit<'a>(&'a Gate);

impl Gate {
    pub fn new(slots: usize) -> Gate {
        Gate {
            free: Mutex::new(slots.max(1)),
            cv: Condvar::new(),
        }
    }

    /// Block until a slot is free.
    pub fn acquire(&self) -> Permit<'_> {
        let mut n = self.free.lock().unwrap_or_else(|e| e.into_inner());
        while *n == 0 {
            n = self.cv.wait(n).unwrap_or_else(|e| e.into_inner());
        }
        *n -= 1;
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.free.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.0.cv.notify_one();
    }
}

const WINDOW: Duration = Duration::from_secs(600);
const SOURCE_WINDOW: Duration = Duration::from_secs(60);
/// Failed attempts one source may make per minute before it is refused.
const SOURCE_CAP: usize = 30;
const MAX_DELAY: Duration = Duration::from_secs(2);
const MAX_ENTRIES: usize = 10_000;

/// Failure bookkeeping for password logins. Not a lockout: a stranger failing
/// against `alice` slows other *wrong* guesses but never blocks alice's right
/// one, and a flooding source is refused alone.
#[derive(Default)]
pub struct Backoff {
    by_login: Mutex<HashMap<String, Vec<Instant>>>,
    by_source: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

fn prune(v: &mut Vec<Instant>, window: Duration) {
    let now = Instant::now();
    v.retain(|t| now.duration_since(*t) < window);
}

impl Backoff {
    /// Has this source exhausted its per-minute failure budget?
    pub fn source_blocked(&self, ip: IpAddr) -> bool {
        let mut m = self.by_source.lock().unwrap_or_else(|e| e.into_inner());
        match m.get_mut(&ip) {
            Some(v) => {
                prune(v, SOURCE_WINDOW);
                v.len() >= SOURCE_CAP
            }
            None => false,
        }
    }

    /// Record a failed attempt; returns how long to delay the failure response
    /// (doubling from 50 ms, capped at 2 s).
    pub fn record_failure(&self, login: &str, ip: IpAddr) -> Duration {
        let n = {
            let mut m = self.by_login.lock().unwrap_or_else(|e| e.into_inner());
            if m.len() > MAX_ENTRIES {
                m.retain(|_, v| {
                    prune(v, WINDOW);
                    !v.is_empty()
                });
            }
            let v = m.entry(login.to_lowercase()).or_default();
            prune(v, WINDOW);
            v.push(Instant::now());
            v.len() as u32
        };
        {
            let mut m = self.by_source.lock().unwrap_or_else(|e| e.into_inner());
            if m.len() > MAX_ENTRIES {
                m.retain(|_, v| {
                    prune(v, SOURCE_WINDOW);
                    !v.is_empty()
                });
            }
            m.entry(ip).or_default().push(Instant::now());
        }
        Duration::from_millis(50u64.saturating_mul(1u64 << (n - 1).min(16))).min(MAX_DELAY)
    }

    /// A success clears the login's failures.
    pub fn record_success(&self, login: &str) {
        self.by_login
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&login.to_lowercase());
    }
}

/// One CIDR block, e.g. `10.0.0.0/8` or `::1/128`.
#[derive(Clone, Debug)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (addr, bits) = s.split_once('/').unwrap_or((s, ""));
        let net: IpAddr = addr
            .parse()
            .map_err(|_| format!("bad address in CIDR {s:?}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = if bits.is_empty() {
            max
        } else {
            bits.parse()
                .map_err(|_| format!("bad prefix in CIDR {s:?}"))?
        };
        if bits > max {
            return Err(format!("prefix too long in CIDR {s:?}"));
        }
        Ok(Cidr { net, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        fn v(ip: IpAddr) -> u128 {
            match ip {
                IpAddr::V4(a) => u128::from(u32::from(a)),
                IpAddr::V6(a) => u128::from(a),
            }
        }
        if self.net.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let width = if ip.is_ipv4() { 32 } else { 128 };
        let shift = width - u32::from(self.bits);
        shift == width || (v(self.net) >> shift) == (v(ip) >> shift)
    }
}

/// Trusted-proxy configuration for resolving the real client address.
#[derive(Clone, Default)]
pub struct Proxies {
    pub header: Option<String>,
    pub cidrs: Vec<Cidr>,
}

impl Proxies {
    /// The address to rate-limit: the forwarded-for value only when the header
    /// is configured **and** the connection's peer is inside a trusted CIDR;
    /// otherwise the peer. (A header from any other peer is ignored, so a
    /// client cannot spoof its address into the limiter.)
    pub fn resolve(&self, peer: IpAddr, header_value: Option<&str>) -> IpAddr {
        let Some(v) = header_value else { return peer };
        if self.header.is_none() || !self.cidrs.iter().any(|c| c.contains(peer)) {
            return peer;
        }
        // Walk from the right: the first address that is not one of our own
        // trusted proxies is the client as the outermost proxy saw it.
        v.rsplit(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .find(|a| !self.cidrs.iter().any(|c| c.contains(*a)))
            .unwrap_or(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn delay_doubles_and_caps_and_success_resets() {
        let b = Backoff::default();
        let d: Vec<u128> = (0..8)
            .map(|_| b.record_failure("Alice", ip("1.1.1.1")).as_millis())
            .collect();
        assert_eq!(d, vec![50, 100, 200, 400, 800, 1600, 2000, 2000]);
        b.record_success("alice"); // case-insensitive key
        assert_eq!(b.record_failure("alice", ip("1.1.1.1")).as_millis(), 50);
    }

    #[test]
    fn a_flooding_source_is_blocked_but_others_are_not() {
        let b = Backoff::default();
        for i in 0..SOURCE_CAP {
            assert!(!b.source_blocked(ip("9.9.9.9")), "attempt {i}");
            b.record_failure(&format!("u{i}"), ip("9.9.9.9"));
        }
        assert!(b.source_blocked(ip("9.9.9.9")));
        assert!(!b.source_blocked(ip("8.8.8.8")));
    }

    #[test]
    fn cidr_membership() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!(!c.contains(ip("::1")));
        assert!(Cidr::parse("::1/128").unwrap().contains(ip("::1")));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains(ip("203.0.113.9")));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn forwarded_for_is_trusted_only_from_a_trusted_peer() {
        let p = Proxies {
            header: Some("x-forwarded-for".into()),
            cidrs: vec![Cidr::parse("127.0.0.1/32").unwrap()],
        };
        assert_eq!(
            p.resolve(ip("127.0.0.1"), Some("6.6.6.6, 5.5.5.5")),
            ip("5.5.5.5")
        );
        // a chain of our own proxies is skipped from the right
        assert_eq!(
            p.resolve(ip("127.0.0.1"), Some("6.6.6.6, 5.5.5.5, 127.0.0.1")),
            ip("5.5.5.5")
        );
        assert_eq!(p.resolve(ip("7.7.7.7"), Some("6.6.6.6")), ip("7.7.7.7"));
        assert_eq!(p.resolve(ip("127.0.0.1"), None), ip("127.0.0.1"));
        assert_eq!(
            Proxies::default().resolve(ip("127.0.0.1"), Some("6.6.6.6")),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn gate_bounds_concurrency() {
        let g = Gate::new(1);
        let p = g.acquire();
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                let _q = g.acquire();
            });
            std::thread::sleep(Duration::from_millis(50));
            assert!(
                !h.is_finished(),
                "second acquire must wait for the first permit"
            );
            drop(p);
        });
    }
}
