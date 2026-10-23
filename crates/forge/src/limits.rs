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
const MAX_ENTRIES: usize = 10_000;
const MAX_KEY: usize = 128;

/// Failure bookkeeping for password logins. Not a lockout: a stranger failing
/// against `alice` slows other *wrong* guesses but never blocks alice's right
/// one, and a flooding source is refused alone.
pub struct Backoff {
    source_cap: usize,
    max_delay: Duration,
    by_login: Mutex<HashMap<String, Vec<Instant>>>,
    by_source: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl Default for Backoff {
    /// 30 attempts per source per minute, delays doubling from 50 ms to 2 s.
    fn default() -> Backoff {
        Backoff::new(30, Duration::from_secs(2))
    }
}

fn prune(v: &mut Vec<Instant>, window: Duration) {
    let now = Instant::now();
    v.retain(|t| now.duration_since(*t) < window);
}

/// Keep a map bounded: drop expired entries, and if it is still over budget
/// start over. shortcut: a distributed flood of more than MAX_ENTRIES live
/// sources resets everyone's counters; move to an LRU if that is ever seen.
fn bound<K>(m: &mut HashMap<K, Vec<Instant>>, window: Duration) {
    if m.len() > MAX_ENTRIES {
        m.retain(|_, v| {
            prune(v, window);
            !v.is_empty()
        });
        if m.len() > MAX_ENTRIES {
            m.clear();
        }
    }
}

/// IPv6 sources are keyed by their /64, since one host usually holds a whole
/// /64 and could otherwise mint endless distinct keys.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => IpAddr::V6((u128::from(a) & (u128::MAX << 64)).into()),
        v4 => v4,
    }
}

impl Backoff {
    pub fn new(source_cap: usize, max_delay: Duration) -> Backoff {
        Backoff {
            source_cap,
            max_delay,
            by_login: Mutex::default(),
            by_source: Mutex::default(),
        }
    }

    /// Reserve one password attempt for `ip`. `false` when the source has used
    /// its per-minute budget; the check and the reservation are one step, so
    /// concurrent requests cannot all slip under the cap. A failure keeps the
    /// reservation as its record; [`Backoff::success`] gives it back.
    pub fn begin(&self, ip: IpAddr) -> bool {
        let ip = source_key(ip);
        let mut m = self.by_source.lock().unwrap_or_else(|e| e.into_inner());
        bound(&mut m, SOURCE_WINDOW);
        let v = m.entry(ip).or_default();
        prune(v, SOURCE_WINDOW);
        if v.len() >= self.source_cap {
            return false;
        }
        v.push(Instant::now());
        true
    }

    /// Record a failed attempt; returns how long to delay the failure response
    /// (doubling from 50 ms, capped).
    pub fn failure(&self, login: &str, _ip: IpAddr) -> Duration {
        let mut m = self.by_login.lock().unwrap_or_else(|e| e.into_inner());
        bound(&mut m, WINDOW);
        let key: String = login.to_lowercase().chars().take(MAX_KEY).collect();
        let v = m.entry(key).or_default();
        prune(v, WINDOW);
        v.push(Instant::now());
        let n = v.len() as u32;
        Duration::from_millis(50u64.saturating_mul(1u64 << (n - 1).min(16))).min(self.max_delay)
    }

    /// A success clears the login's failures and returns the source's reservation.
    pub fn success(&self, login: &str, ip: IpAddr) {
        let ip = source_key(ip);
        let key: String = login.to_lowercase().chars().take(MAX_KEY).collect();
        self.by_login
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
        if let Some(v) = self
            .by_source
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&ip)
        {
            v.pop();
        }
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
            .map(|_| b.failure("Alice", ip("1.1.1.1")).as_millis())
            .collect();
        assert_eq!(d, vec![50, 100, 200, 400, 800, 1600, 2000, 2000]);
        b.success("alice", ip("1.1.1.1")); // case-insensitive key
        assert_eq!(b.failure("alice", ip("1.1.1.1")).as_millis(), 50);
    }

    #[test]
    fn the_source_budget_is_reserved_atomically_and_per_source() {
        let b = Backoff::new(3, Duration::ZERO);
        assert!([
            b.begin(ip("9.9.9.9")),
            b.begin(ip("9.9.9.9")),
            b.begin(ip("9.9.9.9"))
        ]
        .iter()
        .all(|x| *x));
        assert!(
            !b.begin(ip("9.9.9.9")),
            "the fourth attempt is refused before any verification ran"
        );
        assert!(b.begin(ip("8.8.8.8")), "other sources are unaffected");
        b.success("u", ip("9.9.9.9")); // a success gives its reservation back
        assert!(b.begin(ip("9.9.9.9")));
    }

    #[test]
    fn one_ipv6_64_shares_a_budget() {
        let b = Backoff::new(2, Duration::ZERO);
        assert!(b.begin(ip("2001:db8::1")) && b.begin(ip("2001:db8::2")));
        assert!(!b.begin(ip("2001:db8::ffff:1")), "same /64");
        assert!(b.begin(ip("2001:db8:0:1::1")), "a different /64");
    }

    #[test]
    fn maps_stay_bounded_under_a_flood_of_distinct_keys() {
        let b = Backoff::default();
        for i in 0..(MAX_ENTRIES + 50) {
            b.failure(&format!("login-{i}-{}", "x".repeat(500)), ip("1.1.1.1"));
        }
        assert!(b.by_login.lock().unwrap().len() <= MAX_ENTRIES + 1);
        assert!(b
            .by_login
            .lock()
            .unwrap()
            .keys()
            .all(|k| k.len() <= MAX_KEY));
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
