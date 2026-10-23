//! Who is running against which repository, and the cancel handle that ends them.
//!
//! The registry holds a [`Cancel`] per live transport, never a process-group id: only the
//! supervisor thread that owns the child signals its group (while the leader is still an unreaped
//! zombie, so the id cannot have been reused), and it does so when it sees the flag. `delete`
//! closes a repository's slot, cancels what is in it and waits for the transports to unregister
//! before it renames the directory; a transport that arrives after the close is refused.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A cancellation request shared between the registry, the supervisor and the pumps. Setting it
/// is idempotent; the async side awaits [`Cancel::cancelled`], threads poll [`Cancel::is_set`].
#[derive(Clone, Default)]
pub struct Cancel(Arc<CancelInner>);

#[derive(Default)]
struct CancelInner {
    flag: AtomicBool,
    notify: tokio::sync::Notify,
}

impl Cancel {
    pub fn cancel(&self) {
        self.0.flag.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn is_set(&self) -> bool {
        self.0.flag.load(Ordering::SeqCst)
    }

    /// Resolves once cancelled (immediately if it already was).
    pub async fn cancelled(&self) {
        // The `Notified` future is created before the flag is read, so a `cancel` between the two
        // is not lost.
        let n = self.0.notify.notified();
        tokio::pin!(n);
        n.as_mut().enable();
        if self.is_set() {
            return;
        }
        n.await;
    }

    /// Cancels when dropped: held by whatever owns the client side of a transport.
    pub fn on_drop(&self) -> CancelOnDrop {
        CancelOnDrop(self.clone())
    }
}

pub struct CancelOnDrop(Cancel);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Default)]
struct Slot {
    closed: bool,
    live: HashMap<u64, Cancel>,
}

/// Live transports by repository id.
#[derive(Default)]
pub struct Registry {
    slots: Mutex<HashMap<i64, Slot>>,
    idle: Condvar,
    next: AtomicU64,
}

/// A registered transport; unregisters on drop.
pub struct Registration {
    reg: Arc<Registry>,
    repo: i64,
    key: u64,
    pub cancel: Cancel,
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<i64, Slot>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a transport on `repo`. `still_live` runs under the registry lock, after the closed
    /// check, so a repository that `delete` has marked cannot slip a transport in between. `None`
    /// when the slot is closed or the repository is not live.
    pub fn register(
        self: &Arc<Self>,
        repo: i64,
        still_live: impl FnOnce() -> bool,
    ) -> Option<Registration> {
        let mut slots = self.lock();
        if slots.get(&repo).is_some_and(|s| s.closed) || !still_live() {
            return None;
        }
        let key = self.next.fetch_add(1, Ordering::SeqCst);
        let cancel = Cancel::default();
        slots
            .entry(repo)
            .or_default()
            .live
            .insert(key, cancel.clone());
        Some(Registration {
            reg: self.clone(),
            repo,
            key,
            cancel,
        })
    }

    /// Refuse new transports on `repo` and cancel the live ones.
    pub fn close(&self, repo: i64) {
        let mut slots = self.lock();
        let slot = slots.entry(repo).or_default();
        slot.closed = true;
        slot.live.values().for_each(Cancel::cancel);
    }

    /// Allow transports on `repo` again (a delete that did not go through).
    pub fn reopen(&self, repo: i64) {
        let mut slots = self.lock();
        if let Some(s) = slots.get_mut(&repo) {
            s.closed = false;
            if s.live.is_empty() {
                slots.remove(&repo);
            }
        }
    }

    /// Wait up to `limit` for every transport on `repo` to unregister; `false` if some survive.
    pub fn wait_idle(&self, repo: i64, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        let mut slots = self.lock();
        while slots.get(&repo).is_some_and(|s| !s.live.is_empty()) {
            let Some(left) = end.checked_duration_since(Instant::now()) else {
                return false;
            };
            slots = self
                .idle
                .wait_timeout(slots, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }

    /// Drop the (closed) slot of a repository that no longer exists.
    pub fn forget(&self, repo: i64) {
        self.lock().remove(&repo);
    }

    /// Cancel every live transport (shutdown).
    pub fn cancel_all(&self) {
        self.lock()
            .values()
            .flat_map(|s| s.live.values())
            .for_each(Cancel::cancel);
    }

    /// Wait up to `limit` until no transport at all is registered.
    pub fn wait_all_idle(&self, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        let mut slots = self.lock();
        while slots.values().any(|s| !s.live.is_empty()) {
            let Some(left) = end.checked_duration_since(Instant::now()) else {
                return false;
            };
            slots = self
                .idle
                .wait_timeout(slots, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }

    /// How many transports are registered (tests, `/healthz`-style probes).
    pub fn live(&self) -> usize {
        self.lock().values().map(|s| s.live.len()).sum()
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut slots = self.reg.lock();
        if let Some(s) = slots.get_mut(&self.repo) {
            s.live.remove(&self.key);
            if s.live.is_empty() && !s.closed {
                slots.remove(&self.repo);
            }
        }
        self.reg.idle.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closed_slot_refuses_and_cancels() {
        let r = Arc::new(Registry::default());
        let a = r.register(1, || true).expect("open");
        assert!(!a.cancel.is_set());
        r.close(1);
        assert!(a.cancel.is_set(), "close cancels what is live");
        assert!(r.register(1, || true).is_none(), "closed refuses");
        assert!(
            r.register(2, || true).is_some(),
            "other repositories are unaffected"
        );
        assert!(
            !r.wait_idle(1, Duration::from_millis(20)),
            "a live transport keeps it busy"
        );
        drop(a);
        assert!(r.wait_idle(1, Duration::from_millis(20)));
        r.reopen(1);
        assert!(r.register(1, || true).is_some());
    }

    #[test]
    fn the_liveness_check_runs_under_the_lock_and_can_refuse() {
        let r = Arc::new(Registry::default());
        assert!(r.register(1, || false).is_none());
        assert_eq!(r.live(), 0);
    }

    #[test]
    fn wait_idle_wakes_when_the_last_transport_leaves() {
        let r = Arc::new(Registry::default());
        let a = r.register(7, || true).unwrap();
        r.close(7);
        let t = std::thread::spawn({
            let r = r.clone();
            move || r.wait_idle(7, Duration::from_secs(5))
        });
        std::thread::sleep(Duration::from_millis(30));
        drop(a);
        assert!(t.join().unwrap());
    }

    #[test]
    fn shutdown_cancels_everything() {
        let r = Arc::new(Registry::default());
        let a = r.register(1, || true).unwrap();
        let b = r.register(2, || true).unwrap();
        r.cancel_all();
        assert!(a.cancel.is_set() && b.cancel.is_set());
        assert!(!r.wait_all_idle(Duration::from_millis(10)));
        drop((a, b));
        assert!(r.wait_all_idle(Duration::from_millis(10)));
    }

    #[tokio::test]
    async fn cancelled_resolves_after_and_before_the_cancel() {
        let c = Cancel::default();
        let waiter = tokio::spawn({
            let c = c.clone();
            async move { c.cancelled().await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        c.cancel();
        waiter.await.unwrap();
        c.cancelled().await; // already set: returns at once
        let d = Cancel::default();
        drop(d.on_drop());
        assert!(d.is_set());
    }
}
