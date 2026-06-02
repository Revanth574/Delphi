// SPDX-License-Identifier: MIT

//! Async caller-identity resolver for the D-Bus boundary (services-sweep SVC-2,
//! Stage 1b).
//!
//! Stage 1 ([`crate::auth`]) is the pure, bus-free policy core over an
//! *already-resolved* [`CallerIdentity`]. This module is the thin async layer
//! that *produces* that identity from a live D-Bus message, then hands it to the
//! sync policy. It is the boundary entry Codex described as "async because
//! credential resolution is an async D-Bus round-trip".
//!
//! # How a caller is identified
//!
//! The method guard (Stage 2) receives the message [`Header`] and the
//! [`Connection`] via zbus special arguments (`#[zbus(header)]` /
//! `#[zbus(connection)]`) and calls [`CallerResolver::resolve`]:
//!
//! 1. `header.sender()` yields the **unique bus name** (`:1.42`) — assigned by
//!    the bus daemon, unspoofable by a peer, and **never reassigned** for the
//!    life of the daemon. This is the security-critical basis for same-caller
//!    binding (SVC-1-R1-1-01) and is available on *any* bus.
//! 2. uid/pid are resolved via
//!    [`fdo::DBusProxy::get_connection_credentials`] and cached by unique name.
//!    These are only structurally meaningful under the deployed
//!    authenticated-bus model; on the dev session bus they are best-effort.
//!
//! # Graceful degradation (Iron Law #3/#10)
//!
//! Credential resolution can fail (bus error, peer gone). The unique name comes
//! from the message header, *not* the credential call — so on any failure the
//! resolver degrades to a unique-name-only identity (uid/pid `None`) rather than
//! erroring. Same-caller binding still works; only the deployed uid/pid
//! hardening is unavailable, which the policy already treats as "creds unknown".
//!
//! # Cache + invalidation (Codex Q9)
//!
//! Credentials (not decisions) are cached keyed by unique name, with a TTL for
//! defense-in-depth. The authoritative invalidation is the
//! `org.freedesktop.DBus.NameOwnerChanged` signal: when a cached unique name
//! disappears (its connection closed), [`CallerResolver::run_invalidation_watcher`]
//! removes the entry. Because unique names are never reassigned, a successful
//! `get_connection_credentials` for a unique name proves the connection was live
//! and the creds are stable for that name's lifetime — so there is no
//! lookup-to-write owner-change TOCTOU on the unique-name key (the fetch's
//! success is the validation); the watcher is cleanup + defense-in-depth.
//!
//! # Deliberate deviation from Codex Q9 — the insert-time recheck is SKIPPED
//!
//! Codex Q9 prescribed a final ownership/credential recheck on cache insert to
//! close a lookup-to-write TOCTOU. This resolver deliberately SKIPS it, on the
//! argument below — **flagged for the SVC-2 Codex review to ratify or contest**,
//! not silently omitted:
//!
//! The recheck guards against a key's owner changing between the credential
//! lookup and the cache write. D-Bus **unique names are never reassigned** by
//! the daemon — a unique name maps to exactly one connection for the daemon's
//! lifetime. The only event in that window is the connection *dying*, which
//! leaves an *inert* stale entry: no future caller can present that unique name
//! again, so the entry is never matched, and the `NameOwnerChanged` watcher
//! (plus the TTL) drops it. There is no owner-*reassignment*, hence no TOCTOU.
//!
//! **This argument holds only because the cache is keyed by UNIQUE names, never
//! well-known names** (which CAN change owner and would reintroduce the TOCTOU).
//! That keying is an enforced invariant: the sole inserter
//! ([`CallerResolver::resolve`]) derives the key from `header.sender()` (a
//! `UniqueName`), and the sole invalidator (the watcher) uses the signal's
//! `old_owner`/`new_owner` (`UniqueName`s), never the well-known `name` field.
//! [`CredsCache::insert`] additionally refuses any key that is not a unique name
//! (`:`-prefixed), so a well-known name cannot enter even if a future caller
//! path regresses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tracing::{debug, warn};
use zbus::fdo::DBusProxy;
use zbus::message::Header;
use zbus::names::{BusName, UniqueName};
use zbus::Connection;

use crate::auth::CallerIdentity;

/// How long resolved credentials stay cached before re-resolution. Defense-in-
/// depth on top of `NameOwnerChanged` invalidation (the primary mechanism).
const CREDS_TTL: Duration = Duration::from_secs(300);

/// Cached credentials for one unique bus name. Credentials, not decisions
/// (Q9), so a policy change never requires re-resolution.
#[derive(Debug, Clone, Copy)]
struct CachedCreds {
    uid: Option<u32>,
    pid: Option<u32>,
    inserted_at: Instant,
}

/// The credential cache: unique bus name → creds. Kept as a separate, bus-free
/// type so its freshness/invalidation logic is unit-testable without a D-Bus
/// connection.
#[derive(Debug, Default)]
struct CredsCache {
    map: HashMap<String, CachedCreds>,
}

impl CredsCache {
    /// Return the cached creds for `unique` if present and not older than
    /// [`CREDS_TTL`] at `now`. `now` is a parameter so the TTL boundary is
    /// deterministically testable.
    fn get_fresh(&self, unique: &str, now: Instant) -> Option<CachedCreds> {
        self.map
            .get(unique)
            .filter(|c| now.saturating_duration_since(c.inserted_at) <= CREDS_TTL)
            .copied()
    }

    /// Insert resolved creds for a UNIQUE bus name. The cache is keyed by unique
    /// names ONLY — the enforced invariant the insert-time-recheck skip depends
    /// on (see module docs, "Deliberate deviation from Codex Q9"). A non-unique
    /// (well-known) name is refused as defense-in-depth, so the TOCTOU the skip
    /// waves away cannot be reintroduced by a future caller-path regression.
    fn insert(&mut self, unique: String, creds: CachedCreds) {
        if !unique.starts_with(':') {
            warn!(
                key = %unique,
                "refusing to cache a non-unique (well-known?) bus name — would break \
                 the insert-recheck-skip invariant (caller_resolver Q9 deviation)"
            );
            return;
        }
        self.map.insert(unique, creds);
    }

    /// Drop the cached entry for `unique` (called on `NameOwnerChanged`).
    fn invalidate(&mut self, unique: &str) {
        self.map.remove(unique);
    }
}

/// Resolves and caches the identity of D-Bus callers. Shared (`Arc`) across all
/// method invocations and the invalidation watcher.
#[derive(Debug, Default)]
pub struct CallerResolver {
    cache: Mutex<CredsCache>,
}

impl CallerResolver {
    /// Create an empty resolver.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::caller_resolver::CallerResolver;
    ///
    /// let _resolver = CallerResolver::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock the cache, recovering from a poisoned mutex (a creds cache is a
    /// plain map; a panic mid-op leaves it consistent, so recovery is sound and
    /// avoids a forbidden `.unwrap()`/`.expect()`).
    fn lock_cache(&self) -> std::sync::MutexGuard<'_, CredsCache> {
        self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Resolve the caller of the current method from its message `header`.
    ///
    /// Always returns a [`CallerIdentity`]: the unique bus name from
    /// `header.sender()` is the security-critical field; uid/pid are resolved
    /// and cached best-effort, degrading to `None` on any bus error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use delphi_services::caller_resolver::CallerResolver;
    /// # use zbus::message::Header;
    /// # use zbus::Connection;
    /// # async fn demo(resolver: &CallerResolver, header: &Header<'_>, conn: &Connection) {
    /// let caller = resolver.resolve(header, conn).await;
    /// println!("caller {} uid={:?}", caller.unique_name, caller.uid);
    /// # }
    /// ```
    pub async fn resolve(&self, header: &Header<'_>, conn: &Connection) -> CallerIdentity {
        let Some(sender) = header.sender() else {
            warn!("D-Bus message has no sender; treating caller as anonymous");
            return CallerIdentity::from_unique_name(String::new());
        };
        let unique = sender.as_str().to_string();

        if let Some(creds) = self.lock_cache().get_fresh(&unique, Instant::now()) {
            return CallerIdentity {
                unique_name: unique,
                uid: creds.uid,
                pid: creds.pid,
            };
        }

        match resolve_credentials(conn, sender).await {
            Ok((uid, pid)) => {
                self.lock_cache().insert(
                    unique.clone(),
                    CachedCreds {
                        uid,
                        pid,
                        inserted_at: Instant::now(),
                    },
                );
                CallerIdentity {
                    unique_name: unique,
                    uid,
                    pid,
                }
            }
            Err(e) => {
                debug!(
                    error = %e,
                    caller = %unique,
                    "credential resolution failed; degrading to unique-name-only identity"
                );
                CallerIdentity::from_unique_name(unique)
            }
        }
    }

    /// Run the `NameOwnerChanged` invalidation watcher to completion (until the
    /// signal stream ends). Spawn this once from the daemon that owns `conn`; it
    /// drops cached creds for any unique name whose owner changes (i.e. whose
    /// connection closes), keeping the cache from serving entries for dead
    /// connections.
    ///
    /// # Errors
    ///
    /// Returns the zbus error if the `DBusProxy` or the signal subscription
    /// cannot be established.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use delphi_services::caller_resolver::CallerResolver;
    /// # use zbus::Connection;
    /// # async fn demo(conn: Connection) -> zbus::Result<()> {
    /// let resolver = Arc::new(CallerResolver::new());
    /// tokio::spawn(resolver.clone().run_invalidation_watcher(conn));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run_invalidation_watcher(self: Arc<Self>, conn: Connection) -> zbus::Result<()> {
        let proxy = DBusProxy::new(&conn).await?;
        let mut stream = proxy.receive_name_owner_changed().await?;
        while let Some(signal) = stream.next().await {
            let Ok(args) = signal.args() else { continue };
            // A unique name appearing as old/new owner: drop any cached creds for
            // it. (Unique names are never reassigned, so the disappearing
            // old_owner is the meaningful case — cleanup of a dead connection.)
            if let Some(old) = args.old_owner().as_ref() {
                self.lock_cache().invalidate(old.as_str());
            }
            if let Some(new) = args.new_owner().as_ref() {
                self.lock_cache().invalidate(new.as_str());
            }
        }
        Ok(())
    }
}

/// Resolve uid/pid for a unique bus name via `org.freedesktop.DBus`. A
/// successful fetch proves the connection was live; since unique names are
/// never reassigned, the creds are stable for the name's lifetime.
async fn resolve_credentials(
    conn: &Connection,
    sender: &UniqueName<'_>,
) -> zbus::Result<(Option<u32>, Option<u32>)> {
    let proxy = DBusProxy::new(conn).await?;
    let creds = proxy
        .get_connection_credentials(BusName::Unique(sender.clone()))
        .await?;
    Ok((creds.unix_user_id(), creds.process_id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(uid: u32) -> CachedCreds {
        CachedCreds {
            uid: Some(uid),
            pid: Some(1000),
            inserted_at: Instant::now(),
        }
    }

    #[test]
    fn cache_hit_within_ttl() {
        let mut cache = CredsCache::default();
        cache.insert(":1.10".to_string(), creds(501));
        let got = cache.get_fresh(":1.10", Instant::now());
        assert_eq!(got.and_then(|c| c.uid), Some(501));
    }

    #[test]
    fn cache_miss_for_unknown_name() {
        let cache = CredsCache::default();
        assert!(cache.get_fresh(":1.99", Instant::now()).is_none());
    }

    #[test]
    fn cache_entry_expires_after_ttl() {
        let mut cache = CredsCache::default();
        cache.insert(":1.10".to_string(), creds(501));
        // A lookup past the TTL boundary misses (defense-in-depth eviction).
        let later = Instant::now() + CREDS_TTL + Duration::from_secs(1);
        assert!(cache.get_fresh(":1.10", later).is_none());
    }

    #[test]
    fn insert_refuses_well_known_name() {
        // Decision 2(b): the unique-names-only invariant is enforced — a
        // well-known name (no ':' prefix) is refused, so it can never enter the
        // cache and reintroduce the owner-change TOCTOU the Q9 recheck-skip
        // relies on. A genuine unique name is accepted.
        let mut cache = CredsCache::default();
        cache.insert("org.delphi.Shell".to_string(), creds(1000));
        assert!(
            cache.get_fresh("org.delphi.Shell", Instant::now()).is_none(),
            "a well-known name must never be cached (Q9 deviation invariant)"
        );
        cache.insert(":1.7".to_string(), creds(1000));
        assert!(cache.get_fresh(":1.7", Instant::now()).is_some());
    }

    #[test]
    fn invalidate_drops_entry() {
        // The NameOwnerChanged path: once a unique name's connection closes, its
        // cached creds are dropped so a future lookup re-resolves.
        let mut cache = CredsCache::default();
        cache.insert(":1.10".to_string(), creds(501));
        assert!(cache.get_fresh(":1.10", Instant::now()).is_some());
        cache.invalidate(":1.10");
        assert!(cache.get_fresh(":1.10", Instant::now()).is_none());
    }

    #[test]
    fn resolver_locks_and_invalidates_through_public_surface() {
        // Exercise the resolver's own cache plumbing (lock recovery + invalidate)
        // without a bus.
        let resolver = CallerResolver::new();
        resolver
            .lock_cache()
            .insert(":1.5".to_string(), creds(0));
        assert!(resolver.lock_cache().get_fresh(":1.5", Instant::now()).is_some());
        resolver.lock_cache().invalidate(":1.5");
        assert!(resolver.lock_cache().get_fresh(":1.5", Instant::now()).is_none());
    }
}
