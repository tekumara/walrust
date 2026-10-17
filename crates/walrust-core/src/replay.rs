//! Cursor-aware physical replay. The receipt describes the bytes actually
//! restored/applied, not a later listing of mutable remote objects.

use std::path::Path;

use anyhow::{anyhow, bail, Result};
use hadb_changeset::{physical, storage as changesets};
use hadb_storage::StorageBackend;

/// The source of the last applied replay anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayGeneration {
    Snapshot,
    Incremental,
    ExternalBase,
}

/// Strict by default; fork bridging requires an explicit operator policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReplayPolicy {
    #[default]
    Strict,
    AllowForkBridge,
}

/// A receipt for a successfully restored or replayed database.
///
/// `checksum` is the expected `prev_checksum` of the next incremental. For a
/// snapshot/external base it is the database-image checksum, NOT the HADBP
/// envelope checksum. For an incremental it is the HADBP chain checksum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayCursor {
    pub seq: u64,
    pub checksum: u64,
    pub generation: ReplayGeneration,
}

enum VerifiedReplay {
    Snapshot(Vec<u8>),
    Incremental(Vec<u8>, u64),
}

/// Verify and apply the contiguous physical tail from an authoritative cursor.
///
/// Download once, verify the entire discovered batch, then apply those exact
/// bytes. In particular the first incremental must chain to the restored base;
/// missing/overwritten prior objects cannot erase the caller's anchor. A gap,
/// key/header mismatch, corrupt object or fork fails before any page is written
/// under `ReplayPolicy::Strict`. Snapshots consume sequence numbers too: they
/// must chain from the previous receipt, then establish a database-image anchor.
pub async fn pull_incremental_with_cursor(
    storage: &dyn StorageBackend,
    prefix: &str,
    db_name: &str,
    db_path: &Path,
    cursor: ReplayCursor,
    policy: ReplayPolicy,
) -> Result<ReplayCursor> {
    let incrementals = changesets::discover_after(
        storage,
        prefix,
        db_name,
        cursor.seq,
        changesets::ChangesetKind::Physical,
    )
    .await?;
    let mut files: Vec<_> = incrementals.into_iter().map(|file| (file, false)).collect();
    let snapshot_prefix = format!(
        "{}{}/{:04x}/",
        prefix,
        db_name,
        changesets::GENERATION_SNAPSHOT
    );
    let after = changesets::format_key(
        prefix,
        db_name,
        changesets::GENERATION_SNAPSHOT,
        cursor.seq,
        changesets::ChangesetKind::Physical,
    );
    for key in storage.list(&snapshot_prefix, Some(&after)).await? {
        let Some(seq) = key
            .strip_prefix(&snapshot_prefix)
            .and_then(|name| name.strip_suffix(".hadbp"))
            .and_then(|seq| u64::from_str_radix(seq, 16).ok())
        else {
            continue;
        };
        if seq > cursor.seq {
            files.push((
                changesets::DiscoveredChangeset {
                    key,
                    seq,
                    kind: changesets::ChangesetKind::Physical,
                },
                true,
            ));
        }
    }
    files.sort_by_key(|(file, _)| file.seq);
    let mut head = cursor;
    let mut verified = Vec::with_capacity(files.len());
    for (file, snapshot) in files {
        let expected = head
            .seq
            .checked_add(1)
            .ok_or_else(|| anyhow!("replay sequence overflow"))?;
        if policy == ReplayPolicy::Strict && file.seq != expected {
            bail!(
                "non-contiguous changeset for '{db_name}': expected seq {expected}, found {} at {}",
                file.seq,
                file.key
            );
        }
        let data = storage
            .get(&file.key)
            .await?
            .ok_or_else(|| anyhow!("changeset disappeared during replay: {}", file.key))?;
        let changeset =
            physical::decode(&data).map_err(|e| anyhow!("decode changeset {}: {e}", file.key))?;
        if changeset.header.seq != file.seq {
            bail!(
                "changeset key/header seq mismatch at {}: key {}, header {}",
                file.key,
                file.seq,
                changeset.header.seq
            );
        }
        if policy == ReplayPolicy::Strict {
            physical::verify_chain(head.checksum, &changeset).map_err(|e| {
                anyhow!(
                    "changeset checksum chain break for '{db_name}' at {}: {e}",
                    file.key
                )
            })?;
        }
        // Even acknowledged forks apply exactly the decoded/checked bytes and
        // return their actual checksum, not a re-read of the remote head.
        head = if snapshot {
            let (image, result) = crate::ltx::decode_snapshot_image(&data)?;
            verified.push(VerifiedReplay::Snapshot(image));
            ReplayCursor {
                seq: file.seq,
                checksum: result.checksum,
                generation: ReplayGeneration::Snapshot,
            }
        } else {
            verified.push(VerifiedReplay::Incremental(
                data,
                changeset.header.prev_checksum,
            ));
            ReplayCursor {
                seq: file.seq,
                checksum: changeset.checksum,
                generation: ReplayGeneration::Incremental,
            }
        };
    }
    for replay in verified {
        match replay {
            VerifiedReplay::Snapshot(image) => std::fs::write(db_path, image)?,
            VerifiedReplay::Incremental(data, previous_checksum) => {
                crate::ltx::apply_changeset_to_db(&data, db_path, previous_checksum)?;
            }
        }
    }
    Ok(head)
}
