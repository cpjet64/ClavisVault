use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOperation {
    Unlock,
    Lock,
    Copy,
    Push,
    FileUpdate,
    AutoLock,
    BiometricUnlock,
    FailedUnlock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub operation: AuditOperation,
    pub target: Option<String>,
    pub detail: String,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainEntry {
    pub index: u64,
    pub operation: String,
    pub target: Option<String>,
    pub detail: String,
    pub at: DateTime<Utc>,
    pub prev_hash_hex: String,
    pub hash_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub index: u64,
    pub at: DateTime<Utc>,
    pub hash_hex: String,
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLedger {
    pub entries: Vec<AuditChainEntry>,
    pub checkpoints: Vec<AuditCheckpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditIntegrityStatus {
    Valid,
    Invalid { index: u64, reason: String },
}

#[derive(Clone, Debug)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    ledger: AuditLedger,
    max_entries: usize,
    max_age_days: i64,
    checkpoint_every: usize,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new_with_retention(10_000, 90)
    }
}

impl AuditLog {
    pub fn new_with_retention(max_entries: usize, max_age_days: i64) -> Self {
        Self {
            entries: Vec::new(),
            ledger: AuditLedger::default(),
            max_entries,
            max_age_days,
            checkpoint_every: 128,
        }
    }

    pub fn new(max_entries: usize) -> Self {
        Self::new_with_retention(max_entries, 90)
    }

    pub fn record(
        &mut self,
        operation: AuditOperation,
        target: Option<String>,
        detail: impl Into<String>,
    ) {
        let detail = detail.into();
        let now = Utc::now();
        self.record_with_timestamp(operation, target, detail, now);
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn ledger(&self) -> &AuditLedger {
        &self.ledger
    }

    pub fn verify_integrity(&self) -> AuditIntegrityStatus {
        verify_ledger_integrity(&self.ledger)
    }

    fn record_with_timestamp(
        &mut self,
        operation: AuditOperation,
        target: Option<String>,
        detail: String,
        now: DateTime<Utc>,
    ) {
        self.entries.push(AuditEntry {
            operation: operation.clone(),
            target: target.clone(),
            detail: detail.clone(),
            at: now,
        });

        let index = self.ledger.entries.len() as u64;
        let prev_hash_hex = self
            .ledger
            .entries
            .last()
            .map(|entry| entry.hash_hex.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let hash_hex = chain_hash(
            index,
            now,
            &operation,
            target.as_deref(),
            &detail,
            &prev_hash_hex,
        );
        self.ledger.entries.push(AuditChainEntry {
            index,
            operation: format!("{operation:?}"),
            target,
            detail,
            at: now,
            prev_hash_hex: prev_hash_hex.clone(),
            hash_hex: hash_hex.clone(),
        });

        if self
            .ledger
            .entries
            .len()
            .is_multiple_of(self.checkpoint_every)
        {
            self.ledger.checkpoints.push(AuditCheckpoint {
                index,
                at: now,
                hash_hex,
                signature: None,
            });
        }

        self.prune_for_retention(now);
    }

    fn prune_for_retention(&mut self, now: DateTime<Utc>) {
        if self.entries.len() > self.max_entries {
            let overflow = self.entries.len() - self.max_entries;
            if overflow > 0 {
                self.entries.drain(0..overflow);
                let ledger_overflow = self.ledger.entries.len().saturating_sub(self.max_entries);
                if ledger_overflow > 0 {
                    self.ledger.entries.drain(0..ledger_overflow);
                }
            }
        }

        if self.max_age_days > 0 {
            let cutoff = now - Duration::days(self.max_age_days);
            self.entries.retain(|entry| entry.at >= cutoff);
            self.ledger.entries.retain(|entry| entry.at >= cutoff);
            self.ledger
                .checkpoints
                .retain(|checkpoint| checkpoint.at >= cutoff);
        }

        if let Some(first_entry) = self.ledger.entries.first() {
            self.ledger
                .checkpoints
                .retain(|checkpoint| checkpoint.index >= first_entry.index);
        }
    }
}

pub fn verify_ledger_integrity(ledger: &AuditLedger) -> AuditIntegrityStatus {
    let mut previous = "0".repeat(64);
    for (position, entry) in ledger.entries.iter().enumerate() {
        let recomputed = chain_hash(
            entry.index,
            entry.at,
            match entry.operation.as_str() {
                "Unlock" => &AuditOperation::Unlock,
                "Lock" => &AuditOperation::Lock,
                "Copy" => &AuditOperation::Copy,
                "Push" => &AuditOperation::Push,
                "FileUpdate" => &AuditOperation::FileUpdate,
                "AutoLock" => &AuditOperation::AutoLock,
                "BiometricUnlock" => &AuditOperation::BiometricUnlock,
                "FailedUnlock" => &AuditOperation::FailedUnlock,
                _ => {
                    return AuditIntegrityStatus::Invalid {
                        index: entry.index,
                        reason: "unknown operation variant in chain".to_string(),
                    };
                }
            },
            entry.target.as_deref(),
            &entry.detail,
            &entry.prev_hash_hex,
        );

        if position > 0 && entry.prev_hash_hex != previous {
            return AuditIntegrityStatus::Invalid {
                index: entry.index,
                reason: "previous hash link mismatch".to_string(),
            };
        }
        if entry.hash_hex != recomputed {
            return AuditIntegrityStatus::Invalid {
                index: entry.index,
                reason: "entry hash mismatch".to_string(),
            };
        }
        previous = entry.hash_hex.clone();
    }
    AuditIntegrityStatus::Valid
}

fn chain_hash(
    index: u64,
    at: DateTime<Utc>,
    operation: &AuditOperation,
    target: Option<&str>,
    detail: &str,
    prev_hash_hex: &str,
) -> String {
    let line = format!(
        "{}|{}|{:?}|{}|{}|{}",
        index,
        at.to_rfc3339(),
        operation,
        target.unwrap_or(""),
        detail,
        prev_hash_hex
    );
    let digest = Sha256::digest(line.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[derive(Clone, Debug)]
pub struct IdleLockTimer {
    timeout: Duration,
    last_activity: DateTime<Utc>,
}

impl IdleLockTimer {
    pub fn new(timeout: Duration, now: DateTime<Utc>) -> Self {
        Self {
            timeout,
            last_activity: now,
        }
    }

    pub fn touch(&mut self, now: DateTime<Utc>) {
        self.last_activity = now;
    }

    pub fn should_lock(&self, now: DateTime<Utc>) -> bool {
        now - self.last_activity >= self.timeout
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_keeps_max_entries() {
        let mut log = AuditLog::new(3);
        log.record(AuditOperation::Unlock, None, "unlock");
        log.record(AuditOperation::Copy, Some("KEY".to_string()), "copy");
        log.record(AuditOperation::Push, None, "push");
        log.record(AuditOperation::Lock, None, "lock");

        assert_eq!(log.entries().len(), 3);
        assert_eq!(log.entries()[0].operation, AuditOperation::Copy);
        assert_eq!(log.ledger().entries.len(), 3);
    }

    #[test]
    fn audit_log_prunes_entries_by_age() {
        let mut log = AuditLog::new_with_retention(10, 1);
        let now = Utc::now();
        let recent = now - Duration::days(0);
        let stale = now - Duration::days(2);
        log.record_with_timestamp(
            AuditOperation::Unlock,
            Some("K1".to_string()),
            "stale".to_string(),
            stale,
        );
        log.record_with_timestamp(
            AuditOperation::Copy,
            Some("K2".to_string()),
            "recent".to_string(),
            recent,
        );
        log.record(AuditOperation::Push, None, "fresh");

        assert_eq!(log.entries().len(), 2);
        assert_eq!(log.entries()[0].target.as_deref(), Some("K2"));
        assert_eq!(log.ledger().entries[0].target.as_deref(), Some("K2"));
        assert_eq!(log.ledger().entries.len(), 2);
        assert_eq!(log.verify_integrity(), AuditIntegrityStatus::Valid);
    }

    #[test]
    fn idle_lock_timer_triggers_after_timeout() {
        let now = Utc::now();
        let mut timer = IdleLockTimer::new(Duration::minutes(10), now);
        assert!(!timer.should_lock(now + Duration::minutes(5)));
        assert!(timer.should_lock(now + Duration::minutes(10)));

        timer.touch(now + Duration::minutes(10));
        assert!(!timer.should_lock(now + Duration::minutes(15)));
    }

    #[test]
    fn default_and_timeout_accessors_work() {
        let log = AuditLog::default();
        assert!(log.entries().is_empty());

        let now = Utc::now();
        let timer = IdleLockTimer::new(Duration::minutes(7), now);
        assert_eq!(timer.timeout(), Duration::minutes(7));
    }

    #[test]
    fn record_preserves_operation_target_and_detail() {
        let mut log = AuditLog::new(10);
        log.record(
            AuditOperation::FileUpdate,
            Some("agents.md".to_string()),
            "updated managed section",
        );

        let entry = &log.entries()[0];
        assert_eq!(entry.operation, AuditOperation::FileUpdate);
        assert_eq!(entry.target.as_deref(), Some("agents.md"));
        assert_eq!(entry.detail, "updated managed section");
        assert_eq!(log.verify_integrity(), AuditIntegrityStatus::Valid);
    }
}
