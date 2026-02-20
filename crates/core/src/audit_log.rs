use chrono::{DateTime, Duration, Utc};

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub operation: AuditOperation,
    pub target: Option<String>,
    pub detail: String,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    max_entries: usize,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl AuditLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    pub fn record(
        &mut self,
        operation: AuditOperation,
        target: Option<String>,
        detail: impl Into<String>,
    ) {
        self.entries.push(AuditEntry {
            operation,
            target,
            detail: detail.into(),
            at: Utc::now(),
        });

        if self.entries.len() > self.max_entries {
            let overflow = self.entries.len() - self.max_entries;
            self.entries.drain(0..overflow);
        }
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
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
}
