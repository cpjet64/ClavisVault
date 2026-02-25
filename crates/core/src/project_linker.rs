use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};

use crate::{agents_updater::AgentsUpdater, safe_file::SafeFileOps, types::KeyEntry};

#[derive(Debug, Clone)]
pub struct ProjectLinker {
    explicit_files: HashSet<PathBuf>,
    watched_folders: HashSet<PathBuf>,
    debounce: Duration,
}

impl Default for ProjectLinker {
    fn default() -> Self {
        Self {
            explicit_files: HashSet::new(),
            watched_folders: HashSet::new(),
            debounce: Duration::from_millis(800),
        }
    }
}

impl ProjectLinker {
    pub fn add_file(&mut self, file: impl Into<PathBuf>) {
        self.explicit_files.insert(file.into());
    }

    pub fn add_watch_folder(&mut self, folder: impl Into<PathBuf>) {
        self.watched_folders.insert(folder.into());
    }

    pub fn watched_folders(&self) -> Vec<PathBuf> {
        let mut folders: Vec<_> = self.watched_folders.iter().cloned().collect();
        folders.sort();
        folders
    }

    pub fn linked_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<_> = self.explicit_files.iter().cloned().collect();
        files.sort();
        files
    }

    pub fn discover_agents_files(&self) -> Result<Vec<PathBuf>> {
        let mut discovered = HashSet::new();
        for folder in &self.watched_folders {
            discover_recursive(folder, &mut discovered)?;
        }

        let mut sorted: Vec<_> = discovered.into_iter().collect();
        sorted.sort();
        Ok(sorted)
    }

    pub fn auto_add_agents_from_watched_folders(&mut self) -> Result<usize> {
        let before = self.explicit_files.len();
        for path in self.discover_agents_files()? {
            self.explicit_files.insert(path);
        }
        Ok(self.explicit_files.len().saturating_sub(before))
    }

    pub fn sync_linked_files<T: SafeFileOps>(
        &mut self,
        updater: &AgentsUpdater<T>,
        keys: &HashMap<String, KeyEntry>,
        now: DateTime<Utc>,
    ) -> Result<usize> {
        self.auto_add_agents_from_watched_folders()?;

        let mut updated_count = 0;
        for path in self.linked_files() {
            updater
                .update_agents_file(&path, keys, now)
                .with_context(|| format!("failed updating linked file {}", path.display()))?;
            updated_count += 1;
        }

        Ok(updated_count)
    }

    #[cfg_attr(test, inline(never))]
    pub fn create_watcher(&self) -> Result<(RecommendedWatcher, Receiver<notify::Result<Event>>)> {
        let (tx, rx) = mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Self::watcher_config(),
        )?;

        for folder in &self.watched_folders {
            if !folder.is_dir() {
                return Err(anyhow!("{} is not a directory", folder.display()));
            }
            watcher.watch(folder, RecursiveMode::Recursive)?;
        }

        Ok((watcher, rx))
    }

    fn watcher_config() -> Config {
        Config::default()
    }

    #[cfg_attr(test, inline(never))]
    pub fn collect_events(
        &self,
        rx: &Receiver<notify::Result<Event>>,
        wait: Duration,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        match rx.recv_timeout(wait) {
            Ok(Ok(event)) => {
                events.push(event);
                let debounce_until = Instant::now() + self.debounce;
                while Instant::now() < debounce_until {
                    let remaining = debounce_until.saturating_duration_since(Instant::now());
                    let poll_timeout = remaining.min(Duration::from_millis(10));
                    match rx.recv_timeout(poll_timeout) {
                        Ok(Ok(extra)) => events.push(extra),
                        Ok(Err(err)) => return Err(err.into()),
                        Err(_) => break,
                    }
                }
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {}
        }

        Ok(events)
    }
}

#[cfg_attr(test, inline(never))]
fn discover_recursive(root: &Path, out: &mut HashSet<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }

    for entry in
        fs::read_dir(root).with_context(|| format!("read_dir failed for {}", root.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            discover_recursive(&path, out)?;
            continue;
        }

        let is_agents = path
            .file_name()
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case("agents.md"))
            .unwrap_or(false);

        if is_agents {
            out.insert(path);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        fs,
        path::PathBuf,
        sync::mpsc,
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use chrono::Utc;

    use super::*;
    use crate::{agents_updater::AgentsUpdater, safe_file::LocalSafeFileOps, types::KeyEntry};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("clavisvault-core-{name}-{nanos}"));
        fs::create_dir_all(&path).expect("temp dir creation should work");
        path
    }

    fn key_map() -> HashMap<String, KeyEntry> {
        let mut keys = HashMap::new();
        keys.insert(
            "TEST_KEY".to_string(),
            KeyEntry {
                name: "TEST_KEY".to_string(),
                description: "test key".to_string(),
                secret: None,
                tags: vec!["integration".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(Utc::now()),
                owner: Some("integration".to_string()),
            },
        );
        keys
    }

    #[test]
    fn discovers_and_auto_adds_agents_files() {
        let root = temp_dir("project-linker-discover");
        let nested = root.join("a").join("b");
        fs::create_dir_all(&nested).expect("nested dir creation should work");
        fs::write(root.join("agents.md"), "# root").expect("write root agents should work");
        fs::write(nested.join("agents.md"), "# nested").expect("write nested agents should work");

        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(&root);

        let added = linker
            .auto_add_agents_from_watched_folders()
            .expect("auto add should work");
        assert_eq!(added, 2);
        assert_eq!(linker.linked_files().len(), 2);
    }

    #[test]
    fn add_file_and_watch_folder_accessors_are_sorted() {
        let root = temp_dir("project-linker-accessors");
        let a = root.join("a").join("agents.md");
        let b = root.join("b").join("agents.md");
        fs::create_dir_all(a.parent().expect("path has parent")).expect("create dir should work");
        fs::create_dir_all(b.parent().expect("path has parent")).expect("create dir should work");

        let mut linker = ProjectLinker::default();
        linker.add_file(&b);
        linker.add_file(&a);
        linker.add_watch_folder(root.join("z"));
        linker.add_watch_folder(root.join("m"));

        let files = linker.linked_files();
        assert_eq!(files.len(), 2);
        assert!(files[0] <= files[1]);

        let watched = linker.watched_folders();
        assert_eq!(watched.len(), 2);
        assert!(watched[0] <= watched[1]);
    }

    #[test]
    fn discover_handles_missing_watch_folder() {
        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(temp_dir("project-linker-missing").join("does-not-exist"));
        let files = linker
            .discover_agents_files()
            .expect("discover should tolerate missing folder");
        assert!(files.is_empty());
    }

    #[test]
    fn discover_agents_files_is_empty_for_no_watch_folders() {
        let linker = ProjectLinker::default();
        let files = linker
            .discover_agents_files()
            .expect("discover should return empty when no folders are configured");
        assert!(files.is_empty());
    }

    #[test]
    fn sync_updates_all_discovered_files() {
        let root = temp_dir("project-linker-sync");
        let nested = root.join("sub");
        fs::create_dir_all(&nested).expect("nested dir creation should work");
        fs::write(root.join("agents.md"), "# root").expect("write root agents should work");
        fs::write(nested.join("agents.md"), "# nested").expect("write nested agents should work");

        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(&root);

        let updater = AgentsUpdater::new(LocalSafeFileOps::default());
        let count = linker
            .sync_linked_files(&updater, &key_map(), Utc::now())
            .expect("sync should work");

        assert_eq!(count, 2);

        for file in linker.linked_files() {
            let content = fs::read_to_string(file).expect("read synced file should work");
            assert!(content.contains("TEST_KEY"));
        }
    }

    #[test]
    fn watcher_creation_and_collect_timeout() {
        let root = temp_dir("project-linker-watch");
        fs::create_dir_all(&root).expect("watch root creation should work");

        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(&root);

        let (_watcher, rx) = linker
            .create_watcher()
            .expect("watcher creation should work");
        let events = linker
            .collect_events(&rx, Duration::from_millis(50))
            .expect("event collection should work");
        // Some platforms (notably macOS) can emit startup watcher events immediately.
        assert!(
            events
                .iter()
                .all(|event| event.paths.iter().all(|path| path.starts_with(&root)))
        );
    }

    #[test]
    fn create_watcher_without_watch_folders_is_ok() {
        let linker = ProjectLinker::default();
        let (_watcher, _rx) = linker
            .create_watcher()
            .expect("watcher creation should work without folders");
    }

    #[test]
    fn project_linker_builds_watcher_config_via_default_factory() {
        let _ = ProjectLinker::watcher_config();
    }

    #[test]
    fn collect_events_handles_notify_error() {
        let linker = ProjectLinker::default();
        let (tx, rx) = mpsc::channel();
        tx.send(Err(notify::Error::generic("forced notify failure")))
            .expect("send should work");

        let err = linker
            .collect_events(&rx, Duration::from_millis(50))
            .expect_err("collect should fail for notify error");
        assert!(err.to_string().contains("forced notify failure"));
    }

    #[test]
    fn collect_events_propagates_followup_notify_error() {
        let linker = ProjectLinker::default();
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(notify::Event::default()))
            .expect("send first event should work");
        tx.send(Err(notify::Error::generic(
            "forced follow-up notify failure",
        )))
        .expect("send follow-up error should work");

        let err = linker
            .collect_events(&rx, Duration::from_millis(50))
            .expect_err("collect should fail for follow-up notify error");
        assert!(err.to_string().contains("forced follow-up notify failure"));
    }

    #[test]
    fn watcher_collects_real_fs_event() {
        let root = temp_dir("project-linker-watch-events");
        fs::create_dir_all(&root).expect("watch root creation should work");
        let watched_file = root.join("agents.md");

        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(&root);

        let (_watcher, rx) = linker
            .create_watcher()
            .expect("watcher creation should work");
        fs::write(&watched_file, "# update").expect("write watched file should work");

        let events = linker
            .collect_events(&rx, Duration::from_secs(2))
            .expect("event collection should work");

        assert!(!events.is_empty(), "expected at least one watcher event");
    }

    #[test]
    fn collect_events_returns_empty_on_timeout() {
        let linker = ProjectLinker::default();
        let (_tx, rx) = mpsc::channel();

        let events = linker
            .collect_events(&rx, Duration::from_millis(25))
            .expect("timeout path should return Ok(empty)");
        assert!(events.is_empty());
    }

    #[test]
    fn discover_agents_files_collects_sorted_results() {
        let root = temp_dir("project-linker-discover-test");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("nested dir creation should work");
        fs::write(root.join("agents.md"), "# root").expect("write root agents should work");
        fs::write(nested.join("agents.md"), "# nested").expect("write nested agents should work");

        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(&root);

        let files = linker
            .discover_agents_files()
            .expect("discover should collect agents files");

        assert_eq!(files.len(), 2);
        assert!(files[0] <= files[1]);
    }

    #[test]
    fn discover_agents_files_errors_when_watch_folder_is_file() {
        let root = temp_dir("project-linker-discover-file-root");
        let file_root = root.join("not-a-directory.txt");
        fs::write(&file_root, "not a folder").expect("seed file should work");
        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(&file_root);

        let err = linker
            .discover_agents_files()
            .expect_err("discovering through a file should fail");
        assert!(err.to_string().contains("read_dir failed"));
    }

    #[test]
    fn discover_recursive_descends_nested_directories_and_collects_agents_files() {
        let root = temp_dir("project-linker-discovery-nested");
        let nested = root.join("nested");
        let deep = nested.join("deeper");
        fs::create_dir_all(&deep).expect("nested dir creation should work");
        fs::write(root.join("agents.md"), "# root").expect("root agents file should work");
        fs::write(deep.join("agents.md"), "# deep").expect("deep agents file should work");

        let mut discovered = std::collections::HashSet::new();
        discover_recursive(&root, &mut discovered).expect("nested discovery should recurse");

        let mut discovered: Vec<_> = discovered.into_iter().collect();
        discovered.sort();
        assert_eq!(discovered.len(), 2);
        assert_eq!(
            discovered[0].file_name().expect("has filename"),
            "agents.md"
        );
        assert_eq!(
            discovered[1].file_name().expect("has filename"),
            "agents.md"
        );
    }

    #[test]
    fn create_watcher_with_invalid_target_fails_to_watch() {
        let root = temp_dir("project-linker-bad-watcher-target");
        let target = root.join("not-a-folder");
        fs::write(&target, "not a dir").expect("seed invalid watcher target should work");

        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(&target);

        let err = linker
            .create_watcher()
            .expect_err("watching a file should fail");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn create_watcher_with_multiple_valid_targets_is_ok() {
        let mut linker = ProjectLinker::default();
        let mut watched_folders = HashSet::new();

        let first = temp_dir("project-linker-multiple-watchers-first");
        let second = temp_dir("project-linker-multiple-watchers-second");
        fs::create_dir_all(&first).expect("first watch folder should exist");
        fs::create_dir_all(&second).expect("second watch folder should exist");
        watched_folders.insert(first);
        watched_folders.insert(second);

        linker.watched_folders = watched_folders;

        let (_watcher, _rx) = linker
            .create_watcher()
            .expect("watcher creation should support multiple folders");
    }

    #[test]
    fn collect_events_collects_first_event_without_debounce_window() {
        let linker = ProjectLinker {
            debounce: Duration::from_millis(0),
            ..ProjectLinker::default()
        };

        let (tx, rx) = mpsc::channel();
        tx.send(Ok(notify::Event::default()))
            .expect("send first event should work");

        let events = linker
            .collect_events(&rx, Duration::from_millis(50))
            .expect("collect should return first event");

        assert_eq!(events.len(), 1);
    }

    #[test]
    fn collect_events_collects_followup_events_during_debounce_window() {
        let linker = ProjectLinker {
            debounce: Duration::from_millis(200),
            ..ProjectLinker::default()
        };
        let (tx, rx) = mpsc::channel();

        tx.send(Ok(notify::Event::default()))
            .expect("send first event should work");
        tx.send(Ok(notify::Event::default()))
            .expect("send second event should work");

        let events = linker
            .collect_events(&rx, Duration::from_millis(100))
            .expect("collect should process debounce follow-up events");
        assert!(events.len() >= 2);
    }

    #[test]
    fn collect_events_stops_on_debounce_timeout_after_first_event() {
        let linker = ProjectLinker {
            debounce: Duration::from_millis(100),
            ..ProjectLinker::default()
        };
        let (tx, rx) = mpsc::channel();

        tx.send(Ok(notify::Event::default()))
            .expect("send first event should work");

        let events = linker
            .collect_events(&rx, Duration::from_millis(100))
            .expect("collect should stop on timeout");
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn collect_events_disregards_events_arriving_after_debounce_window() {
        let linker = ProjectLinker {
            debounce: Duration::from_millis(25),
            ..ProjectLinker::default()
        };
        let (tx, rx) = mpsc::channel();

        tx.send(Ok(notify::Event::default()))
            .expect("send first event should work");
        let tx = std::sync::Arc::new(tx);
        let delayed_tx = tx.clone();
        let handle = std::thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            delayed_tx
                .send(Ok(notify::Event::default()))
                .expect("send late event should work");
        });

        let events = linker
            .collect_events(&rx, Duration::from_millis(50))
            .expect("collect should drop late events outside debounce");
        handle.join().expect("delayed sender should complete");
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn discover_recursive_skips_non_agents_files_and_reports_dir_read_errors() {
        let root = temp_dir("project-linker-discovery-edge-cases");
        fs::create_dir_all(&root).expect("root creation should work");
        let file = root.join("notes.txt");
        fs::write(&file, "notes").expect("notes write should work");

        let mut discovered = std::collections::HashSet::new();
        discover_recursive(&root, &mut discovered).expect("discovery should skip non-agent files");
        assert!(discovered.is_empty());

        let regular_file = root.join("regular.txt");
        fs::write(&regular_file, "leaf").expect("regular file write should work");
        let mut discovered_file_root = std::collections::HashSet::new();
        discover_recursive(&regular_file, &mut discovered_file_root)
            .expect_err("read_dir against non-directory should fail");
    }

    #[test]
    fn create_watcher_accepts_directory_watch_roots() {
        let root = temp_dir("project-linker-watch-success");
        let folder = root.join("watched");
        fs::create_dir_all(&folder).expect("folder creation should work");
        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(&folder);

        let (_watcher, rx) = linker
            .create_watcher()
            .expect("watcher should be created for directory");
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
    }

    #[test]
    fn discover_recursive_matches_agents_file_case_insensitively() {
        let root = temp_dir("project-linker-discovery-case");
        let upper = root.join("AGENTS.MD");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("nested dir creation should work");
        fs::write(&upper, "upper").expect("write upper file");
        fs::write(nested.join("agents.md"), "nested").expect("write nested file");

        let mut discovered = std::collections::HashSet::new();
        discover_recursive(&root, &mut discovered)
            .expect("discovery should traverse case-insensitive name");

        assert_eq!(discovered.len(), 2);
        assert!(discovered.contains(&upper));
        assert!(discovered.contains(&nested.join("agents.md")));
    }

    #[test]
    fn create_watcher_errors_when_watch_folder_is_not_directory() {
        let root = temp_dir("project-linker-watch-file-root");
        let file_root = root.join("not-a-folder.txt");
        fs::write(&file_root, "not-a-folder").expect("seed file should work");

        let mut linker = ProjectLinker::default();
        linker.add_watch_folder(&file_root);

        let err = linker
            .create_watcher()
            .expect_err("watcher should reject file watch roots");
        assert!(err.to_string().contains("is not a directory"));
    }

    #[test]
    fn discover_recursive_returns_ok_when_root_missing() {
        let missing_root = temp_dir("project-linker-missing-root");
        let _ = fs::remove_dir_all(&missing_root);
        let mut discovered = std::collections::HashSet::new();

        discover_recursive(&missing_root, &mut discovered).expect("missing root should be a no-op");
        assert!(discovered.is_empty());
    }

    #[test]
    fn discover_recursive_reports_read_dir_errors_for_non_directory_roots() {
        let root = temp_dir("project-linker-read-dir-error");
        let file_root = root.join("not-a-directory.txt");
        fs::write(&file_root, "not-a-directory").expect("seed file should work");

        let mut discovered = std::collections::HashSet::new();
        let err = discover_recursive(&file_root, &mut discovered)
            .expect_err("calling discover on a file should surface read_dir failure");
        assert!(err.to_string().contains("read_dir failed for"));
    }
}
