use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
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

    pub fn create_watcher(&self) -> Result<(RecommendedWatcher, Receiver<notify::Result<Event>>)> {
        let (tx, rx) = mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default(),
        )?;

        for folder in &self.watched_folders {
            watcher.watch(folder, RecursiveMode::Recursive)?;
        }

        Ok((watcher, rx))
    }

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
                    match rx.recv_timeout(Duration::from_millis(10)) {
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
        collections::HashMap,
        fs,
        path::PathBuf,
        sync::mpsc,
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

        assert!(events.is_empty());
    }

    #[test]
    fn create_watcher_without_watch_folders_is_ok() {
        let linker = ProjectLinker::default();
        let (_watcher, _rx) = linker
            .create_watcher()
            .expect("watcher creation should work without folders");
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
}
