use log::warn;
use std::{
    fmt,
    fs::remove_file,
    path::{Path, PathBuf},
};

/// File on this path will be removed on `drop()`.
pub struct AutoRemoveFile<'a> {
    path: &'a Path,
    auto_remove: bool,
}

impl AutoRemoveFile<'_> {
    pub fn set_auto_remove(&mut self, enable: bool) {
        self.auto_remove = enable;
    }
}

impl<'a> From<&'a Path> for AutoRemoveFile<'a> {
    fn from(path: &'a Path) -> Self {
        AutoRemoveFile {
            path,
            auto_remove: false,
        }
    }
}

impl<'a> From<&'a PathBuf> for AutoRemoveFile<'a> {
    fn from(path: &'a PathBuf) -> Self {
        AutoRemoveFile {
            path: path.as_path(),
            auto_remove: false,
        }
    }
}

impl<'a> From<&'a str> for AutoRemoveFile<'a> {
    fn from(path: &'a str) -> Self {
        AutoRemoveFile {
            path: Path::new(path),
            auto_remove: false,
        }
    }
}

impl<'a> Drop for AutoRemoveFile<'a> {
    fn drop(&mut self) {
        if self.auto_remove {
            if let Err(err) = remove_file(self.path) {
                warn!("fail to remove {}: {}", self.path.display(), err);
            }
        }
    }
}

impl AsRef<Path> for AutoRemoveFile<'_> {
    fn as_ref(&self) -> &Path {
        self.path
    }
}

impl fmt::Display for AutoRemoveFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())
    }
}
