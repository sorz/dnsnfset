use log::warn;
use std::{fmt, fs::remove_file, path::Path};

/// File on this path will be removed on `drop()`.
pub struct AutoRemoveFile<'a> {
    path: &'a str,
    auto_remove: bool,
}

impl AutoRemoveFile<'_> {
    pub fn set_auto_remove(&mut self, enable: bool) {
        self.auto_remove = enable;
    }
}

impl<'a> From<&'a str> for AutoRemoveFile<'a> {
    fn from(path: &'a str) -> Self {
        AutoRemoveFile {
            path,
            auto_remove: false,
        }
    }
}

impl<'a> Drop for AutoRemoveFile<'a> {
    fn drop(&mut self) {
        println!("drop?");
        if self.auto_remove {
            println!("drop!");
            if let Err(err) = remove_file(&self.path) {
                warn!("fail to remove {}: {}", self.path, err);
            }
        }
    }
}

impl<'a> AsRef<Path> for &'a AutoRemoveFile<'a> {
    fn as_ref(&self) -> &Path {
        self.path.as_ref()
    }
}

impl fmt::Display for AutoRemoveFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path)
    }
}
