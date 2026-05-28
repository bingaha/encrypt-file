use std::fs;
use std::path::Path;

const CLSID: &str = "{21EC2020-3AEA-1069-A2DD-08002B30309D}"; // Control Panel

pub fn hide_folder(path: &Path) -> std::io::Result<()> {
    let name = path.file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no folder name"))?
        .to_string_lossy();
    let hidden_name = format!("{}.{}", name, CLSID);
    let parent = path.parent().unwrap_or(path);
    let hidden_path = parent.join(&hidden_name);
    fs::rename(path, &hidden_path)
}

pub fn unhide_folder(path: &Path) -> std::io::Result<()> {
    let name = path.file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no folder name"))?
        .to_string_lossy();
    let suffix = format!(".{}", CLSID);
    if let Some(stripped) = name.strip_suffix(&suffix) {
        let parent = path.parent().unwrap_or(path);
        let orig_path = parent.join(stripped);
        fs::rename(path, &orig_path)
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "folder name does not have CLSID suffix"))
    }
}

pub fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.ends_with(&format!(".{}", CLSID)))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join("vault_hide_test")
    }

    fn setup() {
        let dir = temp_dir();
        let _ = fs::remove_dir_all(&dir);
        let inner = dir.join("test_folder");
        fs::create_dir_all(&inner).unwrap();
        fs::write(inner.join("file.txt"), b"content").unwrap();
    }

    fn cleanup() {
        let _ = fs::remove_dir_all(temp_dir());
    }

    #[test]
    fn test_hide_unhide_folder() {
        setup();
        let dir = temp_dir();
        let folder = dir.join("test_folder");

        assert!(!is_hidden(&folder));

        hide_folder(&folder).unwrap();

        let hidden = dir.join(format!("test_folder.{}", CLSID));
        assert!(hidden.exists());
        assert!(is_hidden(&hidden));
        assert!(!folder.exists());

        unhide_folder(&hidden).unwrap();

        assert!(folder.exists());
        assert!(!is_hidden(&folder));
        assert!(folder.join("file.txt").exists());

        cleanup();
    }

    #[test]
    fn test_is_hidden_false() {
        let path = std::path::Path::new("some_folder");
        assert!(!is_hidden(path));
    }
}
