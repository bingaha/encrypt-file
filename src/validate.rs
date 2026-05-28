use crate::file_ops;
use crate::name_encrypt;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct ValidationIssue {
    pub path: std::path::PathBuf,
    pub issue: String,
}

pub fn validate_directory(root: &Path, _password: &[u8]) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let exe_path = std::env::current_exe().unwrap_or_default();

    for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();

        if path == exe_path {
            continue;
        }

        if entry.file_type().is_file() {
            if file_ops::is_encrypted(path) {
                issues.push(ValidationIssue {
                    path: path.to_path_buf(),
                    issue: "文件已加密".to_string(),
                });
                continue;
            }

            if fs::OpenOptions::new().write(true).open(path).is_err() {
                issues.push(ValidationIssue {
                    path: path.to_path_buf(),
                    issue: "文件被占用或无法写入".to_string(),
                });
                continue;
            }

            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if name_encrypt::would_exceed_name_limit(&name_str, true) {
                    issues.push(ValidationIssue {
                        path: path.to_path_buf(),
                        issue: format!("加密后文件名过长 ({} 字节)", name_str.len()),
                    });
                }
            }
        } else if entry.file_type().is_dir() && path != root {
            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if name_encrypt::would_exceed_name_limit(&name_str, false) {
                    issues.push(ValidationIssue {
                        path: path.to_path_buf(),
                        issue: format!("加密后目录名过长 ({} 字节)", name_str.len()),
                    });
                }
            }
        }
    }

    issues
}

pub fn validate_file(path: &Path) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    if !path.exists() {
        issues.push(ValidationIssue {
            path: path.to_path_buf(),
            issue: "文件不存在".to_string(),
        });
        return issues;
    }

    if file_ops::is_encrypted(path) {
        issues.push(ValidationIssue {
            path: path.to_path_buf(),
            issue: "文件已加密".to_string(),
        });
        return issues;
    }

    if fs::OpenOptions::new().write(true).open(path).is_err() {
        issues.push(ValidationIssue {
            path: path.to_path_buf(),
            issue: "文件被占用或无法写入".to_string(),
        });
    }

    if let Some(name) = path.file_name() {
        let name_str = name.to_string_lossy();
        if name_encrypt::would_exceed_name_limit(&name_str, true) {
            issues.push(ValidationIssue {
                path: path.to_path_buf(),
                issue: format!("加密后文件名过长 ({} 字节)", name_str.len()),
            });
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vault_validate_test_{}", name))
    }

    fn setup(name: &str) {
        let dir = test_dir(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
    }

    fn cleanup(name: &str) {
        let _ = fs::remove_dir_all(test_dir(name));
    }

    #[test]
    fn test_validate_clean_directory() {
        let name = "clean_dir";
        setup(name);
        let dir = test_dir(name);
        fs::write(dir.join("file.txt"), b"content").unwrap();
        fs::create_dir(dir.join("subdir")).unwrap();
        fs::write(dir.join("subdir/file2.txt"), b"content2").unwrap();

        let issues = validate_directory(&dir, b"password");
        assert!(issues.is_empty());

        cleanup(name);
    }

    #[test]
    fn test_validate_already_encrypted() {
        let name = "already_enc";
        setup(name);
        let dir = test_dir(name);
        let path = dir.join("test.txt");
        fs::write(&path, b"content").unwrap();

        crate::file_ops::encrypt_file(&path, b"password").unwrap();

        let issues = validate_directory(&dir, b"password");
        assert!(issues.iter().any(|i| i.issue.contains("已加密")));

        cleanup(name);
    }

    #[test]
    fn test_validate_file_ok() {
        let name = "file_ok";
        setup(name);
        let dir = test_dir(name);
        let path = dir.join("test.txt");
        fs::write(&path, b"content").unwrap();

        let issues = validate_file(&path);
        assert!(issues.is_empty());

        cleanup(name);
    }

    #[test]
    fn test_validate_file_nonexistent() {
        let issues = validate_file(std::path::Path::new("/nonexistent/file.txt"));
        assert!(issues.iter().any(|i| i.issue.contains("不存在")));
    }
}
