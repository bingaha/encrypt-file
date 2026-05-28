use std::path::PathBuf;

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    FileLocked(PathBuf),
    FileNameTooLong(PathBuf),
    PathTooLong(PathBuf),
    AlreadyEncrypted(PathBuf),
    InvalidPassword,
    CorruptedMetadata(PathBuf),
    DiskFull,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::FileLocked(p) => write!(f, "文件被占用: {}", p.display()),
            Self::FileNameTooLong(p) => write!(f, "加密后文件名过长: {}", p.display()),
            Self::PathTooLong(p) => write!(f, "路径过长: {}", p.display()),
            Self::AlreadyEncrypted(p) => write!(f, "文件已加密: {}", p.display()),
            Self::InvalidPassword => write!(f, "密码不正确"),
            Self::CorruptedMetadata(p) => write!(f, "元数据损坏: {}", p.display()),
            Self::DiskFull => write!(f, "磁盘空间不足"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;
