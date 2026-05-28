fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("vault.ico");
        res.set("ProductName", "Vault");
        res.set("FileDescription", "Vault - Windows 文件加密工具");
        res.set("LegalCopyright", "Copyright (c) 2024");
        res.compile().unwrap();
    }
}
