#![cfg_attr(
    all(not(debug_assertions), windows),
    windows_subsystem = "windows"
)]

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_decorations(false)
            .with_resizable(false)
            .with_inner_size([560.0, 500.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Vault",
        options,
        Box::new(|cc| {
            load_chinese_fonts(&cc.egui_ctx);
            Ok(Box::new(vault::app::VaultApp::default()))
        }),
    )
}

/// 加载系统中文字体，保证中文界面正常显示。
/// Windows 使用系统自带字体目录；Linux 扫描常见字体目录中的 CJK 字体。
/// 均不内嵌字体文件，保持绿色单文件、体积小巧。
fn load_chinese_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    for (i, path) in system_cjk_font_paths().into_iter().enumerate() {
        if let Ok(data) = std::fs::read(&path) {
            let name = format!("chinese_font_{i}");
            fonts
                .font_data
                .insert(name.clone(), egui::FontData::from_owned(data));
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, name.clone());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .insert(0, name);
        }
    }

    ctx.set_fonts(fonts);
}

#[cfg(windows)]
fn system_cjk_font_paths() -> Vec<std::path::PathBuf> {
    // Windows 中文字体优先级：微软雅黑 > 宋体 > 黑体
    [
        "C:/Windows/Fonts/msyh.ttc",   // 微软雅黑
        "C:/Windows/Fonts/msyhbd.ttc", // 微软雅黑粗体
        "C:/Windows/Fonts/simsun.ttc", // 宋体
        "C:/Windows/Fonts/simhei.ttf", // 黑体
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .collect()
}

#[cfg(not(windows))]
fn system_cjk_font_paths() -> Vec<std::path::PathBuf> {
    // 优先无衬线（Sans）中文字体，找不到再退回衬线（Serif）
    const SANS_KEYWORDS: [&str; 6] = [
        "notosanscjk",
        "sourcehansans",
        "wqy",
        "wenquanyi",
        "droidsansfallback",
        "uming",
    ];
    const SERIF_KEYWORDS: [&str; 2] = ["notoserifcjk", "sourcehanserif"];

    let dirs = linux_font_dirs();
    let mut picked = scan_cjk_fonts(&dirs, &SANS_KEYWORDS);
    if picked.is_empty() {
        picked = scan_cjk_fonts(&dirs, &SERIF_KEYWORDS);
    }
    picked
}

#[cfg(not(windows))]
fn linux_font_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = vec![
        std::path::PathBuf::from("/usr/share/fonts"),
        std::path::PathBuf::from("/usr/local/share/fonts"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let home = std::path::PathBuf::from(home);
        dirs.push(home.join(".fonts"));
        dirs.push(home.join(".local/share/fonts"));
    }
    dirs
}

#[cfg(not(windows))]
fn scan_cjk_fonts(dirs: &[std::path::PathBuf], keywords: &[&str]) -> Vec<std::path::PathBuf> {
    let mut regular: Option<std::path::PathBuf> = None;
    let mut bold: Option<std::path::PathBuf> = None;
    let mut fallback: Option<std::path::PathBuf> = None;

    'outer: for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let name = entry
                .path()
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !(name.ends_with(".ttf") || name.ends_with(".otf") || name.ends_with(".ttc")) {
                continue;
            }
            if !keywords.iter().any(|k| name.contains(k)) {
                continue;
            }
            let path = entry.path().to_path_buf();
            if name.contains("regular") {
                if regular.is_none() {
                    regular = Some(path);
                }
            } else if name.contains("bold") {
                if bold.is_none() {
                    bold = Some(path);
                }
            } else if fallback.is_none() {
                fallback = Some(path);
            }
            if regular.is_some() && bold.is_some() {
                break 'outer;
            }
        }
    }

    // 优先 Regular，其次 Bold；都没有时退回任意匹配
    regular
        .into_iter()
        .chain(bold)
        .chain(fallback)
        .take(2)
        .collect()
}
