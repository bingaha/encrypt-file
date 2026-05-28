#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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

fn load_chinese_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Windows 中文字体优先级：微软雅黑 > 宋体 > 系统默认
    let font_paths = [
        "C:/Windows/Fonts/msyh.ttc",   // 微软雅黑
        "C:/Windows/Fonts/msyhbd.ttc", // 微软雅黑粗体
        "C:/Windows/Fonts/simsun.ttc", // 宋体
        "C:/Windows/Fonts/simhei.ttf", // 黑体
    ];

    for (i, path) in font_paths.iter().enumerate() {
        if let Ok(data) = std::fs::read(path) {
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
