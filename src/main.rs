fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 500.0])
            .with_min_inner_size([350.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Vault - 文件加密工具",
        options,
        Box::new(|_cc| Ok(Box::new(vault::app::VaultApp::default()))),
    )
}
