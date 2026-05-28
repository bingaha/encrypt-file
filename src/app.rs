pub struct VaultApp;

impl Default for VaultApp {
    fn default() -> Self { Self }
}

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Vault");
        });
    }
}
