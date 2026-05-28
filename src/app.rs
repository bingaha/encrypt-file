use crate::dir_ops;
use crate::file_ops;
use crate::folder_hide;
use crate::validate;
use egui::{Color32, RichText, Sense, Stroke, ViewportCommand};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum AppMode {
    Detecting,
    DirectoryUnencrypted,
    DirectoryEncrypted,
    SingleFileUnencrypted,
    SingleFileEncrypted,
    Processing,
    Done,
    Error,
}

pub struct VaultApp {
    mode: AppMode,
    password: String,
    confirm_password: String,
    hide_folder: bool,
    error_message: String,
    status_message: String,
    single_file_path: Option<PathBuf>,
}

impl Default for VaultApp {
    fn default() -> Self {
        Self {
            mode: AppMode::Detecting,
            password: String::new(),
            confirm_password: String::new(),
            hide_folder: true,
            error_message: String::new(),
            status_message: String::new(),
            single_file_path: None,
        }
    }
}

impl VaultApp {
    fn detect_directory_mode(&mut self) {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.to_path_buf()));

        if let Some(dir) = exe_dir {
            if dir_ops::has_encrypted_files(&dir) {
                self.mode = AppMode::DirectoryEncrypted;
            } else {
                let file_count = dir_ops::count_files(&dir);
                if file_count > 0 {
                    self.mode = AppMode::DirectoryUnencrypted;
                } else {
                    self.mode = AppMode::SingleFileUnencrypted;
                }
            }
        } else {
            self.mode = AppMode::SingleFileUnencrypted;
        }
    }

    fn detect_single_file_mode(&mut self) {
        if let Some(ref path) = self.single_file_path {
            if file_ops::is_encrypted(path) {
                self.mode = AppMode::SingleFileEncrypted;
            } else {
                self.mode = AppMode::SingleFileUnencrypted;
            }
        }
    }

    fn start_encrypt_directory(&mut self) {
        if self.password.is_empty() || self.password != self.confirm_password {
            self.error_message = "密码不能为空且两次输入必须一致".to_string();
            return;
        }

        let exe_dir = match std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.to_path_buf()))
        {
            Some(d) => d,
            None => {
                self.error_message = "无法确定当前目录".to_string();
                return;
            }
        };

        let issues = validate::validate_directory(&exe_dir, self.password.as_bytes());
        if !issues.is_empty() {
            self.error_message = format!("校验失败: {}", issues[0].issue);
            return;
        }

        self.mode = AppMode::Processing;
        self.status_message = "正在加密...".to_string();

        match dir_ops::encrypt_directory(&exe_dir, self.password.as_bytes()) {
            Ok(processed) => {
                let mut msg = format!("加密完成，共处理 {} 个文件/目录", processed.len());
                if self.hide_folder {
                    // 切换 CWD 到父目录，避免 Windows 拒绝重命名当前工作目录
                    if let Some(parent) = exe_dir.parent() {
                        let _ = std::env::set_current_dir(parent);
                    }
                    match folder_hide::hide_folder(&exe_dir) {
                        Ok(()) => msg.push_str("（文件夹已隐藏）"),
                        Err(e) => msg.push_str(&format!("（文件夹隐藏失败: {}）", e)),
                    }
                }
                self.mode = AppMode::Done;
                self.status_message = msg;
                self.password.clear();
                self.confirm_password.clear();
            }
            Err(e) => {
                self.error_message = format!("加密失败: {}", e);
            }
        }
    }

    fn start_decrypt_directory(&mut self) {
        if self.password.is_empty() {
            self.error_message = "请输入密码".to_string();
            return;
        }

        let exe_dir = match std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.to_path_buf()))
        {
            Some(d) => d,
            None => {
                self.error_message = "无法确定当前目录".to_string();
                return;
            }
        };

        if folder_hide::is_hidden(&exe_dir) {
            let _ = folder_hide::unhide_folder(&exe_dir);
        }

        self.mode = AppMode::Processing;
        self.status_message = "正在解密...".to_string();

        match dir_ops::decrypt_directory(&exe_dir, self.password.as_bytes()) {
            Ok(processed) => {
                self.mode = AppMode::Done;
                self.status_message = format!("解密完成，共处理 {} 个文件/目录", processed.len());
                self.password.clear();
            }
            Err(e) => {
                self.error_message = format!("解密失败: {}", e);
                self.mode = AppMode::DirectoryEncrypted;
            }
        }
    }

    fn start_encrypt_file(&mut self) {
        let path = match &self.single_file_path {
            Some(p) => p.clone(),
            None => {
                self.error_message = "请选择文件".to_string();
                return;
            }
        };

        if self.password.is_empty() || self.password != self.confirm_password {
            self.error_message = "密码不能为空且两次输入必须一致".to_string();
            return;
        }

        let issues = validate::validate_file(&path);
        if !issues.is_empty() {
            self.error_message = format!("校验失败: {}", issues[0].issue);
            return;
        }

        self.mode = AppMode::Processing;
        self.status_message = "正在加密...".to_string();

        match file_ops::encrypt_file(&path, self.password.as_bytes()) {
            Ok(()) => {
                self.mode = AppMode::Done;
                self.status_message = "加密完成".to_string();
                self.password.clear();
                self.confirm_password.clear();
            }
            Err(e) => {
                self.error_message = format!("加密失败: {}", e);
                self.mode = AppMode::SingleFileUnencrypted;
            }
        }
    }

    fn start_decrypt_file(&mut self) {
        let path = match &self.single_file_path {
            Some(p) => p.clone(),
            None => {
                self.error_message = "请选择文件".to_string();
                return;
            }
        };

        if self.password.is_empty() {
            self.error_message = "请输入密码".to_string();
            return;
        }

        self.mode = AppMode::Processing;
        self.status_message = "正在解密...".to_string();

        match file_ops::decrypt_file(&path, self.password.as_bytes()) {
            Ok(()) => {
                self.mode = AppMode::Done;
                self.status_message = "解密完成".to_string();
                self.password.clear();
            }
            Err(e) => {
                self.error_message = format!("解密失败: {}", e);
                self.mode = AppMode::SingleFileEncrypted;
            }
        }
    }

    fn is_single_file_mode(&self) -> bool {
        matches!(
            self.mode,
            AppMode::SingleFileUnencrypted | AppMode::SingleFileEncrypted
        ) || self.single_file_path.is_some()
    }

    fn current_directory_label() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|parent| parent.display().to_string()))
            .unwrap_or_else(|| "无法确定当前目录".to_string())
    }

    fn draw_readonly_row(ui: &mut egui::Ui, label: &str, value: &str) {
        ui.label(RichText::new(label).size(13.0).color(muted()));
        egui::Frame::none()
            .fill(input_bg())
            .stroke(Stroke::new(1.0, border_soft()))
            .rounding(6.0)
            .inner_margin(egui::Margin::symmetric(10.0, 8.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(value).size(13.0).color(muted()));
            });
    }

    fn status_label(&self) -> &'static str {
        match self.mode {
            AppMode::Detecting => "检测中",
            AppMode::DirectoryUnencrypted => "目录未加密",
            AppMode::DirectoryEncrypted => "目录已加密",
            AppMode::SingleFileUnencrypted => "单文件未加密",
            AppMode::SingleFileEncrypted => "单文件已加密",
            AppMode::Processing => "处理中",
            AppMode::Done => "已完成",
            AppMode::Error => "失败",
        }
    }

    fn action_label(&self) -> Option<&'static str> {
        match self.mode {
            AppMode::DirectoryUnencrypted | AppMode::SingleFileUnencrypted => Some("开始加密"),
            AppMode::DirectoryEncrypted | AppMode::SingleFileEncrypted => Some("开始解密"),
            _ => None,
        }
    }
}

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.mode == AppMode::Detecting {
            self.detect_directory_mode();
        }

        // 检测拖拽文件，自动切换到单文件模式
        let dropped = ctx.input(|i| {
            i.raw.dropped_files.iter().find_map(|f| f.path.clone())
        });
        if let Some(path) = dropped {
            self.single_file_path = Some(path);
            self.password.clear();
            self.confirm_password.clear();
            self.error_message.clear();
            self.status_message.clear();
            self.detect_single_file_mode();
        }

        Self::apply_style(ctx);

        // 自绘标题栏
        egui::TopBottomPanel::top("title_bar").show(ctx, |ui| {
            let bar_height = 40.0;
            let resp = ui.allocate_response(
                egui::vec2(ui.available_width(), bar_height),
                Sense::click_and_drag(),
            );
            if resp.drag_started() {
                ctx.send_viewport_cmd(ViewportCommand::StartDrag);
            }

            let rect = resp.rect;
            let painter = ui.painter();
            painter.rect_filled(rect, 0.0, panel());

            // 左侧：图标 + 标题
            let icon_center = egui::pos2(rect.left() + 26.0, rect.center().y);
            painter.circle_filled(icon_center, 14.0, Color32::from_rgb(9, 40, 82));
            painter.circle_stroke(icon_center, 14.0, Stroke::new(1.0, accent()));
            painter.text(
                icon_center,
                egui::Align2::CENTER_CENTER,
                "◆",
                egui::FontId::proportional(16.0),
                accent_light(),
            );
            painter.text(
                egui::pos2(rect.left() + 50.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                "Vault",
                egui::FontId::proportional(18.0),
                text(),
            );

            // 右侧：状态标签 + 关闭按钮
            let close_size = 46.0;
            let close_rect = egui::Rect::from_min_size(
                egui::pos2(rect.right() - close_size, rect.top()),
                egui::vec2(close_size, bar_height),
            );
            let close_resp = ui.allocate_rect(close_rect, Sense::click());
            let close_painter = ui.painter();
            if close_resp.hovered() {
                close_painter.rect_filled(close_rect, 0.0, Color32::from_rgb(180, 40, 40));
            }
            close_painter.text(
                close_rect.center(),
                egui::Align2::CENTER_CENTER,
                "×",
                egui::FontId::proportional(20.0),
                text(),
            );
            if close_resp.clicked() {
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }

            // 状态标签（在关闭按钮左侧）
            let status_rect = egui::Rect::from_min_size(
                egui::pos2(close_rect.left() - 80.0, rect.top()),
                egui::vec2(74.0, bar_height),
            );
            let status_inner = egui::Rect::from_center_size(
                status_rect.center(),
                egui::vec2(70.0, 22.0),
            );
            close_painter.rect_filled(status_inner, 99.0, Color32::from_rgb(5, 25, 52));
            close_painter.rect_stroke(status_inner, 99.0, Stroke::new(1.0, border()));
            close_painter.text(
                status_inner.center(),
                egui::Align2::CENTER_CENTER,
                self.status_label(),
                egui::FontId::proportional(11.0),
                accent_light(),
            );
        });

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(panel()).inner_margin(18.0))
            .show(ctx, |ui| {
                self.draw_tabs(ui);
                ui.add_space(14.0);
                self.draw_body(ui);
                ui.add_space(14.0);
                self.draw_footer(ui);
            });
    }
}

impl VaultApp {
    fn apply_style(ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        style.visuals.override_text_color = Some(text());
        style.visuals.widgets.inactive.bg_fill = input_bg();
        style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, border_soft());
        style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(13, 47, 92);
        style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, accent());
        style.visuals.widgets.active.bg_fill = Color32::from_rgb(17, 81, 174);
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        ctx.set_style(style);
    }

    fn draw_tabs(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(Color32::from_rgb(5, 18, 37))
            .stroke(Stroke::new(1.0, border_soft()))
            .rounding(7.0)
            .inner_margin(egui::Margin::same(4.0))
            .show(ui, |ui| {
                ui.columns(2, |columns| {
                    if Self::tab(&mut columns[0], "目录模式", !self.is_single_file_mode()).clicked()
                    {
                        self.password.clear();
                        self.confirm_password.clear();
                        self.error_message.clear();
                        self.status_message.clear();
                        self.single_file_path = None;
                        self.detect_directory_mode();
                    }

                    if Self::tab(&mut columns[1], "单文件模式", self.is_single_file_mode())
                        .clicked()
                    {
                        self.password.clear();
                        self.confirm_password.clear();
                        self.error_message.clear();
                        self.status_message.clear();
                        self.mode = AppMode::SingleFileUnencrypted;
                    }
                });
            });
    }

    fn tab(ui: &mut egui::Ui, label: &str, selected: bool) -> egui::Response {
        let fill = if selected {
            Color32::from_rgb(19, 87, 202)
        } else {
            Color32::from_rgb(5, 18, 37)
        };
        let stroke = if selected {
            Stroke::new(1.0, accent_light())
        } else {
            Stroke::new(1.0, Color32::TRANSPARENT)
        };

        ui.add_sized(
            [ui.available_width(), 34.0],
            egui::Button::new(RichText::new(label).size(14.0).color(text()))
                .fill(fill)
                .stroke(stroke)
                .rounding(6.0),
        )
    }

    fn draw_body(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(Color32::from_rgba_unmultiplied(4, 22, 45, 220))
            .stroke(Stroke::new(1.0, border()))
            .rounding(8.0)
            .inner_margin(egui::Margin::same(16.0))
            .show(ui, |ui| {
                ui.set_min_height(220.0);

                match self.mode {
                    AppMode::DirectoryUnencrypted => self.draw_directory_encrypt(ui),
                    AppMode::DirectoryEncrypted => self.draw_directory_decrypt(ui),
                    AppMode::SingleFileUnencrypted => self.draw_single_file_encrypt(ui),
                    AppMode::SingleFileEncrypted => self.draw_single_file_decrypt(ui),
                    AppMode::Processing => self.draw_processing(ui),
                    AppMode::Done => self.draw_done(ui),
                    AppMode::Error | AppMode::Detecting => {}
                }
            });
    }

    fn draw_directory_encrypt(&mut self, ui: &mut egui::Ui) {
        Self::draw_readonly_row(ui, "当前目录", &Self::current_directory_label());
        ui.add_space(8.0);
        self.draw_password_pair(ui);
        ui.add_space(2.0);
        ui.checkbox(&mut self.hide_folder, "加密后隐藏文件夹");
        ui.add_space(10.0);
        if self.draw_action_button(ui).clicked() {
            self.error_message.clear();
            self.start_encrypt_directory();
        }
    }

    fn draw_directory_decrypt(&mut self, ui: &mut egui::Ui) {
        Self::draw_readonly_row(ui, "当前目录", &Self::current_directory_label());
        ui.add_space(8.0);
        self.draw_password_once(ui);
        ui.add_space(10.0);
        if self.draw_action_button(ui).clicked() {
            self.error_message.clear();
            self.start_decrypt_directory();
        }
    }

    fn draw_single_file_encrypt(&mut self, ui: &mut egui::Ui) {
        self.draw_file_picker(ui);
        ui.add_space(8.0);
        let enabled = self.single_file_path.is_some();
        ui.add_enabled_ui(enabled, |ui| {
            self.draw_password_pair(ui);
            ui.add_space(10.0);
            if self.draw_action_button(ui).clicked() {
                self.error_message.clear();
                self.start_encrypt_file();
            }
        });
    }

    fn draw_single_file_decrypt(&mut self, ui: &mut egui::Ui) {
        self.draw_file_picker(ui);
        ui.add_space(8.0);
        let enabled = self.single_file_path.is_some();
        ui.add_enabled_ui(enabled, |ui| {
            self.draw_password_once(ui);
            ui.add_space(10.0);
            if self.draw_action_button(ui).clicked() {
                self.error_message.clear();
                self.start_decrypt_file();
            }
        });
    }

    fn draw_file_picker(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("文件").size(13.0).color(muted()));
        ui.horizontal(|ui| {
            let label_width = (ui.available_width() - 94.0).max(0.0);

            let (display_text, full_path) = self
                .single_file_path
                .as_ref()
                .map(|path| {
                    let display = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.display().to_string());
                    (display, path.display().to_string())
                })
                .unwrap_or_else(|| ("未选择文件".to_string(), String::new()));

            egui::Frame::none()
                .fill(input_bg())
                .stroke(Stroke::new(1.0, border_soft()))
                .rounding(6.0)
                .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                .show(ui, |ui| {
                    let label = egui::Label::new(
                        RichText::new(&display_text).size(13.0).color(text()),
                    )
                    .truncate();
                    let resp = ui.add_sized([label_width, 34.0], label);
                    if !full_path.is_empty() && full_path != display_text {
                        resp.on_hover_text(&full_path);
                    }
                });

            if ui
                .add_sized(
                    [84.0, 34.0],
                    egui::Button::new(RichText::new("选择文件").color(text()))
                        .fill(Color32::from_rgb(10, 43, 86))
                        .stroke(Stroke::new(1.0, border()))
                        .rounding(6.0),
                )
                .clicked()
            {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.single_file_path = Some(path);
                    self.error_message.clear();
                    self.status_message.clear();
                    self.detect_single_file_mode();
                }
            }
        });
    }

    fn draw_password_pair(&mut self, ui: &mut egui::Ui) {
        self.password_input(ui, "密码", "输入密码", false);
        self.password_input(ui, "确认密码", "再次输入密码", true);
    }

    fn draw_password_once(&mut self, ui: &mut egui::Ui) {
        self.password_input(ui, "密码", "输入密码", false);
    }

    fn password_input(&mut self, ui: &mut egui::Ui, label: &str, hint: &str, confirm: bool) {
        ui.label(RichText::new(label).size(13.0).color(muted()));
        let value = if confirm {
            &mut self.confirm_password
        } else {
            &mut self.password
        };
        ui.add_sized(
            [ui.available_width(), 34.0],
            egui::TextEdit::singleline(value)
                .password(true)
                .hint_text(hint)
                .vertical_align(egui::Align::Center)
                .text_color(text()),
        );
    }

    fn draw_action_button(&self, ui: &mut egui::Ui) -> egui::Response {
        ui.add_sized(
            [ui.available_width(), 42.0],
            egui::Button::new(
                RichText::new(self.action_label().unwrap_or("处理中"))
                    .size(15.0)
                    .strong()
                    .color(Color32::WHITE),
            )
            .fill(Color32::from_rgb(20, 91, 216))
            .stroke(Stroke::new(1.0, accent_light()))
            .rounding(6.0),
        )
    }

    fn draw_processing(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.spinner();
            ui.add_space(8.0);
            ui.label(RichText::new(&self.status_message).size(15.0).color(text()));
        });
    }

    fn draw_done(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("✓").size(34.0).color(success()));
            ui.label(
                RichText::new(&self.status_message)
                    .size(15.0)
                    .color(success()),
            );
        });
    }

    fn draw_footer(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let color = if !self.error_message.is_empty() {
                danger()
            } else if self.mode == AppMode::Done {
                success()
            } else {
                success()
            };

            ui.label(RichText::new("●").color(color));
            let footer = if !self.error_message.is_empty() {
                self.error_message.as_str()
            } else if !self.status_message.is_empty() {
                self.status_message.as_str()
            } else {
                "就绪"
            };
            ui.label(
                RichText::new(footer)
                    .size(13.0)
                    .color(if color == danger() { danger() } else { muted() }),
            );
        });
    }

}

fn panel() -> Color32 {
    Color32::from_rgb(5, 17, 34)
}

fn input_bg() -> Color32 {
    Color32::from_rgb(4, 15, 30)
}

fn border() -> Color32 {
    Color32::from_rgb(38, 127, 238)
}

fn border_soft() -> Color32 {
    Color32::from_rgb(28, 67, 112)
}

fn accent() -> Color32 {
    Color32::from_rgb(33, 137, 255)
}

fn accent_light() -> Color32 {
    Color32::from_rgb(133, 192, 255)
}

fn text() -> Color32 {
    Color32::from_rgb(226, 240, 255)
}

fn muted() -> Color32 {
    Color32::from_rgb(144, 175, 210)
}

fn success() -> Color32 {
    Color32::from_rgb(82, 230, 133)
}

fn danger() -> Color32 {
    Color32::from_rgb(255, 98, 116)
}
