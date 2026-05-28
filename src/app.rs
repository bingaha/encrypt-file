use crate::dir_ops;
use crate::file_ops;
use crate::folder_hide;
use crate::validate;
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
                if self.hide_folder {
                    let _ = folder_hide::hide_folder(&exe_dir);
                }
                self.mode = AppMode::Done;
                self.status_message = format!("加密完成，共处理 {} 个文件/目录", processed.len());
            }
            Err(e) => {
                self.mode = AppMode::Error;
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
            }
            Err(e) => {
                self.mode = AppMode::Error;
                self.error_message = format!("解密失败: {}", e);
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
            }
            Err(e) => {
                self.mode = AppMode::Error;
                self.error_message = format!("加密失败: {}", e);
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
            }
            Err(e) => {
                self.mode = AppMode::Error;
                self.error_message = format!("解密失败: {}", e);
            }
        }
    }

    fn reset(&mut self) {
        self.password.clear();
        self.confirm_password.clear();
        self.error_message.clear();
        self.status_message.clear();
        self.mode = AppMode::Detecting;
    }
}

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.mode == AppMode::Detecting {
            self.detect_directory_mode();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                ui.heading("Vault - 文件加密工具");
                ui.add_space(10.0);
            });

            ui.separator();
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                let is_dir_mode = !matches!(
                    self.mode,
                    AppMode::SingleFileUnencrypted | AppMode::SingleFileEncrypted
                );
                if ui.selectable_label(is_dir_mode, "目录模式").clicked() {
                    self.reset();
                    self.detect_directory_mode();
                }
                if ui.selectable_label(!is_dir_mode, "单文件模式").clicked() {
                    self.reset();
                    self.mode = AppMode::SingleFileUnencrypted;
                }
            });

            ui.add_space(10.0);

            match self.mode {
                AppMode::Detecting => {}
                AppMode::DirectoryUnencrypted => self.draw_encrypt_ui(ui, true),
                AppMode::DirectoryEncrypted => self.draw_decrypt_ui(ui, true),
                AppMode::SingleFileUnencrypted => self.draw_single_file_encrypt(ui),
                AppMode::SingleFileEncrypted => self.draw_single_file_decrypt(ui),
                AppMode::Processing => self.draw_processing(ui),
                AppMode::Done => self.draw_done(ui),
                AppMode::Error => self.draw_error(ui),
            }
        });
    }
}

impl VaultApp {
    fn draw_encrypt_ui(&mut self, ui: &mut egui::Ui, show_hide_option: bool) {
        ui.vertical(|ui| {
            ui.label("设置加密密码:");
            ui.add(
                egui::TextEdit::singleline(&mut self.password)
                    .password(true)
                    .hint_text("输入密码"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.confirm_password)
                    .password(true)
                    .hint_text("确认密码"),
            );

            if show_hide_option {
                ui.add_space(5.0);
                ui.checkbox(&mut self.hide_folder, "加密后隐藏文件夹");
            }

            ui.add_space(10.0);
            if ui.button("加密").clicked() {
                self.error_message.clear();
                if show_hide_option {
                    self.start_encrypt_directory();
                } else {
                    self.start_encrypt_file();
                }
            }

            if !self.error_message.is_empty() {
                ui.add_space(5.0);
                ui.colored_label(egui::Color32::RED, &self.error_message);
            }
        });
    }

    fn draw_decrypt_ui(&mut self, ui: &mut egui::Ui, is_directory: bool) {
        ui.vertical(|ui| {
            ui.label("输入解密密码:");
            ui.add(
                egui::TextEdit::singleline(&mut self.password)
                    .password(true)
                    .hint_text("输入密码"),
            );

            ui.add_space(10.0);
            if ui.button("解密").clicked() {
                self.error_message.clear();
                if is_directory {
                    self.start_decrypt_directory();
                } else {
                    self.start_decrypt_file();
                }
            }

            if !self.error_message.is_empty() {
                ui.add_space(5.0);
                ui.colored_label(egui::Color32::RED, &self.error_message);
            }
        });
    }

    fn draw_single_file_encrypt(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.label("选择要加密的文件:");
            ui.horizontal(|ui| {
                if let Some(ref path) = self.single_file_path {
                    ui.label(path.to_string_lossy().to_string());
                } else {
                    ui.label("未选择文件");
                }
                if ui.button("选择文件").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.single_file_path = Some(path);
                        self.detect_single_file_mode();
                    }
                }
            });

            ui.add_space(10.0);
            if self.single_file_path.is_some() {
                self.draw_encrypt_ui(ui, false);
            }
        });
    }

    fn draw_single_file_decrypt(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.label("选择要解密的文件:");
            ui.horizontal(|ui| {
                if let Some(ref path) = self.single_file_path {
                    ui.label(path.to_string_lossy().to_string());
                } else {
                    ui.label("未选择文件");
                }
                if ui.button("选择文件").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.single_file_path = Some(path);
                        self.detect_single_file_mode();
                    }
                }
            });

            ui.add_space(10.0);
            if self.single_file_path.is_some() {
                self.draw_decrypt_ui(ui, false);
            }
        });
    }

    fn draw_processing(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.spinner();
            ui.add_space(10.0);
            ui.label(&self.status_message);
        });
    }

    fn draw_done(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.colored_label(egui::Color32::GREEN, &self.status_message);
            ui.add_space(10.0);
            if ui.button("返回").clicked() {
                self.reset();
                self.detect_directory_mode();
            }
        });
    }

    fn draw_error(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.colored_label(egui::Color32::RED, &self.error_message);
            ui.add_space(10.0);
            if ui.button("重试").clicked() {
                let was_single_file = self.single_file_path.is_some();
                self.reset();
                if was_single_file {
                    self.mode = AppMode::SingleFileUnencrypted;
                } else {
                    self.detect_directory_mode();
                }
            }
        });
    }
}
