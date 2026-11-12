#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod models;
mod platform;
mod quarantine;
mod scanner;
mod ui;

use eframe::egui;
use std::sync::Arc;
use ui::app::{SentientApp, LOGO_PNG_BYTES};

fn main() -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Sentient — Offline Desktop Antivirus")
        .with_inner_size([1180.0, 760.0])
        .with_min_inner_size([920.0, 620.0]);

    if let Ok(icon) = eframe::icon_data::from_png_bytes(LOGO_PNG_BYTES) {
        viewport = viewport.with_icon(Arc::new(icon));
    }

    let native_options = eframe::NativeOptions {
        viewport,
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "Sentient",
        native_options,
        Box::new(|cc| Ok(Box::new(SentientApp::new(cc)))),
    )
}
