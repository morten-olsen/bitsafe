use clap::{Parser, Subcommand};
use gtk4::prelude::*;
use libadwaita::prelude::*;
use serde::Serialize;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Parser)]
#[command(name = "bitsafe-prompt-linux")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Password {
        #[arg(long, default_value = "Master password:")]
        message: String,
    },
    Biometric {
        #[arg(long, default_value = "BitSafe wants to verify your identity")]
        reason: String,
    },
    Pin {
        #[arg(long, default_value_t = 1)]
        attempt: u32,
        #[arg(long, default_value_t = 3)]
        max_attempts: u32,
    },
}

#[derive(Serialize)]
struct PromptResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl PromptResult {
    fn emit(self) -> ! {
        println!("{}", serde_json::to_string(&self).unwrap());
        match self.status.as_str() {
            "ok" | "verified" => std::process::exit(0),
            "cancelled" => std::process::exit(1),
            _ => std::process::exit(2),
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let app = libadwaita::Application::builder()
        .application_id("com.bitsafe.prompt")
        .build();

    let mode = Rc::new(RefCell::new(Some(cli.mode)));

    app.connect_activate(move |app| {
        let m = mode.borrow_mut().take().unwrap();
        match m {
            Mode::Password { message } => show_password_dialog(app, &message),
            Mode::Pin {
                attempt,
                max_attempts,
            } => {
                let remaining = max_attempts.saturating_sub(attempt) + 1;
                let msg = format!("Enter PIN ({remaining} attempts remaining):");
                show_password_dialog(app, &msg);
            }
            Mode::Biometric { reason: _ } => {
                // Try fprintd-verify, fall back to error
                match std::process::Command::new("fprintd-verify").output() {
                    Ok(output) if output.status.success() => {
                        PromptResult {
                            status: "verified".into(),
                            credential: None,
                            message: None,
                        }
                        .emit();
                    }
                    _ => {
                        PromptResult {
                            status: "error".into(),
                            credential: None,
                            message: Some("biometric_unavailable".into()),
                        }
                        .emit();
                    }
                }
            }
        }
    });

    app.run_with_args::<&str>(&[]);
}

fn show_password_dialog(app: &libadwaita::Application, message: &str) {
    let window = libadwaita::ApplicationWindow::builder()
        .application(app)
        .title("BitSafe")
        .default_width(380)
        .default_height(-1)
        .resizable(false)
        .build();

    // Heading
    let heading = gtk4::Label::builder()
        .label("BitSafe")
        .css_classes(["title-1"])
        .build();

    // Body
    let body = gtk4::Label::builder()
        .label(message)
        .css_classes(["body"])
        .build();

    // Password entry
    let entry = gtk4::PasswordEntry::builder()
        .show_peek_icon(true)
        .hexpand(true)
        .build();

    // Buttons
    let cancel_btn = gtk4::Button::builder()
        .label("Cancel")
        .hexpand(true)
        .build();

    let ok_btn = gtk4::Button::builder()
        .label("OK")
        .hexpand(true)
        .css_classes(["suggested-action"])
        .build();

    let button_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .homogeneous(true)
        .build();
    button_box.append(&cancel_btn);
    button_box.append(&ok_btn);

    // Layout
    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    content.append(&heading);
    content.append(&body);
    content.append(&entry);
    content.append(&button_box);

    let clamp = libadwaita::Clamp::builder()
        .maximum_size(400)
        .child(&content)
        .build();

    window.set_content(Some(&clamp));

    // Submit on Enter or OK click
    let entry_ref = entry.clone();
    let submit = Rc::new(move || {
        let text = entry_ref.text().to_string();
        if text.is_empty() {
            PromptResult {
                status: "cancelled".into(),
                credential: None,
                message: None,
            }
            .emit();
        } else {
            PromptResult {
                status: "ok".into(),
                credential: Some(text),
                message: None,
            }
            .emit();
        }
    });

    let submit_ref = submit.clone();
    entry.connect_activate(move |_| submit_ref());

    let submit_ref = submit.clone();
    ok_btn.connect_clicked(move |_| submit_ref());

    cancel_btn.connect_clicked(|_| {
        PromptResult {
            status: "cancelled".into(),
            credential: None,
            message: None,
        }
        .emit();
    });

    // Close window = cancel
    window.connect_close_request(|_| {
        PromptResult {
            status: "cancelled".into(),
            credential: None,
            message: None,
        }
        .emit();
    });

    window.present();
    entry.grab_focus();
}
