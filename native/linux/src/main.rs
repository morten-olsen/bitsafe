use clap::{Parser, Subcommand};
use gtk4::glib;
use gtk4::prelude::*;
use libadwaita::prelude::*;
use serde::Serialize;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Parser)]
#[command(name = "grimoire-prompt-linux")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Password {
        #[arg(long, default_value = "Confirm with your master password.")]
        message: String,
    },
    Biometric {
        #[arg(long, default_value = "Grimoire wants to verify your identity")]
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

/// Grimoire design tokens as GTK CSS.
const GRIMOIRE_CSS: &str = r#"
    /* Force dark palette */
    window.grimoire-prompt {
        background-color: #1f1f21;
    }

    /* Brand header */
    .grimoire-brand {
        color: #d6ab61;
        font-size: 13px;
        font-weight: 600;
    }

    .grimoire-brand image {
        color: #d6ab61;
    }

    /* Subtitle */
    .grimoire-subtitle {
        color: rgba(255, 255, 255, 0.48);
        font-size: 12px;
    }

    /* Attempts warning */
    .grimoire-attempts {
        color: rgba(255, 255, 255, 0.48);
        font-size: 11px;
        font-weight: 500;
    }

    .grimoire-attempts.critical {
        color: #e67366;
    }

    /* Custom password entry */
    .grimoire-entry {
        background-color: #17171a;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 8px;
        padding: 8px 12px;
        color: rgba(255, 255, 255, 0.92);
        font-size: 14px;
        min-height: 20px;
    }

    .grimoire-entry:focus-within {
        border-color: rgba(214, 171, 97, 0.45);
        box-shadow: 0 0 0 1px rgba(214, 171, 97, 0.2);
    }

    /* Primary (Continue) button */
    .grimoire-primary {
        background-color: #d6ab61;
        color: rgba(0, 0, 0, 0.85);
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        padding: 6px 20px;
        border: none;
        min-height: 0;
    }

    .grimoire-primary:hover {
        background-color: #ddb86e;
    }

    .grimoire-primary:disabled {
        background-color: #2b2b2e;
        color: rgba(255, 255, 255, 0.30);
    }

    /* Secondary (Cancel) button */
    .grimoire-secondary {
        background: none;
        border: none;
        color: rgba(255, 255, 255, 0.48);
        font-size: 12px;
        font-weight: 500;
        padding: 6px 12px;
        min-height: 0;
    }

    .grimoire-secondary:hover {
        color: rgba(255, 255, 255, 0.65);
    }
"#;

fn load_css() {
    let provider = gtk4::CssProvider::new();
    provider.load_from_string(GRIMOIRE_CSS);
    gtk4::style_context_add_provider_for_display(
        &gtk4::gdk::Display::default().expect("display"),
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

fn main() {
    let cli = Cli::parse();

    let app = libadwaita::Application::builder()
        .application_id("com.grimoire.prompt")
        .build();

    let mode = Rc::new(RefCell::new(Some(cli.mode)));

    app.connect_activate(move |app| {
        load_css();

        // Force dark color scheme
        let style = libadwaita::StyleManager::default();
        style.set_color_scheme(libadwaita::ColorScheme::ForceDark);

        let m = mode.borrow_mut().take().unwrap();
        match m {
            Mode::Password { message } => show_prompt(app, PromptKind::Password, &message, None),
            Mode::Pin {
                attempt,
                max_attempts,
            } => {
                let remaining = max_attempts.saturating_sub(attempt) + 1;
                show_prompt(
                    app,
                    PromptKind::Pin,
                    "Confirm with your PIN",
                    if remaining < 3 { Some(remaining) } else { None },
                );
            }
            Mode::Biometric { reason: _ } => {
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

enum PromptKind {
    Password,
    Pin,
}

fn show_prompt(
    app: &libadwaita::Application,
    kind: PromptKind,
    message: &str,
    remaining_attempts: Option<u32>,
) {
    let window = libadwaita::ApplicationWindow::builder()
        .application(app)
        .title("Grimoire")
        .default_width(300)
        .default_height(-1)
        .resizable(false)
        .decorated(false)
        .build();

    window.add_css_class("grimoire-prompt");

    // Brand header: book icon + "Grimoire"
    let icon = gtk4::Image::from_icon_name("channel-secure-symbolic");
    icon.set_pixel_size(14);
    icon.add_css_class("grimoire-brand");

    let brand_label = gtk4::Label::new(Some("Grimoire"));
    brand_label.add_css_class("grimoire-brand");

    let brand_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(7)
        .halign(gtk4::Align::Center)
        .build();
    brand_box.append(&icon);
    brand_box.append(&brand_label);

    // Subtitle
    let subtitle = gtk4::Label::builder()
        .label(message)
        .halign(gtk4::Align::Center)
        .build();
    subtitle.add_css_class("grimoire-subtitle");

    // Password / PIN entry
    let placeholder = match kind {
        PromptKind::Password => "Master password",
        PromptKind::Pin => "PIN",
    };
    let entry = gtk4::PasswordEntry::builder()
        .show_peek_icon(false)
        .hexpand(true)
        .placeholder_text(placeholder)
        .build();
    entry.add_css_class("grimoire-entry");

    // Buttons
    let cancel_btn = gtk4::Button::with_label("Cancel");
    cancel_btn.add_css_class("grimoire-secondary");

    let ok_btn = gtk4::Button::with_label("Continue");
    ok_btn.add_css_class("grimoire-primary");
    ok_btn.set_sensitive(false);

    let button_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(0)
        .build();
    button_box.append(&cancel_btn);

    // Spacer between buttons
    let spacer = gtk4::Box::builder().hexpand(true).build();
    button_box.append(&spacer);
    button_box.append(&ok_btn);

    // Layout
    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(0)
        .margin_top(28)
        .margin_bottom(22)
        .margin_start(24)
        .margin_end(24)
        .build();

    content.append(&brand_box);

    // 8px gap after brand
    let gap1 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .height_request(8)
        .build();
    content.append(&gap1);
    content.append(&subtitle);

    // 18px gap before entry
    let gap2 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .height_request(18)
        .build();
    content.append(&gap2);
    content.append(&entry);

    // Optional attempts remaining label
    if let Some(remaining) = remaining_attempts {
        let gap3 = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .height_request(8)
            .build();
        content.append(&gap3);

        let attempts_text = if remaining == 1 {
            "1 attempt remaining".to_string()
        } else {
            format!("{remaining} attempts remaining")
        };
        let attempts_label = gtk4::Label::builder()
            .label(&attempts_text)
            .halign(gtk4::Align::Center)
            .build();
        attempts_label.add_css_class("grimoire-attempts");
        if remaining <= 1 {
            attempts_label.add_css_class("critical");
        }
        content.append(&attempts_label);
    }

    // 18px gap before buttons
    let gap4 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .height_request(18)
        .build();
    content.append(&gap4);
    content.append(&button_box);

    window.set_content(Some(&content));

    // Enable/disable Continue based on input
    let ok_ref = ok_btn.clone();
    entry.connect_changed(move |e| {
        let has_text = !e.text().is_empty();
        ok_ref.set_sensitive(has_text);
    });

    // Submit on Enter or Continue click
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

    // Escape key = cancel
    let key_controller = gtk4::EventControllerKey::new();
    key_controller.connect_key_pressed(|_, key, _, _| {
        if key == gtk4::gdk::Key::Escape {
            PromptResult {
                status: "cancelled".into(),
                credential: None,
                message: None,
            }
            .emit();
        }
        glib::Propagation::Proceed
    });
    window.add_controller(key_controller);

    window.present();
    entry.grab_focus();
}
