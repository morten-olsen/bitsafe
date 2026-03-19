use clap::{Parser, Subcommand};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

mod backend;
mod pin;

#[derive(Parser)]
#[command(name = "bitsafe-prompt", about = "BitSafe interactive authentication agent")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Prompt for the master password
    Password {
        /// Prompt message
        #[arg(long, default_value = "Master password:")]
        message: String,
    },
    /// Verify identity via biometric (fingerprint / Touch ID)
    Biometric {
        /// Reason string shown to the user
        #[arg(long, default_value = "BitSafe wants to verify your identity")]
        reason: String,
    },
    /// Prompt for a PIN code
    Pin {
        /// Current attempt number (affects delay display)
        #[arg(long, default_value_t = 1)]
        attempt: u32,
        /// Maximum allowed attempts
        #[arg(long, default_value_t = 5)]
        max_attempts: u32,
    },
}

/// JSON response written to stdout for the service to read.
#[derive(Debug, Serialize)]
struct PromptResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl PromptResult {
    fn ok_with_credential(credential: String) -> Self {
        Self {
            status: "ok".into(),
            credential: Some(credential),
            message: None,
        }
    }

    fn verified() -> Self {
        Self {
            status: "verified".into(),
            credential: None,
            message: None,
        }
    }

    fn cancelled() -> Self {
        Self {
            status: "cancelled".into(),
            credential: None,
            message: None,
        }
    }

    fn error(msg: impl Into<String>) -> Self {
        Self {
            status: "error".into(),
            credential: None,
            message: Some(msg.into()),
        }
    }

    fn emit(&self) -> ! {
        let json = serde_json::to_string(self).expect("serialize prompt result");
        println!("{json}");
        let code = match self.status.as_str() {
            "ok" | "verified" => 0,
            "cancelled" => 1,
            _ => 2,
        };
        std::process::exit(code);
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let Some(backend) = backend::detect() else {
        PromptResult::error("No GUI prompt backend available (need zenity, kdialog, or osascript)").emit();
    };

    match cli.mode {
        Mode::Password { message } => match backend.prompt_password(&message) {
            Ok(Some(pw)) => PromptResult::ok_with_credential(pw).emit(),
            Ok(None) => PromptResult::cancelled().emit(),
            Err(e) => PromptResult::error(e.to_string()).emit(),
        },
        Mode::Biometric { reason } => match backend.verify_biometric(&reason) {
            Ok(true) => PromptResult::verified().emit(),
            Ok(false) => PromptResult::cancelled().emit(),
            Err(e) => PromptResult::error(e.to_string()).emit(),
        },
        Mode::Pin {
            attempt,
            max_attempts,
        } => {
            let remaining = max_attempts.saturating_sub(attempt) + 1;
            let msg = format!("Enter PIN ({remaining} attempts remaining):");
            match backend.prompt_pin(&msg) {
                Ok(Some(pin)) => PromptResult::ok_with_credential(pin).emit(),
                Ok(None) => PromptResult::cancelled().emit(),
                Err(e) => PromptResult::error(e.to_string()).emit(),
            }
        }
    }
}
