# ADR 009: Native Prompt UI and Build Tooling

## Status

Proposed

## Context

The current prompt agent (`bitsafe-prompt`) shells out to `zenity`/`kdialog` on Linux and `osascript`/`swift -e` on macOS. This produces generic, unstyled dialogs that don't match the system's visual language. For a security tool, the prompt is the trust signal — it should look like a system authentication dialog, not a third-party app window.

Additionally, the project now spans multiple languages and build systems:
- Rust (cargo) — the core codebase
- Swift (swiftc/xcodebuild) — macOS native prompt
- C/Rust+GTK (cargo with system deps) — Linux native prompt

We need a developer experience that makes building, testing, and distributing all components straightforward regardless of which platform you're on.

## Decision

### Native Prompt Binaries

Replace the current shell-out approach with purpose-built native prompt binaries that look and feel like system authentication dialogs.

#### macOS: SwiftUI binary (`bitsafe-prompt-macos`)

A small SwiftUI app (~200 lines) that:
- Uses `NSPanel` (floating, always-on-top) for the password/PIN dialog
- Uses `LAContext.evaluatePolicy()` for Touch ID — the same API that 1Password, sudo, and system preferences use
- Matches the system appearance: dark mode, accent color, SF Symbols, vibrancy
- No Xcode project needed — builds with `swiftc` directly
- Ships as a single binary (~500KB)

```
bitsafe-prompt-macos/
  Sources/
    main.swift          # Entry point, argument parsing
    PasswordPrompt.swift # Password/PIN dialog
    BiometricPrompt.swift # Touch ID wrapper
    Theme.swift          # System-matched styling
  Package.swift          # Swift Package Manager manifest
```

**Build**: `swift build -c release` → produces `bitsafe-prompt-macos`

#### Linux: GTK4/libadwaita binary (`bitsafe-prompt-linux`)

A small Rust+GTK4 binary (~200 lines) using `gtk4-rs` and `libadwaita` that:
- Uses `AdwMessageDialog` for password/PIN entry — matches GNOME system dialogs exactly
- Dark mode, accent colors, rounded corners, proper typography — all from libadwaita
- For KDE desktops: detect desktop environment and fall back to `kdialog` (already native-looking on KDE)
- Biometric via `fprintd` D-Bus API (polkit-style prompt)

```
bitsafe-prompt-linux/
  Cargo.toml
  src/
    main.rs              # Entry point, argument parsing
    password.rs          # AdwMessageDialog password prompt
    biometric.rs         # fprintd D-Bus integration
```

**Build**: `cargo build -p bitsafe-prompt-linux --release`

**System deps**: `gtk4`, `libadwaita-1` (available on all modern GNOME distros)

#### Shared Protocol

Both native binaries speak the same protocol as the current `bitsafe-prompt`:
- Arguments: `password [--message MSG]`, `biometric [--reason MSG]`, `pin [--attempt N --max-attempts N]`
- Output: single JSON line to stdout
- Exit codes: 0 = success, 1 = cancelled, 2 = error

The service doesn't need to know which platform binary it's spawning — the interface is identical.

#### Fallback Chain

```
1. Platform-native binary (bitsafe-prompt-macos / bitsafe-prompt-linux)
2. bitsafe-prompt (current zenity/kdialog/osascript fallback)
3. Terminal fallback (rpassword)
```

The service checks for binaries in order:
1. `bitsafe-prompt-{platform}` next to `bitsafe-service`, then in PATH
2. `bitsafe-prompt` next to `bitsafe-service`, then in PATH
3. Terminal fallback (only if `prompt.method = terminal`)

### Build Tooling: mise

The project now has multiple build artifacts across languages. Rather than documenting "run cargo for this, swiftc for that, ensure GTK dev headers are installed" — use [mise](https://mise.jdx.dev/) as the unified tool manager and task runner.

#### Why mise

- **Tool management**: Ensures correct Rust toolchain, Swift version, and system deps are available
- **Task runner**: `mise run build` builds everything, `mise run test` tests everything — regardless of which tools are involved
- **Cross-platform**: Works on Linux and macOS
- **Lightweight**: Single binary, no runtime dependencies (unlike `make` + shell scripts + `just` + ...)
- **`.mise.toml` is declarative**: New contributors run `mise install` and they're ready

#### Configuration

```toml
# .mise.toml

[tools]
rust = "1.88"

[tasks.build]
description = "Build all components"
run = """
cargo build --workspace --release
{% if os() == "macos" %}
cd native/macos && swift build -c release
{% endif %}
{% if os() == "linux" %}
cargo build -p bitsafe-prompt-linux --release
{% endif %}
"""

[tasks.test]
description = "Run all tests"
run = "cargo test --workspace"

[tasks.install]
description = "Install all binaries"
depends = ["build"]
run = """
cargo install --path crates/bitsafe-cli
cargo install --path crates/bitsafe-service
{% if os() == "macos" %}
cp native/macos/.build/release/bitsafe-prompt-macos ~/.cargo/bin/
{% endif %}
{% if os() == "linux" %}
cargo install --path native/linux
{% endif %}
"""

[tasks.dev]
description = "Build debug and run service"
run = """
cargo build --workspace
cargo run -p bitsafe-service
"""

[tasks.fmt]
description = "Format all code"
run = """
cargo fmt --all
{% if os() == "macos" %}
swift-format format --in-place native/macos/Sources/*.swift
{% endif %}
"""

[tasks.lint]
description = "Lint all code"
run = """
cargo clippy --workspace -- -D warnings
{% if os() == "macos" %}
swift-format lint native/macos/Sources/*.swift
{% endif %}
"""
```

#### Project Layout

```
bitsafe/
  .mise.toml                    # Tool management + tasks
  Cargo.toml                    # Rust workspace
  crates/
    bitsafe-sdk/                # SDK wrapper (Rust)
    bitsafe-protocol/           # IPC protocol (Rust)
    bitsafe-service/            # Service daemon (Rust)
    bitsafe-cli/                # CLI client (Rust)
    bitsafe-ssh-agent/          # Standalone SSH agent (Rust)
    bitsafe-common/             # Shared utilities (Rust)
    bitsafe-prompt/             # Fallback prompt (Rust, zenity/kdialog/osascript)
  native/
    macos/                      # SwiftUI prompt
      Package.swift
      Sources/
        main.swift
        ...
    linux/                      # GTK4/libadwaita prompt
      Cargo.toml                # Not in workspace (different deps)
      src/
        main.rs
        ...
  contrib/
    systemd/                    # Systemd unit files
    launchd/                    # LaunchAgent plist
  specs/
  docs/
```

The `native/linux` crate is intentionally **not** part of the Cargo workspace — it has `gtk4` and `libadwaita` dependencies that shouldn't pollute the main workspace build on macOS (where they don't exist).

## Consequences

### Positive

- **System-native appearance**: Prompts are indistinguishable from OS authentication dialogs
- **Touch ID integration**: Direct `LAContext` API, not a Swift script hack
- **Unified DX**: `mise run build` works everywhere, handles all languages
- **Clean fallback**: Works gracefully without native binaries (falls back to current behavior)
- **Small binaries**: ~500KB each, no runtime dependencies beyond system libraries

### Negative

- **Two prompt codebases**: Swift + Rust/GTK. But each is ~200 lines — smaller than many single modules.
- **GTK system dependency on Linux**: Requires `libadwaita-1-dev` / `libgtk-4-dev` for building. Runtime libraries are pre-installed on GNOME desktops.
- **Swift requires Xcode CLI tools on macOS**: `xcode-select --install` — most developers already have this.
- **mise is another tool**: But it replaces multiple tools (Makefile, shell scripts, tool version managers) with one.

### What This Doesn't Change

- The prompt protocol (arguments, JSON stdout, exit codes) is unchanged
- The service's `prompt.rs` module stays the same — just discovers a different binary name
- Terminal fallback still works
- The `bitsafe-prompt` crate remains as the universal fallback
