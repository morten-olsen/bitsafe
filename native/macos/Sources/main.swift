import AppKit
import Foundation
import LocalAuthentication
import SwiftUI

// MARK: - JSON Output

struct PromptResult: Codable {
    let status: String
    var credential: String?
    var message: String?
}

func emit(_ result: PromptResult) -> Never {
    let data = try! JSONEncoder().encode(result)
    print(String(data: data, encoding: .utf8)!)
    switch result.status {
    case "ok", "verified": exit(0)
    case "cancelled": exit(1)
    default: exit(2)
    }
}

// MARK: - Design Tokens

extension Color {
    static let grimoire = GrimoireColors()
}

struct GrimoireColors {
    let accent = Color(red: 0.84, green: 0.67, blue: 0.38)       // warm amber
    let accentDim = Color(red: 0.84, green: 0.67, blue: 0.38).opacity(0.15)
    let surface = Color(red: 0.12, green: 0.12, blue: 0.13)      // rich dark
    let surfaceRaised = Color(red: 0.17, green: 0.17, blue: 0.18)
    let fieldBg = Color(red: 0.09, green: 0.09, blue: 0.10)
    let fieldBorder = Color.white.opacity(0.08)
    let textPrimary = Color.white.opacity(0.92)
    let textSecondary = Color.white.opacity(0.48)
    let textMuted = Color.white.opacity(0.30)
}

// MARK: - Custom Text Field

struct GrimoireSecureField: View {
    let placeholder: String
    @Binding var text: String
    var isFocused: FocusState<Bool>.Binding

    var body: some View {
        SecureField("", text: $text, prompt: Text(placeholder)
            .foregroundColor(Color.grimoire.textMuted))
            .textFieldStyle(.plain)
            .font(.system(size: 14, weight: .regular))
            .foregroundStyle(Color.grimoire.textPrimary)
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color.grimoire.fieldBg)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(
                        isFocused.wrappedValue
                            ? Color.grimoire.accent.opacity(0.45)
                            : Color.grimoire.fieldBorder,
                        lineWidth: isFocused.wrappedValue ? 1.5 : 1
                    )
            )
            .focused(isFocused)
    }
}

// MARK: - Buttons

struct GrimoirePrimaryButton: View {
    let label: String
    let enabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(enabled ? .black.opacity(0.85) : Color.grimoire.textMuted)
                .padding(.horizontal, 20)
                .padding(.vertical, 7)
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(enabled ? Color.grimoire.accent : Color.grimoire.surfaceRaised)
                )
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
    }
}

struct GrimoireSecondaryButton: View {
    let label: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Color.grimoire.textSecondary)
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Password Prompt

struct PasswordPromptView: View {
    let message: String
    @State private var password = ""
    @State private var appeared = false
    @FocusState private var focused: Bool
    let onSubmit: (String) -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            header
            field
            buttons
        }
        .frame(width: 300)
        .background(promptBackground)
        .opacity(appeared ? 1 : 0)
        .offset(y: appeared ? 0 : 4)
        .onAppear {
            withAnimation(.easeOut(duration: 0.25)) { appeared = true }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { focused = true }
        }
    }

    private var header: some View {
        VStack(spacing: 8) {
            HStack(spacing: 7) {
                Image(systemName: "key.fill")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Color.grimoire.accent)
                    .rotationEffect(.degrees(-45))
                Text("Grimoire")
                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                    .foregroundStyle(Color.grimoire.textPrimary)
            }
            Text(message)
                .font(.system(size: 12, weight: .regular))
                .foregroundStyle(Color.grimoire.textSecondary)
                .multilineTextAlignment(.center)
                .lineSpacing(2)
        }
        .padding(.top, 28)
        .padding(.bottom, 18)
    }

    private var field: some View {
        GrimoireSecureField(
            placeholder: "Master password",
            text: $password,
            isFocused: $focused
        )
        .onSubmit { submit() }
        .padding(.horizontal, 24)
    }

    private var buttons: some View {
        HStack {
            GrimoireSecondaryButton(label: "Cancel", action: onCancel)
                .keyboardShortcut(.cancelAction)
            Spacer()
            GrimoirePrimaryButton(label: "Continue", enabled: !password.isEmpty, action: submit)
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 20)
        .padding(.top, 18)
        .padding(.bottom, 22)
    }

    private func submit() {
        guard !password.isEmpty else { return }
        onSubmit(password)
    }
}

// MARK: - PIN Prompt

struct PinPromptView: View {
    let remaining: Int
    @State private var pin = ""
    @State private var appeared = false
    @FocusState private var focused: Bool
    let onSubmit: (String) -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            header
            field

            if remaining < 3 {
                Text("\(remaining) attempt\(remaining == 1 ? "" : "s") remaining")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(remaining <= 1
                        ? Color(red: 0.9, green: 0.45, blue: 0.4)
                        : Color.grimoire.textSecondary)
                    .padding(.top, 8)
            }

            buttons
        }
        .frame(width: 280)
        .background(promptBackground)
        .opacity(appeared ? 1 : 0)
        .offset(y: appeared ? 0 : 4)
        .onAppear {
            withAnimation(.easeOut(duration: 0.25)) { appeared = true }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { focused = true }
        }
    }

    private var header: some View {
        VStack(spacing: 8) {
            HStack(spacing: 7) {
                Image(systemName: "key.fill")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Color.grimoire.accent)
                    .rotationEffect(.degrees(-45))
                Text("Grimoire")
                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                    .foregroundStyle(Color.grimoire.textPrimary)
            }
            Text("Confirm with your PIN")
                .font(.system(size: 12, weight: .regular))
                .foregroundStyle(Color.grimoire.textSecondary)
        }
        .padding(.top, 28)
        .padding(.bottom, 18)
    }

    private var field: some View {
        GrimoireSecureField(
            placeholder: "PIN",
            text: $pin,
            isFocused: $focused
        )
        .onSubmit { submit() }
        .padding(.horizontal, 24)
    }

    private var buttons: some View {
        HStack {
            GrimoireSecondaryButton(label: "Cancel", action: onCancel)
                .keyboardShortcut(.cancelAction)
            Spacer()
            GrimoirePrimaryButton(label: "Continue", enabled: !pin.isEmpty, action: submit)
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 20)
        .padding(.top, 18)
        .padding(.bottom, 22)
    }

    private func submit() {
        guard !pin.isEmpty else { return }
        onSubmit(pin)
    }
}

// MARK: - Shared Background

private var promptBackground: some View {
    RoundedRectangle(cornerRadius: 14, style: .continuous)
        .fill(Color.grimoire.surface)
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(Color.white.opacity(0.06), lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.5), radius: 40, y: 12)
        .shadow(color: .black.opacity(0.2), radius: 8, y: 2)
}

// MARK: - Window

/// Borderless windows don't become key by default — override to accept keyboard input.
class KeyablePanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}

func showPromptWindow<Content: View>(content: Content) {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)

    let hostingView = NSHostingView(rootView:
        content
            .environment(\.colorScheme, .dark)
    )
    hostingView.setFrameSize(hostingView.fittingSize)

    // Add padding around the content so the shadow isn't clipped
    let shadowPad: CGFloat = 50
    let outerSize = NSSize(
        width: hostingView.fittingSize.width + shadowPad * 2,
        height: hostingView.fittingSize.height + shadowPad * 2
    )

    let window = KeyablePanel(
        contentRect: NSRect(origin: .zero, size: outerSize),
        styleMask: [.borderless],
        backing: .buffered,
        defer: false
    )
    window.isOpaque = false
    window.backgroundColor = .clear
    window.hasShadow = false  // we draw our own
    window.level = .floating
    window.isMovableByWindowBackground = true
    window.isReleasedWhenClosed = false
    window.appearance = NSAppearance(named: .darkAqua)

    // Container view for padding
    let container = NSView(frame: NSRect(origin: .zero, size: outerSize))
    hostingView.frame = NSRect(
        x: shadowPad,
        y: shadowPad,
        width: hostingView.fittingSize.width,
        height: hostingView.fittingSize.height
    )
    container.addSubview(hostingView)
    window.contentView = container

    window.center()

    // Close = cancel
    NotificationCenter.default.addObserver(
        forName: NSWindow.willCloseNotification,
        object: window,
        queue: .main
    ) { _ in
        emit(PromptResult(status: "cancelled"))
    }

    window.makeKeyAndOrderFront(nil)
    app.activate(ignoringOtherApps: true)

    // Ensure the window accepts first responder
    window.makeFirstResponder(hostingView)

    app.run()
}

// MARK: - Password Prompt Entry

func promptPassword(message: String) {
    showPromptWindow(content: PasswordPromptView(
        message: message,
        onSubmit: { password in
            emit(PromptResult(status: "ok", credential: password))
        },
        onCancel: {
            emit(PromptResult(status: "cancelled"))
        }
    ))
}

// MARK: - PIN Prompt Entry

func promptPin(attempt: Int, maxAttempts: Int) {
    let remaining = maxAttempts - attempt + 1
    showPromptWindow(content: PinPromptView(
        remaining: remaining,
        onSubmit: { pin in
            emit(PromptResult(status: "ok", credential: pin))
        },
        onCancel: {
            emit(PromptResult(status: "cancelled"))
        }
    ))
}

// MARK: - Biometric (Touch ID)

func verifyBiometric(reason: String) {
    // Ensure the process name is correct for the Touch ID dialog title
    ProcessInfo.processInfo.processName = "Grimoire"

    let context = LAContext()
    var error: NSError?

    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        emit(PromptResult(status: "error", message: "biometric_unavailable"))
    }

    let semaphore = DispatchSemaphore(value: 0)
    var success = false

    context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: reason
    ) { result, _ in
        success = result
        semaphore.signal()
    }

    semaphore.wait()

    if success {
        emit(PromptResult(status: "verified"))
    } else {
        emit(PromptResult(status: "cancelled"))
    }
}

// MARK: - Entry Point

let args = CommandLine.arguments

guard args.count >= 2 else {
    fputs("Usage: grimoire-prompt-macos <password|pin|biometric> [--message MSG] [--reason MSG] [--attempt N] [--max-attempts N]\n", stderr)
    exit(2)
}

let mode = args[1]

func getFlag(_ name: String, default defaultValue: String) -> String {
    if let idx = args.firstIndex(of: name), idx + 1 < args.count {
        return args[idx + 1]
    }
    return defaultValue
}

switch mode {
case "password":
    let message = getFlag("--message", default: "Confirm with your master password.")
    promptPassword(message: message)

case "pin":
    let attempt = Int(getFlag("--attempt", default: "1")) ?? 1
    let maxAttempts = Int(getFlag("--max-attempts", default: "3")) ?? 3
    promptPin(attempt: attempt, maxAttempts: maxAttempts)

case "biometric":
    let reason = getFlag("--reason", default: "Grimoire wants to verify your identity")
    verifyBiometric(reason: reason)

default:
    fputs("Unknown mode: \(mode)\n", stderr)
    exit(2)
}
