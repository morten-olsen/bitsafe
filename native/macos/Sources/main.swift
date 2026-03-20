import AppKit
import Foundation
import LocalAuthentication

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

// MARK: - Password Prompt

func promptPassword(message: String) {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)

    let alert = NSAlert()
    alert.messageText = "Grimoire"
    alert.informativeText = message
    alert.alertStyle = .informational
    alert.addButton(withTitle: "OK")
    alert.addButton(withTitle: "Cancel")

    let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
    input.placeholderString = "Master password"
    alert.accessoryView = input
    alert.window.initialFirstResponder = input

    // Bring to front
    app.activate(ignoringOtherApps: true)

    let response = alert.runModal()
    if response == .alertFirstButtonReturn {
        let password = input.stringValue
        if password.isEmpty {
            emit(PromptResult(status: "cancelled"))
        } else {
            emit(PromptResult(status: "ok", credential: password))
        }
    } else {
        emit(PromptResult(status: "cancelled"))
    }
}

// MARK: - PIN Prompt

func promptPin(message: String) {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)

    let alert = NSAlert()
    alert.messageText = "Grimoire"
    alert.informativeText = message
    alert.alertStyle = .informational
    alert.addButton(withTitle: "OK")
    alert.addButton(withTitle: "Cancel")

    let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 200, height: 24))
    input.placeholderString = "PIN"
    alert.accessoryView = input
    alert.window.initialFirstResponder = input

    app.activate(ignoringOtherApps: true)

    let response = alert.runModal()
    if response == .alertFirstButtonReturn {
        let pin = input.stringValue
        if pin.isEmpty {
            emit(PromptResult(status: "cancelled"))
        } else {
            emit(PromptResult(status: "ok", credential: pin))
        }
    } else {
        emit(PromptResult(status: "cancelled"))
    }
}

// MARK: - Biometric (Touch ID)

func verifyBiometric(reason: String) {
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
    let message = getFlag("--message", default: "Master password:")
    promptPassword(message: message)

case "pin":
    let attempt = getFlag("--attempt", default: "1")
    let maxAttempts = getFlag("--max-attempts", default: "3")
    let remaining = (Int(maxAttempts) ?? 3) - (Int(attempt) ?? 1) + 1
    let message = "Enter PIN (\(remaining) attempts remaining):"
    promptPin(message: message)

case "biometric":
    let reason = getFlag("--reason", default: "Grimoire wants to verify your identity")
    verifyBiometric(reason: reason)

default:
    fputs("Unknown mode: \(mode)\n", stderr)
    exit(2)
}
