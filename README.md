# Grimoire

**A Bitwarden-compatible CLI and SSH agent for Vaultwarden.**
**Built by one engineer and a mass of AI. You should be mass worried.**

---

> *"We wrote a security product with AI and we're telling you not to use it. If that isn't a red flag, we don't know what is. Actually, the fact that you're still reading might be the real red flag. About you."*

---

## What Is This

Grimoire is what happens when you look at `ssh-agent` and think "what if this, but for my entire Bitwarden vault, and also what if I made a series of mass questionable life choices along the way."

It's a daemon that sits in the background, holds your decrypted vault keys in memory, and lets your CLI, your SSH client, and your deployment scripts talk to it over a Unix socket. The actual cryptography is done by the official [Bitwarden SDK](https://github.com/bitwarden/sdk-internal) (which has been professionally audited by people with degrees and certifications). Everything else — the daemon, the socket handling, the prompt agent, the questionable life choices — that's us.

```
  you ─── grimoire (CLI) ────┐
  git ─── ssh ──────────────┼── grimoire-service ──── Vaultwarden
  scripts ── grimoire run ───┘       (keys in memory, prayers in production)
```

It works with [Vaultwarden](https://github.com/dani-garcia/vaultwarden) out of the box. It also works with Bitwarden Cloud, but if you're self-hosting your password manager you're already the target audience for "software that requires compiling from source and reading a threat model before breakfast."

### Why This Exists

The official Bitwarden CLI works fine. Normal people use it and are happy. You are apparently not normal people, because you're reading the README of an alternative CLI that opens with "please don't use this." Welcome. You'll fit right in.

You might want Grimoire if you want:

- **SSH keys from your vault** — no `~/.ssh/id_ed25519` sitting on disk like a welcome mat for anyone who gets shell access. Your private keys exist only in memory and in your vault, which is either brilliant operational security or just moving the "single point of failure" to somewhere with a nicer UI.

- **Secret injection** — `grimoire run -- ./deploy.sh` resolves `grimoire:<id>/password` references in your environment variables before `exec`ing your command. Because environment variables are the new `.env` files, which were the new hardcoded passwords, which were the new sticky notes on monitors, and at some point we should probably just admit that the entire concept of "knowing a secret" is fundamentally incompatible with "computers."

- **Approval prompts that actually mean something** — every vault operation requires biometric, PIN, or password re-verification, scoped to your terminal session, expiring after 5 minutes. Not "unlock once, every process on your machine has a pool party with your credentials." Actual, per-session, time-limited approval. This is the feature that exists because someone once got RCE'd and the attacker's script just ran `bw get password prod-database` and nobody asked any questions.

- **A daemon that locks itself** — 15 minutes of inactivity and the vault locks. This is hardcoded. You cannot change it. We don't care that you find it inconvenient. You know what else is inconvenient? Explaining to your team why `prod-readonly-definitely-not-admin` had `DROP TABLE` permissions and someone found the password on your unlocked laptop at a coffee shop.

- **Vaultwarden compatibility that actually works** — the official SDK's API bindings assume Bitwarden Cloud's exact response format. Vaultwarden's responses are *slightly different* in about seventeen ways that each took us a full day to discover and a full evening to be annoyed about. We do our own HTTP calls. The SDK does the crypto. Everyone's happier.

## The Security Model (Read This Or Don't, We're Not Your Parents)

Grimoire follows the `ssh-agent` trust model: a single-user daemon holds decrypted keys in memory, accessible over a Unix socket. If you know what `ssh-agent` does, you know the shape of this. If you don't know what `ssh-agent` does, you're about to learn, and honestly this is a great way to learn because we're going to be very honest about all the ways it can go wrong.

If you skip this section and something bad happens, the consequences could include but are not limited to: credential exposure, unauthorized access to your infrastructure, your production database being renamed to `lol_no_backups`, your cryptocurrency wallet sending everything to an address that starts with `0xDEAD`, your CI pipeline deploying a bitcoin miner to every edge node, and a very awkward conversation with your CISO who specifically told you not to use unaudited security tools you found on GitHub.

### What We Defend Against

We're going to give you two tables. The first one is the one you show your manager. The second one is the one you actually need to read.

**The table you show your manager:**

| Threat | Defense | How Bad If We're Wrong |
|--------|---------|----------------------|
| Other users on the machine | Socket mode `0600` + `SO_PEERCRED`/`getpeereid` UID check | Your coworker's cron job reads your GitHub token. Their side project is now deployed with your credentials. They get promoted. You get paged. |
| IPC eavesdropping | X25519 key exchange + ChaCha20-Poly1305 AEAD per connection | Someone sniffs your socket traffic and learns your Netflix password is `netflix123!` and you haven't changed it since 2019. The security implications are secondary to the personal embarrassment. |
| Swap/core dump exposure | `mlockall` + `PR_SET_DUMPABLE` (Linux only) | A core dump contains your master password. It gets included in a bug report. The bug report is public. Your master password is `ILoveMyCat2024`. The cat's name is in your Twitter bio. |
| Brute force | Exponential backoff (master password), 3 attempts + auto-lock (PIN) | Someone tries every PIN from 0000 to 9999 except they only get 3 before the vault locks and the keys are scrubbed from memory. They are very frustrated. Good. |
| Blind RCE / shell access | GUI prompt required for unlock — attacker needs physical display access | Attacker runs `grimoire list`, a dialog box pops up on *your* screen asking for your fingerprint, attacker stares at their reverse shell wondering why nothing is happening. Chef's kiss. |
| Physical access without credentials | Prompt requires biometric, PIN, or master password | Someone walks up to your machine. A dialog appears. They need your fingerprint, your PIN, or your master password. They have none of these. They walk away. The system works exactly as intended, which is a sentence we don't get to say often enough. |
| Background process abuse | Scoped approval tied to terminal session leader PID (always on, hardcoded) | That sketchy npm postinstall script tries to read your vault. It's in a different session. Denied. It files a GitHub issue calling this "overly restrictive." We frame it. |
| Config-based downgrade | Security parameters are hardcoded constants | Attacker modifies your config file to set `require_approval = false`. Nothing happens because that setting doesn't exist anymore. Attacker reads CLAUDE.md, learns this was removed on purpose, briefly questions their life choices. |

### The Session Approval Model

This is the feature we're most proud of. It's also the one that will annoy you the most in daily use. These two facts are related.

Every vault operation — reading a password, signing with an SSH key, injecting a secret — requires **scoped access approval**. Not "you unlocked the vault so everything's fair game." Not "you typed your password twenty minutes ago so clearly you're still you." Actual, active, per-session, time-limited approval that you have to earn like a responsible adult.

Here's the flow:

1. You unlock the vault. This requires your master password via a GUI prompt, which means someone has to physically interact with your display. A script cannot do this. A reverse shell cannot do this. Your cat walking across the keyboard *theoretically* could, but the odds are low.
2. You run a vault command. A prompt appears: fingerprint, PIN, or password. You verify. You're approved.
3. The approval is scoped to your **terminal session** — specifically, the session leader PID. Every process spawned from that terminal shares the approval. A different terminal tab? Different session. Has to approve independently.
4. After **5 minutes**, the approval expires. Want more secrets? Prove you're you again.
5. All of these parameters are **hardcoded**. Not configurable. Not optional. Not "off by default but you can enable it." On. Always. Forever.

**Why this matters**: Imagine an attacker gets shell access to your machine — RCE, compromised SSH key, that mass npm package you installed without checking, whatever. They run `grimoire list`. A dialog box pops up on your screen. They're sitting in their apartment in another timezone staring at a shell prompt wondering why nothing happened. They need your fingerprint, your PIN, or your master password. If they have your master password, they *could* use `grimoire approve` — but at that point both your computer and your master password are compromised, and you have much bigger problems than Grimoire's approval model. Like explaining to your team why the deploy keys are now on a Telegram channel, your DNS is pointing to a parking page, and someone is mass mining Dogecoin on your Kubernetes cluster.

We learned our lesson from every tool that shipped with `--disable-security-for-testing` and discovered that production *is* the test environment. You can't turn this off. We're sorry. We're not actually sorry.

### What We Don't Defend Against

This section is more important than the one above. If the last section was the brochure, this is the terms and conditions. Read it or end up like the people who agreed to clean public toilets because they didn't read the [Wi-Fi T&Cs](https://www.theguardian.com/technology/2017/jul/14/wifi-terms-and-conditions-clean-toilets-experiment).

**Root access** — Root can read process memory, attach a debugger, and extract your keys. This is true of every userspace secret manager ever written and every one that will ever be written. If root is compromised, the attacker isn't breaking into your vault — they're already living in your house, eating your food, and wearing your clothes, and you're arguing about whether the lock on the bathroom door is good enough. The correct response to "root is compromised" is not "use a better password manager." It's "reinstall the operating system and rotate every credential you've ever created, then sit in a dark room and think about what happened."

**Same-user attackers** — Any process running as your user can connect to the socket. The encrypted channel prevents eavesdropping, and the approval system means they can't *do* anything without authenticating, but they can try. If you're running malware as your own user, you have a trust problem that no software can solve. Maybe audit your browser extensions. Maybe stop installing random things from `curl | sh`. Maybe both. We're not judging. We're absolutely judging.

**macOS memory hardening** — `mlockall` and `PR_SET_DUMPABLE` are Linux-only. On macOS, your decrypted vault keys might get swapped to disk. We log a warning when this happens, which is the security equivalent of a lifeguard yelling "be careful" while watching someone swim with sharks. We'd love to fix this but Apple's memory protection APIs are... an adventure. An adventure we haven't gone on yet. An adventure that probably ends with filing a radar that gets closed as "works as intended."

**Memory residue** — All password and PIN fields use `Zeroizing<String>` (zeroed on drop), and the SDK uses `ZeroizingAllocator` for key material. We did the right thing. We're good engineers. But Rust's optimizer might copy strings around before we zero them, and the prompt subprocess communicates credentials via stdout JSON, which means those bytes travel through a pipe buffer, which means the kernel has opinions about when they get overwritten, which means your master password may briefly exist in RAM like a ghost at a party — technically present, hopefully unnoticed, almost certainly fine, but "almost certainly fine" is a phrase that has preceded every disaster in the history of computing.

### The Honest Assessment

This software was built by one person with substantial AI assistance. The AI was very confident about everything it wrote, which is either reassuring or terrifying depending on how much you know about AI.

It has **not** had a professional security audit. The cryptography is delegated to the Bitwarden SDK (which *has* been audited by people who get paid a lot of money to find problems). But the integration layer — the daemon, the socket handling, the state machine, the prompt agent, the part where we parse Vaultwarden's JSON responses and pray — that's us. Our code. Unreviewed by anyone who doesn't live in this repository.

We believe the architecture is sound. We've written a [thorough security analysis](docs/security.md) and a [comprehensive security report](docs/security-report.md). We've thought carefully about the threat model. But "we think it's fine" is not the same as "a professional found it to be fine," much like "I think this mushroom is edible" is not the same as "a mycologist confirmed this mushroom is edible." One of those sentences ends with dinner. The other might also end with dinner but then continues for another 12-48 hours in ways you won't enjoy.

**If you use this for real secrets, you are accepting that risk.** Possible outcomes include: everything works perfectly for years and you tell your friends about this cool tool you found (most likely), a subtle bug leaks one credential and you have a bad afternoon (unlikely but possible), or you wake up to find your homelab's Grafana dashboard has been replaced with a cryptocurrency mining operation, your smart fridge is sending spam, and your Roomba has joined a botnet (extremely unlikely but we're legally required to inform you that we cannot prove this is impossible).

We would genuinely love for someone to audit this and tell us what we got wrong. If you do, please [open an issue](../../issues) — we'll buy you coffee, mass fix everything you find, and name a test case after you. `test_the_bug_that_kevin_found_at_3am` will live in our codebase forever.

## Features

The boring list, but we'll try to make it less boring:

- **Vault access** — list, search, get passwords, usernames, notes, TOTP codes. The basics. The bread and butter. The reason you're here instead of just using `pass` like a minimalist.
- **SSH agent** — your vault's SSH keys, served from memory, no files on disk. Ed25519 today, RSA/ECDSA when we get around to it. Your `~/.ssh` directory can finally be empty, which will confuse every onboarding guide ever written.
- **Secret injection** — `grimoire run -- ./deploy.sh` scans env vars for `grimoire:<id>/password` references, resolves them, and `exec`s your command. No wrapper process. No temp files. No shell history. Your secrets go from vault to process memory and nowhere else. It's like a dead drop but for environment variables.
- **Scoped access approval** — biometric, PIN, or password re-verification per terminal session. Always on. Not negotiable. We don't care about your convenience. We care about the mass incident you'll have *without* it.
- **Encrypted IPC** — every socket connection does an X25519 key exchange and then speaks ChaCha20-Poly1305. This is the definition of defense in depth: the socket permissions should be enough, but "should be enough" is a phrase that appears on approximately 100% of post-incident reports.
- **Auto-lock** — 15 minutes of inactivity and the vault locks itself. Hardcoded. Because we know you. We know you'd set it to `999999`. We know you'd write a cron job to reset the timer. We know because we thought about doing it ourselves.
- **GUI prompts** — native Swift on macOS, GTK4/libadwaita on Linux, zenity/kdialog as fallback, terminal as last resort. We will find a way to ask you for your password. You cannot escape the dialog box. The dialog box is inevitable.
- **Background sync** — vault syncs from your server every 5 minutes. You'll always have fresh data. Unless your server is down. In which case you'll have 5-minute-old data, which is still better than the sticky note under your keyboard.
- **Shell completions** — bash, zsh, fish. We're not animals.
- **Persistent login** — service restarts only need `unlock`, not a full `login`. Because retyping your email and server URL every time your laptop wakes from sleep would make us uninstall our own software.
- **Git commit signing** — sign commits with SSH keys from your vault. No key files. No GPG. No existential crisis about expired subkeys.
- **Headless support** — `grimoire approve` for SSH sessions and servers without displays. Because not every machine has a screen, but every machine deserves secrets.
- **Hardcoded security** — security parameters are compile-time constants. `auto_lock_seconds = 0` is not a power user setting. It's a cry for help. We hardcoded the defaults so you can't weaken them. You're welcome. Please stop asking.

## Quick Install

### Prerequisites

- **Rust 1.88+** — install via [rustup](https://rustup.rs/). If you don't have Rust installed, you're about to mass enter a mass new mass chapter of your life. Rust compilation times build character. And mass patience. Mostly mass patience.
- A running **Vaultwarden** (or Bitwarden-compatible) server — if you don't have one, you need to set one up first. That's a whole other README. Godspeed.
- **Linux**: optionally `libgtk-4-dev` and `libadwaita-1-dev` for the native GUI prompt. Without these you get zenity dialogs, which work fine but look like they time-traveled from 2008.
- **macOS**: Xcode Command Line Tools for the native Swift prompt. You probably already have these from that one time you tried to learn iOS development and gave up after the third Xcode update.

### Build & Install

```bash
git clone https://github.com/user/grimoire.git
cd grimoire
cargo install --path crates/grimoire-cli
cargo install --path crates/grimoire-service
cargo install --path crates/grimoire-prompt
# Go make mass coffee. Rust is compiling. It'll be a minute.
# Not a literal minute. More like four minutes. Unless you're on a Raspberry Pi,
# in which case go make lunch.
```

### First Run

```bash
# Start the service (it runs in the background like your mass anxiety)
grimoire-service &

# Log in (one-time — you won't need to do this again unless you logout)
grimoire login you@example.com --server https://vault.example.com

# Use it (a dialog will pop up. approve it. this is the approval system. it's a feature.)
grimoire list
grimoire get <id> -f password
```

For detailed installation instructions including native prompts, service auto-start, and platform-specific setup, see the **[Installation Guide](docs/install.md)**. It's less funny than this README but more useful, which is a tradeoff we've made peace with.

## Documentation

We have a lot of docs. Possibly too many. But this is a security product and "I didn't document it" is how you get "I didn't understand it" which is how you get "I deployed it wrong" which is how you get "why is my database on the internet."

### For Users (Start Here)

| Document | What's In It |
|----------|-------------|
| **[Installation Guide](docs/install.md)** | Full install for Linux, macOS, and Android/Termux. Yes, Termux. We're as surprised as you are. |
| **[Tutorial: Getting Started](docs/tutorials/01-getting-started.md)** | Your first login, your first `grimoire list`, your first approval prompt dialog that you didn't expect. The full experience. |
| **[Tutorial: SSH Agent](docs/tutorials/02-ssh-agent.md)** | Delete your `~/.ssh/id_ed25519`. Actually don't. Back it up first. Then set this up. Then delete it. Actually keep the backup. |
| **[Tutorial: Secret Injection](docs/tutorials/03-secret-injection.md)** | `grimoire run` and the art of never putting secrets in shell history again. Your `~/.bash_history` will finally be something you could show a security auditor. |
| **[Tutorial: Headless Servers](docs/tutorials/04-headless.md)** | Running Grimoire on machines that don't have screens. Which is most servers. Which is arguably the important use case. |
| **[Quick Reference](docs/quickstart.md)** | Every command. No prose. No personality. Just the facts. The anti-README. |
| **[SSH Agent Reference](docs/ssh-agent.md)** | Everything about the SSH agent you could possibly want to know and several things you didn't. |

### Security (Read This If You Read Nothing Else, Actually You Should Definitely Read Other Things Too)

| Document | What's In It |
|----------|-------------|
| **[Security Model](docs/security.md)** | What we protect, what we don't, and why. The document you cite when someone asks "is this safe" and you want to give an honest answer instead of just saying "yeah probably." |
| **[Security Report](docs/security-report.md)** | The full security audit we did on ourselves. It's like grading your own homework, except we were genuinely trying to fail ourselves. |

### Architecture (For the Curious and the Paranoid)

| Document | What's In It |
|----------|-------------|
| **[Architecture](docs/architecture.md)** | How the pieces fit together. Diagrams. Arrows. Boxes. The kind of thing that makes architects happy and everyone else scroll faster. |
| **[Lifecycle](docs/lifecycle.md)** | The vault state machine, explained. LoggedOut → Locked → Unlocked, and all the exciting ways to go back. |
| **[SDK Integration](docs/sdk-integration.md)** | How we wrap the Bitwarden SDK and why we do our own HTTP. Contains the phrase "discovered the hard way" more times than we'd like. |
| **[Specs](specs/)** | ADR-style decision records for every design choice. Nine specs. Nine times we wrote a document before writing the code. Nine times the code didn't match the document on the first try. |

## Platform Support

| Platform | Status | Native Prompt | Service Manager | Vibe |
|----------|--------|---------------|-----------------|------|
| Linux (x86_64) | Fully supported | GTK4/libadwaita | systemd user unit | Production-ready. As production-ready as an unaudited security tool can be. Which is a sentence with a lot of asterisks. |
| macOS (Apple Silicon + Intel) | Fully supported | Native Swift (macOS 13+) | launchd LaunchAgent | Works great. Memory hardening is missing. We log a warning about it. The warning does nothing. |
| Android (Termux) | Experimental | Terminal only | Manual / Termux:Boot | It compiles. It runs. We've tested it. "Experimental" means "it works but if something goes wrong we'll be less surprised than you." |

## A Final Word

We built this because we wanted it. We use it daily. We've mass mass bet our own credentials on it, which is either a strong endorsement or a confession, depending on your perspective.

The world has enough security products where the author's confidence exceeds the evidence. We don't want to add to that pile. So instead we wrote a README that spends more time telling you not to use our software than explaining how to use it, which is either refreshing honesty or a terrible marketing strategy. Possibly both.

Use it to explore. Read the code. Learn from the architecture. Run it against a test vault with passwords like `hunter2` and `correct-horse-battery-staple` that you wouldn't mind seeing on a billboard. And if you decide to trust it with real secrets — please, do your own security review first. We're serious. We wrote a [29,000-word security report](docs/security-report.md) so you'd have a head start. We tried to mass break our own software. We documented everything we found. And then we wrote this README, which is somehow longer than most of our actual documentation.

If you find something, we want to hear about it. If you don't find anything, we *still* want to hear about it, because that either means we did a good job or you didn't look hard enough, and both outcomes are interesting.

If you find something *catastrophic*, we want to hear about it very quietly via email before you tell the rest of the internet. We promise to mass panic privately and fix it publicly. We'll credit you in the changelog. Your mass contribution of "found the bug that could have leaked everyone's passwords" will live forever in git history, right next to our mass contribution of "wrote the bug that could have leaked everyone's passwords."

## License

MIT. Do what you want. Including mass forking it, mass auditing it, mass telling us everything we got wrong, or printing out the source code and using it as kindling. We'd prefer the mass auditing option but we respect your autonomy.
