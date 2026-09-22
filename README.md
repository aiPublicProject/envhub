# keyfort

**English** | [简体中文](README.zh-CN.md)

> Encrypt your secrets into one local file, injected as environment variables at launch — zero code changes, one command to enable, no more leaked keys.

In 2026, xAI's Grok Build and Zhipu's ZCode were both caught **silently uploading users' entire codebases** — Git history, local records, and plaintext API keys, all packaged and shipped to the cloud. keyfort encrypts your secrets into a single `.keyfort` file: even if a tool packages it up and sends it away someday, what leaves your machine is ciphertext.

`DB_PASS`, `API_KEY` and other sensitive values no longer sit in plaintext inside your project. When you develop, entering the project directory automatically injects them as environment variables — `npm run dev` and `python main.py` run untouched, **not a single line of code changes**.

A purely local tool: no account, no server, no network requests of any kind. Built for individual developers.

## Quick Look

```console
$ pip install keyfort

$ cd my-project
$ keyfort .env.local my-password
Scope? [1] all (default) [2] partial — keep only the lines to encrypt, in your editor: 2
   ↳ your editor opens: keep the lines to encrypt, save & close
Original .env.local? [1] extract these secrets from the file (default) ...: 1

$ npm run dev            # secrets are already in the environment

# ---- next session ----
$ cd my-project          # open a new terminal, cd in — auto-injected, nothing to type
```

In terminals without the integration installed, typing the single word `keyfort` also drops you into the injected environment (exit to return).

## Why keyfort

- **Purely local** — no account, no server, no network requests; fully usable offline
- **Zero code changes** — injection happens via environment variables (OS parent-to-child inheritance); works with node / python / any language
- **Type the password once** — stored in the OS credential manager (Windows Credential Manager / macOS Keychain / Linux Secret Service); no plaintext ever hits the disk
- **Secrets separated from ordinary vars** — `DB_PASS` goes into the ciphertext, `PORT=3000` stays in the original file for frameworks to read as usual
- **Auditable** — 3 core files, ~950 lines, readable in half an hour; only two dependencies: `cryptography` and `keyring`

## Installation

```console
$ pip install keyfort          # before the first release: pip install git+https://github.com/aiPublicProject/keyfort.git
```

Python ≥ 3.9; Windows / macOS / Linux.

> Note: interactive CLI messages are currently Chinese-only. Localization is on the [roadmap](ROADMAP.md).

## Quick Start

```console
$ cd your-project
$ keyfort .env.local your-password
```

It asks two things in order: the **encryption scope** (everything, or partial — an editor opens where you keep only the lines to encrypt; what you keep IS the selection, and editing line counts doesn't matter), and **what to do with the original file** (extract these secrets / keep it as-is). Then terminal integration installs automatically and you enter the injected environment.

Daily use is three actions:

```console
$ keyfort edit           # edit secrets in your editor; re-encrypted on close (password required)
$ keyfort set KEY value  # add a secret (no password)
$ keyfort restore        # one-click restore to plaintext; deletes .keyfort and the cached password
```

What ends up on your machine:

| Location | What it is |
|---|---|
| `.keyfort` in your project | The encrypted secrets file (auto-added to `.gitignore`) |
| `.env.local` in your project | The original file, secrets extracted, the rest intact (auto-added to `.gitignore`) |
| `C:\Users\you\.keyfort\` (macOS/Linux: `~/.keyfort/`) | A tiny folder holding the cmd auto-activation script; removed by `keyfort uninit` |
| Your OS password manager | The encryption password — **not a file** |

## Commands

| Command | What it does |
|---|---|
| `keyfort .env.local password` | Encrypt & register: choose scope → split & encrypt → install terminal integration → enter injected environment |
| `keyfort` | Enter the injected environment (in integrated terminals = in-place activation, no exit needed) |
| `keyfort edit` | Edit secrets in your system editor (password required; re-encrypted on close) |
| `keyfort set KEY value` | Add/update a secret (no password needed) |
| `keyfort unset KEY` | Delete a secret |
| `keyfort print` | Print all secrets (password required) |
| `keyfort list` | List secret names (no values) |
| `keyfort passwd` | Change the encryption password |
| `keyfort run <command>` | Run a single command with the injected environment (scripts/CI; set `KEYFORT_PASSWORD` for unattended use) |
| `keyfort restore` | Restore plaintext: merge secrets back into the env file, delete `.keyfort` and the cached password |
| `keyfort init` / `uninit` | Install / remove terminal integration (idempotent, fully reversible) |

The terminal integration adds a small marked script to: PowerShell 5.1/7 profiles, bash's `.bashrc`, and cmd's AutoRun. If PowerShell's execution policy is Restricted and profiles don't load: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

## How It Works

**Encryption**. `.keyfort` stores the ciphertext of the selected `KEY=VALUE` lines:

```
KEYFORT1
<base64(salt 16B + nonce 12B + AES-256-GCM ciphertext)>
```

The encryption key is derived from your password via PBKDF2-HMAC-SHA256 (200,000 iterations) with a fresh random salt each time. AES-256-GCM is authenticated — a tampered file fails to decrypt rather than yielding fake values. Only raw bytes are stored; `KEY=VALUE` parsing happens only at injection time.

**Injection**. Environment variables are the OS's parent-to-child mechanism — `keyfort` decrypts, spawns a child shell (bash / PowerShell / cmd auto-detected), and puts the variables into its environment block, so any language can read them. Terminal integration takes another path: a shell function calls `keyfort activate --emit` to get an assignment script and runs it in the **current** session (a shell function is not a child process, so it can modify the current environment); the `KEYFORT_ACTIVE_KEYS` marker prevents double injection and enables cleanup.

**New machine**. Copy `.keyfort` over and type the password once — the ciphertext is OS-independent, no re-encryption needed.

## Security

**Why these guarantees matter — two real incidents:**

- **July 2026: xAI's Grok Build caught silently uploading users' codebases.** Reverse engineering by an independent researcher showed the AI coding tool uploaded users' complete Git repositories and commit history to the cloud — even with privacy settings off. Musk later promised to delete the data and open-sourced Grok Build.
- **September 2026: Zhipu's ZCode caught silently uploading user workspaces.** After login it packaged and uploaded the entire workspace (including Git history and local operation records), with no working off switch in the UI. Zhipu later apologized and promised to open-source the code and accept third-party audits.

The common thread: users only learned what these tools uploaded from their own machines **through reverse engineering** — and a plaintext `.env` goes to the cloud along with the workspace. keyfort's answer works in both directions: `.keyfort` contains only ciphertext, so uploads can't hurt you; and keyfort makes zero network requests with open-source code — no reverse engineering needed to know what it does.

**What it guarantees:**

- No network requests of any kind: the code imports no network modules — no internet, no registration, no data collection
- Open source, quick to audit (MIT): core logic is ~950 lines across 3 files
- Plaintext exists in only two places: your terminal session, and `keyfort edit`'s temp file (deleted on close)

**What it does not protect against (honestly):**

- Same-user malware can read your injected environment variables and credential store — the same boundary as 1Password CLI, sops, and ssh-agent; keyfort protects against "secret files committed to git / copied away"
- Lose the password, lose the data — there is no backdoor; back the password up together with `.keyfort`
- `git add -f` forced adds — `.gitignore` prevents accidents, not deliberate bypasses

## Development

```console
$ git clone https://github.com/aiPublicProject/keyfort.git
$ cd keyfort && pip install -e .
$ python tests/cli_flow.py      # full-flow tests; all should PASS
$ python -m build               # build into dist/
```

Planned features and design trade-offs (placeholder model, proxy mode, explicit non-goals) are in [ROADMAP.md](ROADMAP.md) (currently Chinese).

## License

MIT © aiPublicProject
