# Little Pause

[![Checks](https://github.com/i-xoxol/little-pause/actions/workflows/checks.yml/badge.svg)](https://github.com/i-xoxol/little-pause/actions/workflows/checks.yml)

A quiet, self-hosted private journal. Plain text entries are encrypted in the
browser before they reach the server. Built with Python's standard library,
vanilla JavaScript and Web Crypto; no third-party app dependencies or CDNs.

## Features

- One-owner registration with a one-time invitation, email verification, a
  user-chosen password and a personal recovery kit.
- Browser-side encryption of entry titles, text, dates, mood, favorites and trash.
- Autosave, encrypted unsynced drafts, local search, recoverable Trash, change
  conflicts, encrypted backup downloads and ten-minute inactivity locking.
- Responsive desktop/phone layouts and keyboard-accessible controls.
- Password recovery requires **both** an emailed link and the personal recovery
  key. Resetting the password retains access to existing encrypted entries.
- Optional browser-side migration of entries from the earlier plaintext version.

## Try it locally

Requires Python 3.12+ and Node.js 22+. No package installation is necessary.

```sh
git clone https://github.com/i-xoxol/little-pause.git
cd little-pause
python dev_fixture.py
```

Open http://127.0.0.1:18095/. The test invitation is `fixture-invitation`.
The fixture sends **no email**: verification and recovery tokens are written to
`.test-state/mail.json`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full flow.
Use only disposable test passwords and synthetic journal entries with this fixture.

```sh
python -m unittest discover -v
node --check app.mjs
node --check crypto.mjs
node --test test_crypto.mjs
```

## Privacy model

A random 256-bit vault key encrypts entries with AES-256-GCM and fresh 96-bit
nonces. Associated data binds each ciphertext to its vault, entry and version.
PBKDF2-SHA-256 (600,000 iterations, random 256-bit salt) and HKDF separate the
password wrapping key from the authentication credential. The server stores a
salted scrypt hash of that separate credential (N=131072, r=8, p=1), encrypted
vault-key wrappers and encrypted entries. It never receives the password, vault
key, password wrapping key or recovery secret.

The browser creates a separate random 256-bit recovery key. Keep it private and
separate from the password. Email alone cannot decrypt an existing journal. If
both password and recovery key are lost, existing entries cannot be recovered.

Usernames, email addresses, entry IDs/versions/count and authentication metadata
remain visible to the host. This protects stored content; a server administrator
who replaces the delivered web client can capture a future password or plaintext.
A compromised device/browser has the same limitation. This is a custom
implementation, not an independently audited cryptosystem.

The legacy import encrypts and verifies entries in the owner's browser before
atomically importing them and clearing the old live SQLite rows using
`secure_delete` and `VACUUM`. It cannot erase earlier copies or forensic remnants.

## Production configuration

Run `server.py` behind a trusted HTTPS reverse proxy with persistent private data
outside the release directory. The app reads:

| Variable | Purpose |
| --- | --- |
| `JOURNAL_DATA` | Private directory containing `setup-code`, `vault.sqlite3`, optional legacy `journal.sqlite3`, and `mail.json` |
| `JOURNAL_ORIGIN` | Canonical HTTPS origin, such as `https://journal.example.com` |
| `JOURNAL_TRUSTED_PROXY` | Comma-separated, exact proxy peer IPs allowed to assert HTTPS; defaults to none |
| `JOURNAL_HTTP_HOSTS` | Optional local Host headers permitted to receive an HTTPS redirect |
| `JOURNAL_PORT` | Listening port; defaults to 8095 |
| `JOURNAL_MAIL_CONFIG` | Optional path overriding the private `mail.json` location |

The private SMTP JSON accepts `host`, `port`, `from`, optional `tls` (`ssl` or
STARTTLS), `username` and `password`. Remote SMTP uses TLS; a loopback MTA can
accept locally without TLS. Do not put this real configuration in Git. Keep the
data directory 0700 and files 0600. For direct SMTP configure SPF/DKIM/DMARC and
check deliverability; even authenticated messages can land in Spam/Junk.

The normal app URL is the domain root. An invitation code is entered in a form
only for the first registration. Do not create the real owner's account on her
behalf or choose/store her password or recovery secret.

## Automatic releases

**`main` is the public release branch.** GitHub Actions checks pushes and pull
requests. The Linux host polls main every two minutes, tests the exact commit in
an unprivileged sandbox, and switches to a new release only after tests pass.
HTTPS health checks verify the running commit; failed activation rolls back code.
Runtime data and mail configuration remain outside releases and outside Git.

See [ops/README.md](ops/README.md) for installation, status, rollback behavior and
how to pause automatic updates. Candidate tests cannot access production home
directories or the network. No GitHub token, SSH deploy key, webhook, or repository
secret is needed on the host. Other branches and unmerged pull requests do not
change production. Installed privileged deployment helpers are updated manually,
not by arbitrary changes to their copies in the public repository.

Contributions should preserve backward-compatible data/schema behavior; the
updater never automatically restores or replaces user databases. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before pushing to main.

## References

- [Web Crypto key derivation](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey)
- [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
