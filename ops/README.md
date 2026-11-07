# Automatic releases from public main

The installer is for an **existing** Linux/systemd Little Pause installation
using `/opt/little-pause/current`, `/opt/little-pause/releases`, and
`little-pause.service`. Prerequisites: Python 3.12+, Node.js 22+, Git and an
already configured HTTPS proxy. It does not change SMTP, DNS, account data,
invitation codes, passwords or encryption keys.

Review the installer and controller before installing them as root:

```sh
sudo python3 ops/install_updater.py \
  --repository https://github.com/YOUR-ACCOUNT/little-pause.git \
  --origin https://journal.example.com \
  --data /absolute/path/to/existing/private-data \
  --proxy YOUR_TRUSTED_PROXY_PEER_IP
sudo systemctl start little-pause-update.service
```

Host configuration lives in `/etc/little-pause-deploy.json` (root-only), outside
Git. The installer adds a journal service drop-in for the public origin and
trusted HTTPS proxy peer. Optional `--http-hosts` is a comma-separated list of
local Host headers permitted to receive an HTTP-to-HTTPS redirect.

Every two minutes the controller fetches **only `main`**, anonymously over HTTPS.
There are no server GitHub credentials, public webhook, or GitHub-hosted SSH key.
The exact commit's source is validated and tested by `little-pause-build.service`
as a separate nonlogin user with a private network, no home access and a writable
disposable build directory only. Repository tests/install scripts are never run
as root. Background test processes are killed with the build service.

If tests pass and `main` has not moved, the controller installs regular source
files from the same immutable Git objects into a root-owned release directory,
backs up **only `vault.sqlite3`**, switches the `current` symlink atomically,
restarts only the journal, and checks HTTPS health including the exact commit ID.
It never packages production data. It never backs up the legacy plaintext DB.

Failed tests retain the active release. Failed startup/health restores the
previous symlink and restarts that release. User databases are never automatically
restored or replaced. Keep future schema changes backward compatible; destructive
migrations require explicit maintenance. After a failed commit, retries occur
after 15 minutes or immediately when a different main commit arrives.

The privileged controller is copied to `/usr/local/lib/little-pause-deploy` at
installation. Edits to `ops/` on main do **not** replace this installed controller
or systemd units. Review and rerun the installer for intentional controller changes.

```sh
sudo cat /var/lib/little-pause-deploy/status.json
systemctl list-timers little-pause-update.timer
sudo journalctl -u little-pause-update.service -u little-pause-build.service
sudo systemctl start little-pause-update.service
sudo python3 /usr/local/lib/little-pause-deploy/updater.py --retry
sudo systemctl disable --now little-pause-update.timer  # pause automatic releases
```

Release directories and encrypted vault snapshots are retained for rollback and
manual maintenance; the updater does not prune them. Monitor disk use. Runtime
configuration, SMTP secrets and private data stay outside repository/releases.
