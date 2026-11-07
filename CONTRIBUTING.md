# Working on Little Pause

Use a feature branch and open a pull request. Merging or pushing to `main` marks
the commit as a public release: the production server checks `main` every two
minutes, tests that exact commit, and deploys it if the checks pass.

## Local development

Requires Python 3.12+ and Node.js 22+. No package installation is needed.

```sh
python dev_fixture.py
```

Open http://127.0.0.1:18095/. The disposable invitation code is
`fixture-invitation`. Use an address ending in `.test`; the fixture writes fake
verification/recovery messages to `.test-state/mail.json` and sends no mail.
Open the returned token as `http://127.0.0.1:18095/#setup=TOKEN` in a new tab.
For password recovery use `/#reset=TOKEN`. Never use real journal credentials
or real diary text with the fixture.

```sh
python -m unittest discover -v
node --check app.mjs
node --check crypto.mjs
node --test test_crypto.mjs
```

## Release rules

- Preserve client-side encryption and key separation. The password, vault key,
  recovery secret and diary plaintext must not be sent to the backend.
- Do not log request bodies, secret URL fragments or diary contents.
- Keep data/schema changes backward compatible. The updater rolls back code,
  not user data; destructive migrations need a separate maintenance procedure.
- Never commit SQLite databases, mail settings, account state, invitation codes,
  recovery kits, authentication files, private keys or production logs.
- App code and assets can be updated through `main`. Changes under `ops/` do not
  automatically replace the privileged updater installed on the host.
- Anyone who can push or merge into `main` controls the live web client. Forked
  pull requests are tested on GitHub but are not deployed until merged.

No repository secrets or server SSH keys are needed for GitHub Actions.
