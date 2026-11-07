# Little Pause contributor instructions

This repository is public and `main` is the production release branch.

- Use only synthetic data and the fake-mail local fixture for tests.
- Do not read production diary contents, create the real owner's account, choose
  her password, or obtain/store her recovery key.
- Preserve browser-side encryption. The backend must never receive plaintext
  diary entries, passwords, vault keys or recovery secrets.
- Keep real data, mail settings, setup invitations, credentials, logs, databases
  and recovery kits outside Git and outside release directories.
- Run the server tests and Node crypto checks before proposing a release.
- The host updater executes candidate tests as an isolated unprivileged user.
  Do not introduce production credentials or network-dependent tests.
- Automatic releases must preserve existing data and schema compatibility.
- Limit deployment changes to this app; do not restart unrelated services.
