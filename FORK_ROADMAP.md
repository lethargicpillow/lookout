# Lookout fork roadmap

Baseline: the upstream README and [OUTLOOK_PARITY.md](OUTLOOK_PARITY.md) as
preserved on `main` at `a33e9f34ae22ccaea680e59aa77691307159ceb2`.
The upstream 76% parity score is historical; it is not a recalculated score
for this fork. Keep the original roadmap and its item IDs for comparison.

## Current priority: installable desktop builds

- [x] Existing workspace regression baseline: `c3892f7`, all ordinary
  workspace tests passed on the development Kubuntu machine (2026-11-15).
- [x] Adapt the existing cargo-deb packaging for locked builds and identifiable
  fork revisions, retaining the application ID and package name.
- [x] Build and validate a DEB locally on Kubuntu: `98a29dc`, package content,
  desktop entry, schema and native libraries verified; APT simulates an
  upgrade from `0.9.310-1` without installing or removing other packages.
- [ ] Finish installed-app acceptance: KDE menu launch, GSettings, tray,
  and preservation of configuration, keyring credentials, local tasks and cache.
- [ ] Before the first fork release, refresh the About dialog and related
  metadata: identify the fork and its version/revision, replace the outdated
  GNOME Online Accounts-only description, point issue reporting to the fork,
  and review the website link, AppStream, package descriptions and README for
  consistency. Retain original author Gavin Graham, contributor attribution,
  copyright and GPL-3.0-or-later notices. Keep the application ID and package
  name unchanged; agree on branding and version wording before editing.
- [ ] Validate CI on develop: build, tests, GreenMail, lint/format, and DEB
  artifact. Docker is not installed on the development machine.
- [ ] Fix any real CI/package failures before tagging a fork release.
  RPM, Flatpak and Snap remain the existing upstream release targets.

## Upstream roadmap cross-reference

| Upstream items | Fork assessment |
| --- | --- |
| Phase 1, 1.18 / 1.22 | Outlook shortcut preset and opening MSG files remain open. |
| Phase 2 | Upstream marks all roadmap rows complete; retain regression coverage. |
| Phase 3, 3.9 / 3.20 | Reminders window and calendar print styles remain open. |
| Phase 4, 4.7 / 4.11 | Directory lookup has Graph, LDAP and OAB implementations; full upstream acceptance still needs audit. Subtasks remain open. |
| Phase 5, 5.6 | Shared mailboxes/delegation are partial; verify real Microsoft 365 cases. |
| Phase 6, 6.4 | S/MIME and OpenPGP remain open. |
| Phase 7, 7.1–7.8 | Migration/PST, MSG/PDF export, translation, Immersive Reader, mail merge and notes are future work. Attachment preview and assistant functionality exist, but require comparison against the full upstream scope. |
| Track U | Fork has substantial ribbon, reading pane and compose refinements; do not mark the entire UI/UX track complete without reviewing the upstream acceptance criteria. |

## Fork-specific work and follow-up

- Account wizard, on-premises Exchange Autodiscover/NTLM, DavMail transport,
  OAB directory, account/sender names: implemented; validate fresh setup and
  package dependencies. Native EWS mail transport is not implemented.
- Gmail SMTP and sync, Google CardDAV, Yandex IMAP: tested with real accounts.
  Yandex's server-side BYE/UNAVAILABLE behavior remains; reconnect and
  background retries are bounded. Check long-running CardDAV and interactive
  reads during an initial large-mailbox sync without destroying a live cache.
- Google OAuth independent of GOA, complete Microsoft 365 setup validation,
  and DavMail lifecycle automation are the next account-related projects.
- Preserve package name `lookout`, app ID `io.github.gavindi.Lookout`,
  GSettings schema, XDG paths and keyring identity. Do not delete a working
  user's profile as part of package installation, upgrade, or regression tests.

A local DEB is an installation candidate, not a release until the package and
CI acceptance checks pass. See [PACKAGING.md](PACKAGING.md) for the procedure.
