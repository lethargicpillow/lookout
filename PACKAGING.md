# Debian packages for the Lookout fork

Build from a clean checkout of `develop` on the target Ubuntu/Kubuntu system.
The upstream application version remains 0.9.313 until an actual release.
Debian revisions identify the fork commit, e.g. `1+lookout.<commit-time>.g<sha>`.
On a normal chronological development history these sort after upstream's
`-1` and newer fork revisions sort after older ones. Do not replace the
upstream Git tag or publish a new release until acceptance is complete.

## Build and inspect

```sh
sudo apt-get install libgtk-4-dev libadwaita-1-dev libwebkitgtk-6.0-dev \
    libglib2.0-dev libssl-dev pkg-config dpkg-dev desktop-file-utils
cargo install cargo-deb --locked --version 3.7.0
./build.sh --deb
```

The build prints the exact archive path under `source/target/debian/`.
Pass that archive to `./scripts/check-deb.sh <path-to-deb>`. This inspects
the package, extracts it to a temporary directory, and validates the desktop
file, GSettings schema, app icon, AppStream file and native library links.
It does not install or launch the app.

## Local installation and upgrade acceptance

1. Close the running debug or installed Lookout. Keep a backup of existing
   application settings, local tasks and cache (and ensure any pending outbox
   work is safe). No package step should remove these.
2. Check `dpkg-deb -f <path-to-deb> Package Version Architecture Depends`;
   run `apt-get -s install --no-install-recommends ./<path-to-deb>` and inspect
   the proposed changes. Optional features such as EDS, DavMail and Office
   previews can use the existing recommended packages; they are not mandatory
   for the core client.
3. Install the chosen archive with
   `sudo apt install --no-install-recommends ./<path-to-deb>`. Do not purge an
   existing package first.
4. Check `dpkg-query -W lookout`, `gsettings list-schemas`, and launch
   `/usr/bin/lookout` (not `target/debug/lookout`). Verify KDE launcher,
   icon, tray, reading, compose, sending, contacts, calendar, and the existing
   account list and settings. The original app ID and XDG paths are unchanged.
5. Repeat with a newer fork package; check that APT recognises the newer
   version and that data remains present after restart.

A build on Ubuntu 24.04 is not a guarantee of compatibility with arbitrary
older distributions. The CI package is a native amd64 Ubuntu 24.04 artifact;
the local Kubuntu build uses the libraries of the actual target system.
