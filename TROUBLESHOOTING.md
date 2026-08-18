# Troubleshooting

This guide covers the public local desktop. Source builds do not include Hydra Remote; Remote being
unavailable in a source build is expected.

Before diagnosing a problem, record the Hydra version or source commit, operating-system version
and—on Linux—the display server. Do not run Hydra with `sudo`.

## `local_data_migration_failed`

Hydra stops rather than guessing when it cannot prove that the local store and its ancestry are
safe. The error is fail-closed: a failed legacy import leaves the legacy data untouched.

Possible causes include:

- an app-support directory owned by another user;
- a non-system symlink in the path;
- an ancestor writable by another local user without sticky-directory protection;
- an unexpected access-control-list entry;
- a database or sidecar that is not a singly linked regular file owned by the current user; or
- invalid or unsupported database schema metadata.

Close every Hydra window before investigating. Preserve the complete error text and inspect only the
path named by the error. Useful read-only commands are:

```sh
# macOS
stat -f '%Su %Sg %Sp %N' '<path-from-the-error>'
ls -lde '<path-from-the-error>'

# Linux
stat -c '%U %G %A %n' '<path-from-the-error>'
namei -l '<path-from-the-error>'
```

Correct an ownership or permission problem only when you understand exactly how that path acquired
the wrong metadata. Do not use recursive `chmod` or `chown`, and do not weaken a directory to mode
`0777`.

Never delete, truncate, rename or manually open Hydra's SQLite database, `-wal`, `-shm` or journal
files as a generic repair. Do not run `sqlite3` against the live store. Those files form one database
state and manipulating one member can destroy recoverable data or race a running process. If the
offending metadata is not unambiguous, stop and contact
[info@hydraterms.com](mailto:info@hydraterms.com) with redacted diagnostics.

## An installed agent is shown as unavailable

Hydra verifies supported agent executables through the user's interactive login shell. A command
available in one terminal tab may still be absent from the login-shell environment Hydra receives.

Check the same boundary Hydra uses, substituting the affected fixed command:

```sh
"$SHELL" -lic 'command -v codex'
"$SHELL" -lic 'command -v claude'
```

If the command prints no path, install the provider CLI or fix the appropriate login-shell startup
file. If it prints a path but Hydra times out, check that the startup file does not wait for input,
print unbounded output or perform slow network work. Restart Hydra after changing shell startup
configuration so new launch checks use the updated environment.

Do not work around the check by running Hydra as root or by placing an unrelated executable under a
supported agent's name. Choose **Terminal** when you intentionally want a plain shell rather than a
provider CLI.

## Linux Wayland and X11

The production Linux app selects the active GDK display backend and supports native Wayland and
X11. Capture these values without posting the rest of your environment:

```sh
printf 'session=%s\nwayland=%s\ndisplay=%s\ngdk=%s\n' \
  "${XDG_SESSION_TYPE:-unset}" \
  "${WAYLAND_DISPLAY:+set}" \
  "${DISPLAY:+set}" \
  "${GDK_BACKEND:-unset}"
```

`XDG_SESSION_TYPE=wayland` identifies the desktop session, but an explicitly forced
`GDK_BACKEND=x11` can still place an application on XWayland. Unless you are reproducing a backend
bug, remove an inherited backend override and let GTK select the native session backend.

For a real X11 qualification, sign out and choose the desktop's Xorg/X11 session. Running an X11
window through XWayland is useful compatibility evidence but is not equivalent to native Wayland or
a real X11 session.

The standalone `maestro-renderer --demo-scene` and `--stress` developer probes use winit's X11
backend. On a Wayland desktop they require XWayland even though the production Hydra app supports a
native Wayland presentation path. Do not diagnose the production host from those probes alone.

When reporting a Linux rendering problem, include:

- distribution and desktop environment;
- GPU and driver;
- `XDG_SESSION_TYPE` and whether `GDK_BACKEND` was explicitly set;
- whether the failure occurs in the production app, source app or renderer-only probe; and
- whether it reproduces on native Wayland, XWayland or real X11.

## Logs and reports

For source builds, preserve the bounded error printed by the process that failed. On macOS,
installed-launcher diagnostics are under `~/Library/Logs/Hydra`; files are owner-only but can contain
local paths and provider or session identifiers. Inspect and redact them before sharing.

Use a public GitHub issue for reproducible non-security bugs. Report suspected vulnerabilities only
through [SECURITY.md](SECURITY.md), never in a public issue.
