# Passing process configuration to runj-entrypoint

## Problem

`runj-entrypoint` is the small helper that starts a process inside a jail. It
runs inside the jail: it calls `jail.Attach`, which enters the jail and
`chroot`s into the jail root, and only then `exec(2)`s the target program.

Several OCI `process.*` fields can only be applied at that point, after the
process is inside the jail and immediately before `exec`:

* `process.cwd`: the `chdir` must resolve relative to the jail root.
* `process.user` (uid/gid/umask/additionalGids), `process.rlimits`, and
  `process.consoleSize` must be set on the process that becomes the container
  process.

So these values have to travel from `runj` into `runj-entrypoint`. The two
processes are separate programs, invoked two different ways:

* The init process: `runj create` forks `runj-entrypoint` as a child
  (`jail.SetupEntrypoint`), which blocks on a fifo until `runj start`.
* The secondary process: `runj exec` `exec(2)`s into `runj-entrypoint`
  (`jail.ExecEntrypoint`), replacing the `runj` image in place.

The channels available between the two are `runj-entrypoint`'s positional
arguments, its environment, an inherited file descriptor, or a file on disk.

## Decision

`runj-entrypoint` reads the process configuration from the container's state
directory, using only information it already has.

* Init process: the full OCI config is already persisted to the state directory
  by `oci.StoreConfig` during `runj create` (it is copied so later edits to the
  bundle do not affect the container). `runj-entrypoint` loads it with
  `oci.LoadConfig(id)` and reads `Process` from it. No new data crosses the
  wire.
* Secondary process: there is no long-lived persisted spec, because the process
  is transient and per-invocation. `runj exec` `exec(2)`s into
  `runj-entrypoint`, which preserves the pid. `runj exec` writes the resolved
  `Process` to `state/<id>/process.<pid>.json` (`oci.StoreProcess`) immediately
  before the `exec`, and `runj-entrypoint` reads `process.<getpid>.json`
  (`oci.LoadProcess`), applies it, and unlinks it. Each `exec` has a distinct
  pid, so concurrent execs use distinct files and nothing on the wire needs to
  name which file.

The configuration is read before `jail.Attach`, because the state directory
lives on the host filesystem and is unreachable from inside the `chroot`.

The positional arguments (`JAIL-ID FIFO-PATH PROGRAM [ARGS...]`) and the process
environment carry `process.args` and `process.env`. The fields applied from
inside the jail are read from disk.

## Alternatives considered

These are the other channels between `runj` and `runj-entrypoint`, and why each
one is not used.

A new positional argument (`... FIFO-PATH CWD PROGRAM ...`) changes the `runj`
to `runj-entrypoint` contract. An init `runj-entrypoint` can sit blocked on its
fifo across a `runj` upgrade, and both binaries resolve independently from
`PATH`, so the two can be version-skewed. An older `runj-entrypoint` handed the
new argument layout could read the cwd as the program to run and fail.

One environment variable per field (`__RUNJ_CWD`, `__RUNJ_UID`, ...) does not
scale: each new field adds a variable to set, document, and unset before the
final `exec` so it does not leak into the container's environment. A single
variable holding the whole `Process` as JSON would still be threaded through the
environment.

An inherited file descriptor still has to be named to `runj-entrypoint` (the
console socket passes its fd number in `__RUNJ_CONSOLE_SOCKET`), so it does not
avoid the environment. A fixed fd number is not guaranteed in the `exec` path:
`unix.Exec` has no `ExtraFiles`, `unix.Dup` returns an arbitrary fd, and forcing
a low number with `Dup2` can clobber an fd the Go runtime owns. Go marks its fds
`CLOEXEC`, so an fd needs a `dup` to survive `exec`. Because `unix.Exec`
replaces the image, the spec must already sit in a pipe buffer or a temp file,
which brings back the file cleanup this option was meant to avoid.

## Consequences

* Adding a future `process.*` field is mostly a matter of teaching
  `runj-entrypoint` to apply another field of the `Process` it already reads,
  with no new channel or wire format.
* `runj-entrypoint`'s argument and environment contract does not change, so a
  version-skewed or in-flight older `runj-entrypoint` keeps working; it does not
  apply the new field.
* `runj exec` writes a small `process.<pid>.json` into the state directory.
  `runj-entrypoint` unlinks it once read; if `runj-entrypoint` dies first, the
  file is removed when the state directory is deleted on `runj delete`.
* This is an internal, unstable contract between `runj` and `runj-entrypoint`,
  not a stable API.
