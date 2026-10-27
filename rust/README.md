# ext (userspace, Rust)

`ext` indexes the SHA-256 digests of the files under registered directories and
answers "which paths hold this content?". This crate is a Linux-only
implementation of the userspace part of the Extant design in the repository's
root [README](../README.md). The places where it departs from that text, or
decides something the text leaves open, are listed one by one in
[DIVERGENCES.md](DIVERGENCES.md), written against the spec as changed by
PR #12 (branch `spec/consensus-fixes`, commit bb9a46f).

Version 1 has no external services, no truncation, no `hash://` parsing, no
human names or tags, no watcher, no config file, and no parent/sub-extant
linking. It needs Linux 5.6 or later (`openat2`); mount boundaries use
`STATX_MNT_ID` (5.8) and fall back to `st_dev` with a warning.

## Build and test

```sh
cd rust
nix-shell shell.nix --run 'cargo build --release'
nix-shell shell.nix --run 'cargo test'
```

`shell.nix` pins nixpkgs and provides cargo, rustc, clippy, rustfmt and a C
compiler (SQLite is bundled). The crate declares `rust-version = "1.90"`.

Some tests (mount boundaries, nested registered roots, a store owned by another
uid) run `ext` inside an unprivileged user and mount namespace. They need
unprivileged user namespaces to be enabled and `unshare`, `chroot`, `ldd`, `cp`
and `mount` on `PATH`. Where that is unavailable they print `skipped` and pass,
so a green run on such a host did not exercise them.

## Commands

```
ext [--d <path>] [--hex] [-0] <command>
```

| Command | Effect |
|---|---|
| `init [<dir>]` | Create `<dir>/.ext/` (default: the current directory) and register `<dir>` in it. Fails if `.ext` exists. |
| `init --bare <path>` | Create a flat store at `<path>` with an empty registry. This is how `/var/lib/ext` is made. |
| `register <path>`, `-r <path>` | Add the directory (canonicalised) to the registry and scan it. Registering an already registered root re-records its filesystem identity and keeps its entries. |
| `unregister <path>`, `-u <path>` | Remove an exact registry entry and every index entry under it. |
| `resolve <digest>` | Print the paths whose last-scanned content has this digest, sorted by bytes. |
| `list` | Print every `<digest>:SHA-256<TAB><path>`, sorted by digest bytes then path bytes. |
| `check` | Scan the registered roots, hash files whose metadata changed, report differences. Accepts ordinary edits into the index. |
| `check --full` | Hash every file regardless of metadata. A digest change under unchanged metadata is a `VIOLATION`, not written. |
| `check --accept` | As `check`, but write violations into the index as the new baseline (reported `ACCEPTED`). |
| `rebuild` | Clear the index, then hash everything and accept it. |

Global options:

| Option | Effect |
|---|---|
| `--d <path>` | Use this store, or the store at `<path>/.ext`. Not valid with `init`. |
| `--hex` | Print digests as uppercase hex instead of b64ut. |
| `-0` | End records with NUL instead of newline and print paths raw (unescaped). |

Digest arguments to `resolve` must be labelled and full length: `<value>:SHA-256`
or `SHA-256:<value>`, where `<value>` is 43 b64ut characters or 64 hex
characters (either case).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK. Also: a reader closed the pipe, or the only changes were `MISSING`, `ACCEPTED`, `EXCLUDED`, `MOUNT` or `SUBEXTANT`. |
| 1 | Not found: `resolve` found no path. |
| 2 | Mismatch: `check` found an unaccepted `VIOLATION`. |
| 3 | Ambiguous. Never emitted, because truncation is not supported. |
| 4 | Usage or configuration error, including a malformed registry, an untrusted store, and a failed write. Message on stderr. |
| 5 | Not in the spec: the scan was incomplete (at least one `ERROR`, `UNSTABLE` or `REFUSED`) and found no violation. Per-file errors do not abort a scan, so a script needs a code that says coverage was partial. |

A store or database failure during a scan exits 4 even if earlier records were
printed. When both a violation and an incomplete item occur, the exit code is 2.

## Output

`check`, `register` and `rebuild` print one record per notable path on stdout:

```
<STATUS><TAB><path>[<TAB><stored digest><TAB><actual digest>][<TAB><cause>]
```

| Status | Meaning | Index |
|---|---|---|
| `NEW` | Path was not indexed. | written |
| `EDITED` | Metadata changed (or the entry was racy) and the digest differs. Both digests follow the path. | written |
| `VIOLATION` | `--full` found a different digest under unchanged, non-racy metadata. Both digests follow the path. | not written |
| `ACCEPTED` | A violation taken by `--accept`. Both digests follow the path. | written |
| `MISSING` | An indexed file is gone. | entry removed |
| `EXCLUDED` | An indexed path now lies under a sub-extant or mount. | entry removed |
| `SUBEXTANT` | A directory holding a real `.ext/` store was not entered. | unchanged |
| `MOUNT` | A directory on another mount was not entered. | unchanged |
| `UNSTABLE` | The file or directory changed while being read or opened. Cause follows. | entry removed |
| `ERROR` | A file or directory could not be read. Cause follows. | entries kept |
| `REFUSED` | A root could not be opened safely, or its filesystem identity changed. Cause follows. | entries kept |

Files that are hashed with an equal digest are not printed. A counts line
(`new=… edited=… unchanged=… skipped=… symlinks=… special=…`) goes to stderr
after every scan.

Paths are escaped on output: `\` becomes `\\`, and every byte of a control
character (C0, DEL, C1), of an invalid UTF-8 sequence, and of a Unicode bidi
control becomes `\xNN` (uppercase). Other valid UTF-8 is printed as is. The
escaping is injective, so an escaped name never collides with another path. With
`-0` paths are written raw and records end in NUL; a raw path may then contain
tabs or newlines, so split on NUL first. Causes (OS error text) are always
escaped.

## Store

A store is a directory containing `registry`, `index.db` and `lock`.

**Location**, first match wins:

1. `--d <path>`
2. `EXTANT_DIR` (empty counts as unset)
3. `/var/lib/ext`
4. `./.ext`

For steps 1 and 2 the path may be a store or a directory whose `.ext` is one. An
explicit path that is neither is an error; resolution does not fall through to a
lower step.

**Trust.** `ext` refuses a store, or its `registry`, `index.db` or `lock`, that
is not owned by the effective user or is writable by group or others. It also
refuses a store whose ancestor directories (lexically and after symlink
resolution) are owned by anyone but root or the effective user, or are
group/other-writable without the sticky bit. `init` creates the directory with
mode 0700 and the files with 0600, so `sudo ext init --bare /var/lib/ext`
produces a root-owned, root-only system store; other users get exit 4.

**Registry.** One absolute path per line, escaped as above. Blank lines and
lines starting with `#` are ignored. `//` and a trailing `/` are collapsed; `.`
and `..` segments are rejected. Duplicates are dropped. The file is replaced
atomically (temp file, fsync, rename). The registry is authoritative: every
scan first drops index entries that are not under a registered root.

**Index.** SQLite (`index.db`, WAL, schema version 1; a different version is
refused). Per file it holds path bytes, digest, size, mtime, ctime, device,
inode and the time of the last check. Writes are committed in batches of 1000
files, so an interrupted run loses at most uncommitted work and the next run
converges.

**Locking.** `register`, `unregister`, `check` and `rebuild` hold an
exclusive `flock` on `lock` for the whole run and wait for it. `resolve` and
`list` do not lock.

## Change detection

A file is skipped without hashing only if its mtime, ctime, size, device and
inode equal the stored values and the entry is not racy. An entry is racy when
`max(mtime, ctime) >= last_checked - 2 s`; `last_checked` is read before the
file's metadata. Metadata skipping is a performance heuristic. `check --full`
ignores it.

A file is hashed through an open descriptor and its metadata compared before and
after; on a change it is hashed once more, and if still changing it is
`UNSTABLE` and its entry is deleted so `resolve` cannot serve it.

## Traversal

Only regular files are hashed. Descent is relative to open directory
descriptors; symlinks are counted and never followed, and a root with a symlink
in any component is `REFUSED`. FIFOs, sockets and devices are counted and never
opened. A directory on a different mount is not entered. A directory holding a
real `.ext/` store (registry, index.db and lock present as regular files, owned
by the root's owner or root, not group/other-writable) is a sub-extant and is
not entered; any other `.ext` is ordinary content. The store being used is never
indexed. An unreadable file or directory never causes its entries to be treated
as deleted. A registered root that no longer exists reports each entry `MISSING`
and leaves the registry line.

## Known limits

- A huge or sparse file is hashed in full while the store lock is held. There is
  no size cap.
- A root's filesystem identity (`f_fsid` from `statvfs`) is recorded on first
  scan. If a later scan sees a different identity (unmounted, mounted over,
  replaced) the root is `REFUSED`, its entries are kept, and the run exits 5. If
  a filesystem's id legitimately changes (for example across reboots on some
  filesystems), run `ext register <root>` to record the new identity; entries
  are kept. Whether the id is stable on every filesystem has not been verified.
- Registered roots may be nested. A root's walk stops at another registered root,
  and each file is indexed once, by the inner root.
- `register` takes directories only. A registry entry with a symlink in any
  component is `REFUSED` at scan time.
- Hand-editing the registry while `ext register` runs can lose one of the two
  changes.
- `resolve` answers from the last scan; it does not re-read the files. A
  consumer that needs the bytes must verify them on open.
