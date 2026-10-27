# Divergences from the spec

Each entry is a place where this implementation departs from the root
[README](../README.md), or decides something it leaves open. Line numbers refer
to the root README. "PR #12" is the branch `spec/consensus-fixes`, whose spec
changes this implementation follows where noted. "Issue" is an issue in
Cyphrme/ext; "new" means no issue covers it yet.

## Index and registry

### SQLite index

- Spec (L37-L38, L40-L47): "Indexes are kept in `<extant_path>/<index_name>`"
  with text record formats for Source, Path Index, Timestamp and so on.
- Does: one SQLite file, `index.db` (WAL, schema version 1), holds a row per
  file: path bytes, algorithm, digest, size, mtime, ctime, device, inode,
  `last_checked`. Source lookup is `resolve`, the path index is the primary key,
  and the timestamp record is the metadata columns. `ext list` prints the Source
  format.
- Why: paths are arbitrary bytes and text indexes cannot hold them, lock them or
  update them atomically.
- Issue: #1.

### Escaped paths in records and the registry

- Spec (L18, L41): the registry is "a list of paths and URIs, newline
  delimited"; records are tab-separated.
- Does: a path is written as `\\` for a backslash and `\xNN` for each byte of a
  control character (C0, DEL, C1), of an invalid UTF-8 sequence, and of a Unicode
  bidi control (U+061C, U+200E-200F, U+202A-202E, U+2066-2069); everything else
  is verbatim. This applies to the registry file and to all output; `-0` prints
  raw paths instead. The registry holds absolute paths only: a relative path or
  URI is a parse error naming its line. `//` and a trailing `/` are collapsed,
  `.` and `..` segments are rejected, `#` lines and blank lines are ignored.
- Why: a name containing a tab or newline would otherwise forge or split a
  record, and bidi controls let a name reorder the terminal text around it.
- Issue: #1.

### Timestamp record

- Spec (L47, L256-L258): `<path>\t<last_checked>\t<last_modified>`, skip when
  mtime matches.
- Does: follows PR #12 instead. A path is skipped only if mtime, ctime, size,
  device and inode all equal the stored values and the entry is not racy
  (`max(mtime, ctime) >= last_checked - 2 s`, `last_checked` read before the
  file's metadata). Device is stored and compared in addition to PR #12's list.
  Timestamps are nanoseconds.
- Why: mtime alone can be set from userspace; the racy window handles coarse
  timestamps.
- Issue: PR #12 (device: new).

### Hand-edited registry

- Spec (L21): files "may be registered by `ext -r <path>` or by editing the
  registry file".
- Does: both work. The registry is authoritative: every scan first removes index
  entries not under a registered root. A hand edit racing `ext register` can lose
  one of the two changes; this is not guarded.
- Why: a lock-free read of a hand-edited file cannot be made atomic with a
  rename-based writer.
- Issue: new.

## Trust, stores and locations

### Store ownership, mode and ancestors

- Spec (L201-L210): the spec names directories but not who may own or write
  them.
- Does: `ext` refuses a store directory, or its `registry`, `index.db` or `lock`,
  that is not owned by the effective user or is group/other-writable. It also
  refuses a store whose ancestors, lexically and after symlink resolution, are
  owned by someone other than root or the effective user, or are group/other
  writable without the sticky bit. `index.db` is opened by path, so the store's
  identity is re-checked after SQLite opens it. `init` creates the store
  atomically (temp sibling, then `renameat2` without replace) with mode 0700 and
  files 0600; `sudo ext init --bare /var/lib/ext` therefore yields a root-owned,
  root-only system store, and other users get exit 4. `EXTANT_DIR` and the
  current directory are not exempted when running as root.
- Why: per issue #2's recommendation, the userspace tool runs as the invoking
  user and indexes what that user can read; a store the user does not own or
  that others can write cannot vouch for anything.
- Issue: #2. The elevated-privilege rule ("ignore `EXTANT_DIR` and the current
  directory") is not implemented; it is new.

### Store lookup order and `./.ext/`

- Spec (L205-L210): "Use the first candidate that exists": environment
  variable, default path, flag value, current directory.
- Does: flag (`--d`), `EXTANT_DIR` (empty counts as unset), `/var/lib/ext`,
  then `./.ext`, as PR #12 orders them. A flag or environment path may be a store
  or a directory whose `.ext` is a store; if it is neither, that is an error and
  lookup does not fall through. A candidate "exists" only if `registry` and
  `index.db` are regular files in it. The current-directory step looks for
  `./.ext`, not `./`.
- Why: an explicit choice must not be silently overridden, and store files are
  kept out of the content directory (see sub-extants).
- Issue: PR #12 for the order; `./.ext` is #13.

### `--d`

- Spec (L223, L246): `ext --d <path>` "Specifies the working directory for
  `ext`".
- Does: `--d` names the store (or a directory whose `.ext` is a store). It is
  rejected by `init`, which takes its location as an argument.
- Why: the store must be locatable before any config could be read, and there is
  no other working-directory notion to set.
- Issue: new.

### Config file not created

- Spec (L212-L224): flags saved in `<extant_path>/config`: Aware, Base64, Hex,
  DefaultEnc, IndexEnc, Truncation, Unlabeled, Directory, Hash.
- Does: no config file is read or written. The behaviour is fixed: SHA-256,
  b64ut default output, hex and b64ut input, labelled digests only, no
  truncation.
- Why: every flag either selects something v1 does not implement or has an open
  question (#6, #10).
- Issue: #10, #6.

### `init` layout

- Spec (L227): "`ext init <path>` - Create a `ext` directory with a new
  registry."
- Does: `ext init [dir]` creates `<dir>/.ext/` (`registry`, `index.db`, `lock`)
  and registers `<dir>`; it fails if `.ext` exists and never overwrites a store.
  `ext init --bare <path>` creates a flat store at `<path>` with an empty
  registry. The `--bare` spelling follows `git init --bare`.
- Why: a store inside `.ext/` keeps store files out of the content; a flat store
  is what `/var/lib/ext` needs.
- Issue: #10, #13.

## External services, names, algorithms

### External services and cache deferred

- Spec (L28-L34, L79-L90, L186-L198): registering URIs, external lookup, the LRU
  cache.
- Does: none of it. A URI given to `register` fails (it is not a directory); a
  URI in the registry file is a parse error. There are no Cache or Cache Time
  indexes.
- Why: the spec has no verify-before-use rule or request protocol yet.
- Issue: #3.

### `hash://` is not parsed

- Spec (L92-L125): the `hash://alg:digest[tail]` URI and its parsing rules.
- Does: `resolve` accepts a bare labelled digest only. A `hash://` argument is
  rejected (it contains more than one colon). `tail` is not recognised.
- Why: the URI is not valid RFC 3986 as written and its parsing rules are being
  revised.
- Issue: #4.

### Digest parsing

- Spec (L55, L68, L119, L125, L159): reverse form `<digest>:<alg>`; "Even-length
  `0-9A-F` is hex. Otherwise strict b64ut"; SHA-256 "is 32 bytes, 43 b64ut chars,
  or 64 uppercase hex chars"; hex "lower, upper, and mixed case".
- Does: input must be labelled, in either order (`<value>:SHA-256` or
  `SHA-256:<value>`); the algorithm name is exact and case-sensitive. The
  encoding is chosen by length alone: 43 characters is b64ut, 64 is hex; any
  other length is an error. Hex input is accepted in any case. b64ut must be
  canonical (the unused low bits of the last character are zero), with no `=`.
  Output is b64ut, or uppercase hex with `--hex`, always as `<value>:<alg>`.
  There is no whitespace trimming.
- Why: choosing by length means a value cannot be read two ways, and accepting
  both orders costs nothing because an algorithm name is never a valid value.
- Issue: #5.

### Truncation, AMBIGUOUS and COLLISION

- Spec (L162-L184, L284-L285): truncated digests, `AMBIGUOUS` output, errors
  `AMBIGUOUS` and `COLLISION`.
- Does: truncated digests are a length error. `resolve` returns every path with
  the full digest. Neither error is produced and exit code 3, which #10 proposed
  for ambiguity, is unused.
- Why: no truncation, so no ambiguity; `ext` does not hold two byte strings for
  one digest, so it cannot detect a collision.
- Issue: #5.

### SHA-256 only; `Aware` and `Unlabeled`

- Spec (L216, L222, L224, L296-L306): configurable algorithms, `Aware`,
  `Unlabeled`.
- Does: SHA-256 is the only algorithm and every digest carries its label.
  `Unlabeled` and `Aware` are not implemented. The algorithm column is stored so
  more algorithms can be added without changing the index key.
- Why: no algorithm table exists in the spec, and an unlabelled digest lowers
  the security floor.
- Issue: #6.

### Human names and tags deferred

- Spec (L44, L61-L77): human names, ergonomic naming, the Tag index.
- Does: not implemented; no command sets or reads a name or tag.
- Why: there is no grammar or storage rule for names.
- Issue: #7.

## Sub-extants and traversal

### Sub-extants as `<dir>/.ext/`

- Spec (L23-L26, L293-L294): sub-extants keep their registries "in
  `<sub-extant_path>/registry`", "may be registered to a parent extant";
  "Recursion is not supported. If an ext path contains another ext, it is
  ignored."
- Does: a sub-extant's store is `<dir>/.ext/`. A directory containing a real
  store there is not entered by any parent walk; it is reported `SUBEXTANT`, and
  entries previously indexed beneath it are reported `EXCLUDED` and removed. A
  `.ext` counts as a real store only if `registry`, `index.db` and `lock` are
  regular files, owned by the registered root's owner or by root, and not
  group/other-writable; any other `.ext` is ordinary content and is indexed. A
  sub-extant works standalone (`ext init <dir>`, then `ext --d <dir> ...`). The
  store of the extant being run is always excluded from its own walk, and its own
  root is not treated as a sub-extant of itself.
- Why: a bare `registry` file is too generic a marker, and a store inside the
  content would index itself. Requiring a real store stops a planted `.ext` from
  hiding a subtree.
- Issue: #8, #13.

### Sub-extant linking not implemented

- Spec (L26): "Sub-extants may be registered to a parent extant."
- Does: there is no linking. A parent never reads a child's index and does not
  hash a child's files.
- Why: what a parent may trust from a child is undecided.
- Issue: #13.

### Traversal rules

- Spec (L19, L230-L233): the example registers `/`; nothing says what is hashed.
- Does:
  - Only regular files are hashed. Symlinks and special files are counted and
    never opened.
  - Descent uses `openat2`/`openat` relative to open directory descriptors with
    `O_NOFOLLOW`; a registered root with a symlink in any component is
    `REFUSED`. Regular files are opened `O_NONBLOCK`, and their type and
    (device, inode) are re-checked on the descriptor; a mismatch is `UNSTABLE`.
  - A directory on a different mount (by mount id, or `st_dev` where the kernel
    lacks mount ids) is reported `MOUNT` and not entered.
  - The walk is iterative, so tree depth is bounded by memory, not by stack or
    descriptors.
  - Metadata is compared before and after hashing; one retry, then `UNSTABLE`
    and the entry is deleted.
  - Per-file errors are reported and the scan continues; the exit code is 5.
  - Registered roots that contain other registered roots: the outer walk stops at
    the inner root.
- Why: these are the proposals in issue #9, with the symlink policy decided as
  "count and skip".
- Issue: #9 (nested registered roots: new).

### Unreadable is never treated as deleted

- Spec (L232-L233): "Deleting a directory also unregisters."
- Does: an entry is reported `MISSING` and removed only when the walk did not see
  the file and a descriptor-relative check confirms it is no longer a regular
  file. A file or directory that cannot be read or listed keeps its entries
  (`ERROR`, exit 5); a refused root keeps its entries (`REFUSED`). A deleted
  registered root reports each entry `MISSING` but its registry line stays; there
  is no automatic unregistration.
- Why: a permission error or an unmounted filesystem must not wipe the index.
- Issue: #9.

### Root filesystem identity and `REFUSED`

- Spec: none (nothing says what happens when a registered root is an unmounted
  mount point).
- Does: the first scan of a root records its filesystem id (`f_fsid` from
  `statvfs`). A later scan that sees a different id reports `REFUSED`, keeps the
  entries and exits 5. `ext register <root>` on an already registered root
  records the current id and keeps its entries; `unregister` forgets it.
  Whether `f_fsid` is stable across reboots on every filesystem is unverified.
- Why: an empty mount point looks like a tree whose files were all deleted.
- Issue: new.

## Commands

### `check`

- Spec (L239-L244): "`ext check`, `ext -check` - Re-hash all files and compare
  digests. Skip unchanged paths."; "`ext check --full` - ... does not skip
  unchanged paths"; "`ext -rerun` - Rebuild all indexes and re-hash all files."
- Does: one `check` command. A file whose metadata changed and whose digest
  differs is `EDITED`, reported with both digests, and the index is updated. With
  `--full`, a digest change under unchanged, non-racy metadata is a `VIOLATION`
  (exit 2) and the index entry is not written. `--accept` writes violations as
  the new baseline and reports them `ACCEPTED` (exit 0). `rebuild` replaces
  `-rerun`: it clears the index and re-hashes, accepting everything. The
  `-check` and `-rerun` spellings are not accepted. There is no `update`
  command.
- Why: a tampering that preserves metadata is distinguishable from an edit
  only by `--full`, and it must not be absorbed silently.
- Issue: #10.

### Exit codes

- Spec: none.
- Does: 0 success; 1 `resolve` found nothing; 2 an unaccepted violation; 4
  usage, configuration or store error; 5 scan incomplete (`ERROR`, `UNSTABLE` or
  `REFUSED`). 3 is unused. Violation outranks incomplete; any exit 4 outranks
  both. `MISSING`, `EXCLUDED`, `MOUNT`, `SUBEXTANT` and `ACCEPTED` exit 0. A
  closed output pipe is a quiet stop: `list` and `resolve` exit 0, `check`,
  `register` and `rebuild` exit with the scan's code. Command-line usage errors
  exit 4, not the parser's default of 2.
- Why: #10 asks for a table; 5 is added because per-file errors no longer abort a
  scan, and a script must tell that coverage was partial.
- Issue: #10 (code 5: new).

### Flag forms

- Spec (L230-L246): `ext register`,`ext -r`; `ext unregister`, `ext -u`;
  `ext --d <path>`; `-check`, `-rerun`.
- Does: subcommands, with `-r` and `-u` as short forms of `register` and
  `unregister`; global long options `--d`, `--hex`, and a global `-0`.
  `check` takes `--full` and `--accept`.
- Why: consistent GNU-style syntax, as #10 proposes.
- Issue: #10.

### `register` and `unregister` arguments

- Spec (L230, L232): register "Supports both files and directories";
  unregister removes "all references in indexing".
- Does: `register` accepts directories only, canonicalises the path, adds it and
  scans that root. `unregister` needs a path that exactly matches a registry
  entry (exit 4 otherwise) and removes the entry and all index entries under it.
- Why: the walk is rooted at directories; an exact match avoids removing a
  parent by accident.
- Issue: new.

### Not implemented

- `ext watch` and the watcher (L248, L270-L276): no watcher; every run is a
  metadata scan. Issue: new.
- `/dev/ext` (L127-L156): out of scope for the userspace tool.
- Concurrency: writing commands hold an exclusive lock on the store's `lock` file
  for the whole run and wait for it; `resolve` and `list` do not lock. The spec
  says nothing about this. Issue: #1.
