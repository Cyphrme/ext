# Divergences from the spec

This lists where the implementation departs from the spec, or decides
something the spec leaves open. It is written against `README.md` as changed by
PR #12 (branch `spec/consensus-fixes`, commit 4cdcefd, with `docs/traversal.md`),
which records a decision on every issue #1-#10 and #13. The spec is cited by
section name, since line numbers move. "Issue" is an issue in Cyphrme/ext;
"new" means no issue covers the point. Each entry carries one status:

- **follows**: the code does what the spec text says. The entry only records
  details the spec leaves to the implementation.
- **differs**: the spec decides the point and the code does something else.
  The entry says how, and why, and is one of two kinds:
  - *implementation choice*: non-normative; the spec leaves the point to the
    implementer, or the code is stricter or richer than the spec, and no other
    implementation, exported file or script written to the spec would observe
    the difference.
  - *interface difference*: another implementation, an exported file or a
    script would observe it. These should be raised with the spec author.
- **deferred**: the spec describes it and v1 does not implement it.
- **open**: the spec leaves the point undecided; the entry names the question.
  No entry is open at 4cdcefd.

Behaviour the spec now states and this implementation follows: the store is
never indexed (README, Extant Registry and Index paths); a per-file read error is reported and does not abort the
scan (README, Extant Registry and Index paths); external service URIs are not stored in the indexes (README, External Service Registration; a URI in
the registry is a parse error); directory precedence flag, `EXTANT_DIR`,
`/var/lib/ext`, current directory, and an explicit path that is missing is an
error (README, Directories); `-r` and `-u` aliases (README, Commands); the timestamp index and racy
rule (README, Incrementality), with the differences below; sub-extants are not recursed
into unless registered (README, Technical Considerations: Recursion).

## Index and registry

### SQLite index with TSV export and import (differs: implementation choice, #1)

- Spec: README, Extant Registry and Index paths, "Indexes are kept in `<extant_path>/<index_name>`", with the text
  record formats under File Formats and the TSV rule there (records sorted by the raw bytes
  of the first field). The author prefers a defined flat-file format that is
  exportable and importable, and does not want a relational database coupled to
  the design (acceptable "as a simple store").
- Does: one SQLite file, `index.db` (WAL, schema version 1), as the live store.
  `ext export <dir>` writes `registry`, `source` and `timestamp` as TSV;
  `ext import <dir>` loads them into a store whose index is empty (exit 4
  otherwise). The Path Index, Tag, Cache and Cache Time files do not exist, and
  the file names `source` and `timestamp` are this implementation's choice.
  The index file is not itself a TSV file, so the spec's "index file replaced
  atomically by rename" holds for the registry and the export files only; SQLite
  provides its own atomicity.
- Sort order: by the unescaped bytes of the first field. For `source` and for
  `ext list` that field is the text `<value>:SHA-256` as printed (b64ut, or hex
  with `--hex`), with the path breaking ties; this is not the order of the
  digest bytes.
- `export` holds the store's write lock while it reads, so the registry and the
  index come from one moment. It therefore waits behind a running writer.
- Import writes the index rows in one transaction and swaps the registry before
  it commits; if the commit itself fails after the swap, the registry is the
  imported one and the index is empty. Rerunning the import is safe.
- Why: lookup by digest and by path, atomic updates and safe concurrent writers
  come from one file, and the export gives the portable form.
- Kind: the export files use the spec's record formats, so the portable form
  conforms. A second implementation reading this store directory in place would
  find `index.db` rather than TSV index files; it must go through `export`.
  The file names `source` and `timestamp` and the `export`/`import` commands
  are this code's.

### Escaped paths (follows, #1)

- Spec: README, File Formats: "a backslash, tab, or newline in a field is escaped as `\\`,
  `\t`, or `\n`", unescaping per Cyphrme/TSV.
- Does: the registry file, `list`, `resolve`, reports and the export files use
  exactly those three escapes; everything else, including control characters,
  invalid UTF-8 and bidi controls, is verbatim. Unescaping is one left-to-right
  pass over backslash pairs; any other pair or a trailing backslash is an error
  (the Cyphrme/TSV README's replace-in-turn wording is not followed because it
  mis-decodes `\\t`). `-0` prints raw paths with NUL-terminated records. The
  registry holds absolute paths only; a relative path or URI is a parse error
  naming its line. `//` and a trailing `/` are collapsed, `.` and `..` segments
  are rejected, `#` and blank lines are ignored.
- Consequence: text output can carry terminal control sequences from file
  names. The earlier `\xNN` scheme prevented that; it was dropped to follow TSV.

### Timestamp record (follows; directory records deferred)

- Spec: README, File Formats: `<path>\t<last_checked>\t<mtime>\t<ctime>\t<size>\t<inode>\t<dev>`;
  Incrementality: skip rule, and the option that disables the ctime, inode and
  dev comparisons.
- Does: the same skip and racy rules (`max(mtime, ctime) >= last_checked - 2 s`,
  `last_checked` read before the file's metadata). `export` writes `<dev>` as
  the seventh, trailing field; times are integer nanoseconds. The config key
  `CompareCtimeInode` (default true) false compares only size and mtime, and
  the racy rule still reads the stored ctime.
  Directory records (Incrementality, Directories, "may also be recorded") are
  deferred; every file is examined by the rule above.
- Why: an inode number is only meaningful with its device.

### Hand-edited registry (follows)

- Spec: README, Registration: "or by editing the registry file".
- Does: supported. The registry is authoritative: each scan first removes index
  entries not under a registered root. A hand edit racing `ext register` can
  lose one of the two changes; this is not guarded.

## Trust, stores and locations

### Store ownership, mode and ancestors (differs: implementation choice, #2)

- Spec: README, Trust: a store "must be owned by the user running `ext`", and
  `ext` refuses any other; a system-wide store serving other users is future
  work. Mode, ancestors and `init` permissions are not specified.
- Does: refuses a store directory, or its `registry`, `index.db` or `lock`, that
  is not owned by the effective user (the spec's rule) or is group/other-writable
  (an addition). Also refuses a
  store whose ancestors, lexically and after symlink resolution, are owned by
  anyone but root or the effective user, or are group/other-writable without the
  sticky bit. `init` creates the store atomically with mode 0700 and files 0600,
  so `sudo ext init --bare /var/lib/ext` yields a root-owned, root-only system
  store and other users get exit 4. With elevated privilege (AT_SECURE, effective uid 0, or
  an effective uid or gid differing from the real one) `EXTANT_DIR` and the
  current directory are not consulted, as the spec's Trust section says; `--d`
  still is.
- Why: a store the user does not own, or that others can write, cannot vouch for
  anything.

### Current-directory step is `./.ext` (follows, #13)

- Spec: README, Directories: "4. Current directory: its `.ext/` store".
- Does: the same. A candidate exists only if `registry`, `index.db` and `lock`
  are regular files in it. Once `/var/lib/ext` is a store, a non-root user
  without `--d` or `EXTANT_DIR` reaches it first and gets exit 4 (foreign
  owner), even with `./.ext` present; that follows from the specced order.

### `--d` names the store (differs: implementation choice)

- Spec: README, Directories and Commands: "`ext --d <path>` - Specifies the working directory".
- Does: `--d` names the store, or a directory whose `.ext` is a store. `init`
  rejects it and takes its location as an argument.
- Why: the store must be located before anything else, and there is no other
  working-directory notion to set.

### Config file (deferred except four keys, #10)

- Spec: README, Config Flags: "The config file is saved as <extant_path>/config. Its format
  is JSON5." with the flags Aware, Base64, Hex, DefaultEnc, IndexEnc, Truncation,
  Unlabeled, Directory, Hash; Incrementality: "A configuration option may disable the
  ctime and inode comparisons"; the traversal document's "a config option
  disables" unregistering a deleted root.
- Does: reads `<store>/config` (JSON5, optional) with the registry's ownership
  and mode checks. Honoured: `Base64` and `Hex` (false refuses that encoding as
  `resolve` input), `DefaultEnc` (`B64` or `Hex`; `--hex` overrides),
  `CompareCtimeInode` and `UnregisterDeleted` (both default true). Every other key (`Aware`, `IndexEnc`,
  `Truncation`, `Unlabeled`, `Directory`, `Hash`) is accepted only at the value
  the code already behaves as; any other value, and any unknown key, is
  exit 4 naming the key. `Directory` is not a working-directory setting here.
- Why: a key that is accepted and ignored would let an operator believe a policy
  is in force.

### `init` layout (differs: implementation choice, #13)

- Spec: README, Commands: "Create a `ext` directory with a new registry. If no
  path is specified CWD is used."; Subdirectory Registration puts a store in
  `<dir>/.ext/`.
- Does: `ext init [dir]` creates `<dir>/.ext/` as specced, with `index.db` and
  `lock` beside the `registry`, and registers `<dir>` in it (the spec's "new
  registry" does not say whether it starts empty); it fails if `.ext` exists and
  never overwrites a store.
  `ext init --bare <path>` creates a flat store at `<path>` with an empty
  registry (how `/var/lib/ext` is made), after `git init --bare`.
- Why: a store in `.ext/` keeps store files out of the content; `/var/lib/ext`
  needs the flat form.

## External services, names, algorithms

### External services and cache (follows, #3)

- Spec: `docs/services.md` (ES-1 to ES-33), branch `spec/external-services`.
- Does: the `https` backend, the cache and the services file as specified.
  The choices below are ones the spec leaves to the implementation.

### Read-only index open (follows: implementation choice)

- Spec: ES-25, "a `resolve` answered from the local index MUST succeed" on a
  read-only store; the spec does not say how the index is read there.
- Does: on a store the effective user cannot write, the index is opened
  `mode=ro`, which reads `index.db-wal`. If that fails (no `-shm`, which a
  read-only directory cannot gain) and the WAL holds data, the lookup stops
  with exit 5 naming the index. Only with no WAL content does it fall back to
  SQLite `immutable`. An initialised index missing its `files` table is also
  exit 5; a missing table reads as empty only in an index never written.
- Why: committed rows may exist only in the WAL (a crash, or a live store made
  read-only); reading past them would answer "absent" for an indexed file.

### Address allow-list (differs: implementation choice)

- Spec: ES-15, the IANA special-purpose registries "minus every block ...
  whose Globally Reachable value is False".
- Does: a block marked False is denied whole, including smaller blocks inside
  it that the registry marks True (192.0.0.9/32, 192.0.0.10/32, the reachable
  parts of 2001::/23).
- Why: those are anycast and protocol assignments no blob service uses, and
  denying too much is the safe direction.

### Redirect Locations that only look like a scheme (differs: implementation choice)

- Spec: ES-14, a `Location` "is resolved against the current URL" and must
  satisfy the services grammar; it does not say what counts as a scheme.
- Does: a `Location` is absolute only if the text before its first `:` is a
  valid scheme (a letter, then letters, digits, `+`, `-`, `.`). Otherwise it is
  a relative reference: `9:x` and `a_b:c` resolve to the paths `/9:x` and
  `/a_b:c`. A valid scheme other than `http` or `https` is an Error.
- Why: this is how the WHATWG URL parser reads such text, and RFC 3986 gives
  the same reading since a scheme cannot start with a digit or contain `_`.

### `resolve` with a file name (follows: implementation choice)

- Spec: ES-1 orders the layers and says nothing of names; README, Human
  names, makes a name a filter on the returned paths.
- Does: a query with a name is answered by the index alone; the cache and the
  services are not consulted.
- Why: cache paths and services carry no file names to match.

### Hash URI (follows, #4)

- Spec: README, Scheme and URI API, `hash://<alg>/<digest>[tail]`, `alg` matched
  case-insensitively, tail ignored.
- Does: `resolve` accepts it. The scheme and `alg` match in any case, the digest
  is case-sensitive, and the tail starts at the first non-b64ut character. The
  digest must be full length (43 b64ut or 64 hex characters, so a b64ut run that
  continues past either length is an error). Only `resolve` takes it; no command
  prints one.

### Digest input and output (follows, #5)

- Spec: README, Hash Storage: reverse form `<digest>:<alg>`; Human Naming: the name forms; Hash Scheme Grammar:
  encoding decided by length; Bases: hex in any case. The spec decides the
  encoding by the algorithm's digest size.
- Does: `resolve` input must be labelled, in either order (`<value>:SHA-256` or
  `SHA-256:<value>`). Outside `hash://` the algorithm name is exact and
  case-sensitive: the spec lowercases case only for the URI authority, so
  `sha-256:<value>` is an error. The encoding is chosen by length alone (43 is
  b64ut, 64 is hex), any other length is an error. Hex input is accepted in any
  case; b64ut must be canonical (unused trailing bits zero) with no `=`. Output is
  b64ut, or uppercase hex with `--hex`, always as `<value>:<alg>`. No whitespace
  is trimmed.
- Why: choosing by length means a value cannot be read two ways; an algorithm
  name is never a valid value, so both orders are unambiguous.

### Truncation, AMBIGUOUS, COLLISION (deferred, #5)

- Spec: README, Bases and Truncation and Collision (truncation "supported but disabled by default"), Technical Considerations.
- Does: truncated digests are a length error. `resolve` returns every path with
  the full digest. `AMBIGUOUS` and `COLLISION` are never produced; `ext` does not
  hold two byte strings for one digest, so it cannot detect a collision.

### SHA-256 only; `Aware` and `Unlabeled` (deferred, #6)

- Spec: README, Coz: a client may support a subset of algorithms, and a label
  naming an unsupported one "is rejected, not treated as unlabeled"; Config
  Flags and Technical Considerations (Digest Labeling) for `Aware` and
  `Unlabeled`.
- Does: SHA-256 is the only algorithm (the Coz rule, followed); a label naming
  any other algorithm is rejected. Every digest must carry its label, which is
  the spec's default (`Unlabeled` false); the option itself is not implemented.
  The algorithm is stored per row so others can be added.

### Human names (follows; tags deferred, #7)

- Spec: README, Human Naming. The name is the file's name, extension included when present;
  it must equal the last component of a path with the digest, and one match among
  several paths suffices. Tags are TODO.
- Does: `resolve` accepts `<alg>:<value>:<name>`, `<value>:<alg>:<name>`,
  `<name>:<alg>:<value>` and `<name>:<alg>:<value>.<ext>` (filename
  `<name>.<ext>`). Only paths whose last component equals the filename, compared
  as bytes and case-sensitively, are printed; none is exit 1. Names may contain
  `:`. The label and the fixed-length digest beside it are located first. In the
  name-first forms the rightmost label wins, since the digest ends the argument;
  the prefix forms are tried before it. A name must be non-empty and contain no
  `/`; an empty `.<ext>` is an error. The name is taken from the command-line
  argument, which must be valid UTF-8. Tags are not implemented, and the index
  does not store names (the name is the path's last component).

## Sub-extants and traversal

### Sub-extant marker (follows, #8, #13)

- Spec: README, Subdirectory Registration: a sub-extant keeps its store in
  `<dir>/.ext/`; it is a sub-extant "only if its `.ext/` is a directory
  containing a registry, both owned by the owner of the parent's registered root
  or by root"; any other `.ext` is ordinary content. Technical Considerations
  (Recursion): a parent's scan skips sub-extants.
- Does: the same. A directory whose `.ext` is a directory holding a `registry`
  regular file, both owned by the registered root's owner or root, is not
  entered by a parent walk, unless it is itself a registered root (see
  "Sub-extant linking"), and is reported `SUBEXTANT`; entries previously indexed
  beneath it are reported `EXCLUDED` and removed. `index.db` and `lock` are not
  required, since another implementation's store need not have them. Added
  hardening: the `.ext` directory and its `registry` must not be
  group/other-writable, so a `.ext` with a group-writable registry is indexed as
  ordinary content here although the spec's rule would skip it. A sub-extant
  works standalone (`ext init <dir>`, then `ext --d <dir> ...`). The store in
  use is never indexed, and its own root is not a sub-extant of itself.
- Why: a store in the content would index itself, and a planted `.ext` must not
  hide a subtree; the ownership check is what stops that.

### Sub-extant linking (follows, #13)

- Spec: README, Subdirectory Registration and Technical Considerations
  (Recursion): registering a sub-extant to the parent includes it; the parent
  hashes the files itself and does not read the sub-extant's index.
- Does: that, and nothing more. `ext register <sub>` in the parent scans
  `<sub>`'s files (checked by a run: a file in a sub-extant appears in the
  parent's `list` only after the registration); the sub-extant's own `.ext/` is
  never indexed. Copy and reference modes are not implemented.

### Traversal (follows, #9)

- Spec: README, Registration (`/` and `/srv/www` as examples) and `docs/traversal.md`
  (file types, mounts, read errors). Race handling is an implementation detail.
  The bullets below are the parts the spec leaves to the implementation, plus
  the spec's rules for reference.
- Does:
  - `/`, or any directory, can be registered. Only regular files are hashed;
    symlinks and special files are counted and never opened.
  - Descent uses `openat2`/`openat` relative to open directory descriptors with
    `O_NOFOLLOW`; a registered root with a symlink in any component is
    `REFUSED`. Regular files are opened `O_NONBLOCK` and their type and
    (device, inode) re-checked on the descriptor; a mismatch is `UNSTABLE`.
  - Metadata is compared before and after hashing; one retry, then `UNSTABLE`
    and the entry is deleted.
  - Other mounted filesystems are entered (the boundary is judged by mount id,
    or `st_dev` where the kernel lacks mount ids, against the directory's
    parent), so `/` covers the system. A mount whose `statfs` type is one of the
    virtual types in `docs/traversal.md` is reported `MOUNT` and not entered; a
    registered root on such a filesystem is walked. The type list is
    `src/vfs.rs`; configfs, fusectl and mqueue are not in linux/magic.h and
    their values come from the kernel. A bind mount is entered at each place it
    is mounted, so its files are indexed under each path.
  - The walk is iterative; depth costs memory, not stack or descriptors.
  - Nested registered roots: the outer walk stops at the inner root.

### Deleted roots and unreadable paths (follows)

- Spec: README, Commands: "Unregister, removing all references in indexing. (Deleting a
  directory also unregisters.)"; `docs/traversal.md` "Deleted roots".
- Does: a registered root that no longer opens (ENOENT) is compared with its
  nearest existing ancestor. If that ancestor is on the filesystem recorded for
  the root (`f_fsid` from `statvfs`, recorded on first scan) the root is
  *deleted*: each entry is reported `MISSING` and removed, the root is
  unregistered, and `DELETED` is printed (exit 0). With config
  `UnregisterDeleted` false only `DELETED` is printed and nothing changes. If
  the ancestor is on another filesystem, or the ancestor cannot be examined, or
  no filesystem was recorded for the root, it is a missing mount: `REFUSED`,
  entries and registration kept, exit 5. A root that exists but whose filesystem
  differs from the record is `REFUSED` in the same way. `ext register <root>`
  on a registered root records the current identity and keeps its entries;
  `unregister` forgets it.
- An entry is `MISSING` only when the walk did not see the file and a
  descriptor-relative check confirms it is no longer a regular file. A file or
  directory that cannot be read or listed keeps its entries (`ERROR`, exit 5).
- Not decided by the spec: a root with no recorded identity (a hand-edited
  registry line never scanned) is treated as a missing mount, the safe side.
  `f_fsid` on btrfs includes the subvolume, so a deleted subvolume root also
  reads as a missing mount. Stability of `f_fsid` across reboots on every
  filesystem is unverified.
- Why: an unmounted disk looks like a deleted tree; wiping its baseline on that
  evidence loses data.

## Commands

### `register` and `unregister` arguments (follows)

- Spec: README, Commands: `register` "Supports both files and directories";
  URIs are covered under External services.
- Does: `register` accepts a directory or a regular file (anything else, a
  FIFO or device, is exit 4), canonicalises the path, adds it and scans that
  root. A file root is a single entry: hashed, checked, and judged deleted or a
  missing mount like a directory root, with its parent as the nearest ancestor.
  A registry entry that is a symlink or a special file is `REFUSED` at scan time
  and never opened. So is a root that is the store in use or lies inside it, or
  lies inside a sub-extant's store (decided by device and inode of each
  directory on the path); `register` rejects these with exit 4. A refused root
  keeps whatever entries it already had, and none are created for it. `unregister` needs a path that exactly matches a registry
  entry (exit 4 otherwise) and removes the entry and all index entries under it.
- Why: exact matching avoids removing a parent by accident.

### `check` and `rebuild` (follows, #10)

- Spec: README, Commands: `ext check`, `ext check --full`, `ext check --accept`,
  `ext rebuild` ("Rebuild all indexes and re-hash all files"). A digest change under unchanged metadata is a violation: reported,
  index not updated, exit 2.
- Follows: `check`, `check --full` (violation, exit 2, not written) and
  `check --accept` (writes the new digests, reported `ACCEPTED`, exit 0). A file
  whose metadata changed and whose digest differs is `EDITED`, reported with
  both digests, and the index is updated.
- `rebuild` clears the index, re-hashes, and accepts everything. The earlier
  spellings `-check` and `-rerun` are not accepted (exit 4, checked by a run).
- Why: tampering that preserves metadata is distinguishable from an edit only by
  `--full`, and must not be absorbed silently.

### Exit codes (follows, #10)

- Spec: README, Exit codes: 0 OK, 1 not found, 2 mismatch (`check`), 3 ambiguous, 4 usage
  or configuration error, 5 incomplete (a mismatch takes precedence).
- Does: 0, 1 (`resolve` found nothing), 2 (an unaccepted violation, the
  mismatch) and 4 (usage, configuration or store error, including the argument
  parser's own errors) as specced. 3 is never emitted: ambiguity needs
  truncation, which is off (conformant). 5, in the spec as "Incomplete", is a scan that was incomplete
  (`ERROR`, `UNSTABLE` or `REFUSED`) and no violation was found. A violation
  outranks an incomplete scan; a store or database failure during a scan exits 4.
  `MISSING`, `DELETED`, `EXCLUDED`, `MOUNT`, `SUBEXTANT` and `ACCEPTED` exit 0. A closed
  output pipe is a quiet stop: `list` and `resolve` exit 0; `check`, `register`
  and `rebuild` exit with the scan's code.
- Why: per-file errors do not abort a scan (README, Extant Registry and Index paths), so a script needs a code that
  says coverage was partial; reusing 2 would conflate it with tampering.

### Flags and commands the spec lacks (differs: implementation choice)

- Spec: README, Commands lists `-r`, `-u`, `--d`, `check --full` and
  `check --accept`, `rebuild`; these are implemented as specced (`-r`/`-u` as short names
  of `register`/`unregister`).
- Does, beyond the spec: global `--hex` (the spec fixes hex output as
  uppercase but names no flag), global `-0`, `init --bare`,
  and `export` and `import` (see the SQLite entry).

### Not implemented (deferred)

- `ext watch` and the watcher (README, Commands and Incrementality: Watcher):
  every run is a metadata scan. The spec says the watcher is not required for
  correctness. Issue: new.
- `/dev/ext` (README, System Integrated Extant): the spec marks it a later TODO.

### Locking (follows, #1)

- Spec: README, Extant Registry and Index paths: a writing process holds an
  exclusive lock on `<extant_path>/lock` for its whole run; readers take no lock.
- Does: `register`, `unregister`, `check`, `rebuild` and `import` hold it for the
  whole run and wait for it; `resolve` and `list` do not lock. `export` also
  takes it, although it only reads, so the registry and the index come from one
  moment.
