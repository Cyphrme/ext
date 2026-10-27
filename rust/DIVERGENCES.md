# Divergences from the spec

This lists where the implementation departs from the spec, or decides something
the spec leaves open. It is written against `README.md` as changed by PR #12
(branch `spec/consensus-fixes`, commit bb9a46f), which records the decisions
reached on issues #1-#10. Line numbers refer to that file. "Issue" is an issue
in Cyphrme/ext; "new" means no issue covers the point yet. Status is one of:

- **open**: the issue is still under discussion with the spec author.
- **agreed**: the author agreed to the direction in the issue; the spec text
  does not cover it.
- **deferred**: not implemented in v1.

Behaviour the spec now states and this implementation follows: the store is
never indexed (L41); a per-file read error is reported and does not abort the
scan (L42); external service URIs are not stored in the indexes (L53; a URI in
the registry is a parse error); directory precedence flag, `EXTANT_DIR`,
`/var/lib/ext`, current directory, and an explicit path that is missing is an
error (L224-L229); `-r` and `-u` aliases (L269); the timestamp index and racy
rule (L285-L313), with the differences below; sub-extants are not recursed
into (L357).

## Index and registry

### SQLite index; no export/import (open, #1)

- Spec: L38 "Indexes are kept in `<extant_path>/<index_name>`", with the text
  record formats at L44-L51. The author prefers a defined flat-file format that
  is exportable and importable, and does not want a relational database coupled
  to the design (acceptable "as a simple store").
- Does: one SQLite file, `index.db` (WAL, schema version 1). `ext list` prints
  the Source format (`<digest>:<alg><TAB><path>`) sorted by raw bytes, digest
  then path; nothing reads that format back, and the Path Index, Tag, Cache and
  Cache Time files do not exist.
- Why: lookup by digest and by path, atomic updates and safe concurrent writers
  come from one file.

### Escaped paths (open, #1)

- Spec: L18 "a list of paths and URIs, newline delimited"; records are
  tab-separated (L45-L51). The author asked for prior art on path escaping and
  is unsure the spec is the place for the rule.
- Does: in the registry file and in all output, `\` is written `\\`, and each
  byte of a control character (C0, DEL, C1), of an invalid UTF-8 sequence, and
  of a Unicode bidi control (U+061C, U+200E-200F, U+202A-202E, U+2066-2069) is
  written `\xNN` (uppercase); everything else is verbatim. `-0` prints raw paths
  with NUL-terminated records. The registry holds absolute paths only; a
  relative path or URI is a parse error naming its line. `//` and a trailing `/`
  are collapsed, `.` and `..` segments are rejected, `#` and blank lines are
  ignored.
- Why: a name with a tab or newline would otherwise forge or split a record, and
  bidi controls let a name reorder the terminal text around it.

### Timestamp record (follows the spec, two differences; new)

- Spec: L51 `<path>\t<last_checked>\t<mtime>\t<ctime>\t<size>\t<inode>`; L294
  skip rule; L301-L303 "A configuration option may disable the ctime and inode
  comparisons".
- Does: the same skip and racy rules (`max(mtime, ctime) >= last_checked - 2 s`,
  `last_checked` read before the file's metadata). It also stores and compares
  the device number, and it has no option to disable the ctime or inode
  comparison because there is no config file. Directory records (L317-L322) are
  not implemented; every file is examined by the rule above.
- Why: an inode number is only meaningful with its device.

### Hand-edited registry (new)

- Spec: L22 "or by editing the registry file".
- Does: supported. The registry is authoritative: each scan first removes index
  entries not under a registered root. A hand edit racing `ext register` can
  lose one of the two changes; this is not guarded.

## Trust, stores and locations

### Store ownership, mode and ancestors (agreed, #2)

- Spec: silent. The author agreed to a per-user store now, with a root store
  behind a privileged service possibly later.
- Does: refuses a store directory, or its `registry`, `index.db` or `lock`, that
  is not owned by the effective user or is group/other-writable. Also refuses a
  store whose ancestors, lexically and after symlink resolution, are owned by
  anyone but root or the effective user, or are group/other-writable without the
  sticky bit. `init` creates the store atomically with mode 0700 and files 0600,
  so `sudo ext init --bare /var/lib/ext` yields a root-owned, root-only system
  store and other users get exit 4. The rule "with elevated privilege ignore
  `EXTANT_DIR` and the current directory" is not implemented.
- Why: a store the user does not own, or that others can write, cannot vouch for
  anything.

### Current-directory step is `./.ext` (open, #13)

- Spec: L228 "4. Current directory".
- Does: the order is as specced (L224-L229), but the current-directory step
  looks for `./.ext`, not `./`. A candidate "exists" only if `registry` and
  `index.db` are regular files in it. Once `/var/lib/ext` exists, a non-root user
  without `--d` or `EXTANT_DIR` reaches it first and gets exit 4 (foreign owner),
  even with `./.ext` present; whether the current directory should come first is
  an open question.

### `--d` names the store (new)

- Spec: L242, L265 "`ext --d <path>` - Specifies the working directory".
- Does: `--d` names the store, or a directory whose `.ext` is a store. `init`
  rejects it and takes its location as an argument.
- Why: the store must be located before anything else, and there is no other
  working-directory notion to set.

### No config file (deferred, #10)

- Spec: L232-L243 "The config file is saved as <extant_path>/config. Its format
  is JSON5." with the flags Aware, Base64, Hex, DefaultEnc, IndexEnc, Truncation,
  Unlabeled, Directory, Hash.
- Does: no config file is read or written. Behaviour is fixed: SHA-256, b64ut
  output by default (`--hex` for hex), b64ut and hex input, labelled digests
  only, no truncation.
- Why: each flag either selects something v1 does not implement or is undecided.

### `init` layout (open, #10, #13)

- Spec: L246 "Create a `ext` directory with a new registry."
- Does: `ext init [dir]` creates `<dir>/.ext/` (`registry`, `index.db`, `lock`)
  and registers `<dir>`; it fails if `.ext` exists and never overwrites a store.
  `ext init --bare <path>` creates a flat store at `<path>` with an empty
  registry (how `/var/lib/ext` is made), after `git init --bare`.
- Why: a store in `.ext/` keeps store files out of the content; `/var/lib/ext`
  needs the flat form.

## External services, names, algorithms

### External services and cache (deferred, #3)

- Spec: L29-L35, L199-L217. The author agreed to verify-before-cache,
  configurable size and timeout limits, an origin per cache entry, and LRU by
  bytes; rules for redirects and localhost are unsettled.
- Does: none of it. A URI given to `register` fails; a URI in the registry file
  is a parse error. There is no cache.

### Hash URI not implemented (deferred, #4)

- Spec: L98-L137, now `hash://<alg>/<digest>[tail]` with `alg` matched
  case-insensitively.
- Does: the code neither parses nor emits hash URIs. `resolve` takes a labelled
  digest only (below); an argument beginning `hash://` is rejected as an unknown
  algorithm (exit 4).

### Digest input and output (open, #5)

- Spec: L61 reverse form `<digest>:<alg>`; L74 `<alg>:<value>`; L130-L131
  "Even-length `0-9A-F` is hex. Otherwise strict b64ut"; L137 "43 b64ut chars, or
  64 uppercase hex chars"; L171 hex "lower, upper, and mixed case". The author
  agreed the encoding is decided by character class or by the algorithm's size.
- Does: `resolve` input must be labelled, in either order (`<value>:SHA-256` or
  `SHA-256:<value>`); the algorithm name is exact and case-sensitive. The
  encoding is chosen by length alone (43 is b64ut, 64 is hex), any other length
  is an error. Hex input is accepted in any case; b64ut must be canonical (unused
  trailing bits zero) with no `=`. Output is b64ut, or uppercase hex with `--hex`,
  always as `<value>:<alg>`. No whitespace is trimmed.
- Why: choosing by length means a value cannot be read two ways; an algorithm
  name is never a valid value, so both orders are unambiguous.

### Truncation, AMBIGUOUS, COLLISION (deferred, #5)

- Spec: L175-L197 (truncation "supported but disabled by default"), L346-L347.
- Does: truncated digests are a length error. `resolve` returns every path with
  the full digest. `AMBIGUOUS` and `COLLISION` are never produced; `ext` does not
  hold two byte strings for one digest, so it cannot detect a collision.

### SHA-256 only; `Aware` and `Unlabeled` (deferred, #6)

- Spec: L235, L241, L360-L370. The author accepts a client supporting a subset
  of algorithms and treats `Unlabeled` as a low-priority advanced mode.
- Does: SHA-256 is the only algorithm; a label naming any other algorithm is
  rejected, not treated as unlabeled. Every digest must carry its label, which is
  the spec's default (`Unlabeled` false); the option itself is not implemented.
  The algorithm is stored per row so others can be added.

### Human names and tags (deferred, #7)

- Spec: L45-L48, L67-L83. Under discussion: the name is the optional filename and
  must match; tags are unspecified.
- Does: not implemented.

## Sub-extants and traversal

### Sub-extants live in `<dir>/.ext/` (open, #8, #13)

- Spec: L25 "Sub-extants keep their own registries in
  `<sub-extant_path>/registry`."; L357 "If an ext path contains another ext, it
  is ignored."
- Does: a sub-extant's store is `<dir>/.ext/`. A directory containing a real
  store there is not entered by a parent walk and is reported `SUBEXTANT`;
  entries previously indexed beneath it are reported `EXCLUDED` and removed. A
  `.ext` counts only if `registry`, `index.db` and `lock` are regular files owned
  by the registered root's owner or root and not group/other-writable; any other
  `.ext` is ordinary content and is indexed. A sub-extant works standalone
  (`ext init <dir>`, then `ext --d <dir> ...`). The store in use is never
  indexed, and its own root is not a sub-extant of itself.
- Why: a bare `registry` file is too generic a marker, and a store in the
  content would index itself. Requiring a real store stops a planted `.ext` from
  hiding a subtree. The author wants explicit registration only; this holds.

### Sub-extant linking (open, #13)

- Spec: L27 "Sub-extants may be registered to a parent extant."
- Does: no linking. A parent never reads a child's index. The proposed copy and
  reference modes, and an opt-in flag, are not implemented.

### Traversal (open for symlinks and special files, #9)

- Spec: L19-L20 (`/` and `/srv/www` as examples), L41-L42. Symlink policy is to
  be discussed with the author; special files are to get a separate document;
  the author considers race handling an implementation detail.
- Does:
  - `/`, or any directory, can be registered. Only regular files are hashed;
    symlinks and special files are counted and never opened.
  - Descent uses `openat2`/`openat` relative to open directory descriptors with
    `O_NOFOLLOW`; a registered root with a symlink in any component is
    `REFUSED`. Regular files are opened `O_NONBLOCK` and their type and
    (device, inode) re-checked on the descriptor; a mismatch is `UNSTABLE`.
  - Metadata is compared before and after hashing; one retry, then `UNSTABLE`
    and the entry is deleted.
  - A directory on a different mount (by mount id, or `st_dev` where the kernel
    lacks mount ids) is reported `MOUNT` and not entered.
  - The walk is iterative; depth costs memory, not stack or descriptors.
  - Nested registered roots: the outer walk stops at the inner root.

### Deleted roots and unreadable paths (open, #9)

- Spec: L251-L252 "Unregister, removing all references in indexing. (Deleting a
  directory also unregisters.)" The author prefers that a deletion updates the
  index by default (configurable), and that deletion be distinguished from a
  failed mount.
- Does: a registered root that no longer exists reports each entry `MISSING` and
  removes the entries, but the registry line stays; there is no automatic
  unregistration. An entry is `MISSING` only when the walk did not see the file
  and a descriptor-relative check confirms it is no longer a regular file. A file
  or directory that cannot be read or listed keeps its entries (`ERROR`, exit 5).
  A root whose filesystem identity (`f_fsid` from `statvfs`, recorded on first
  scan) has changed is `REFUSED`, keeps its entries and exits 5;
  `ext register <root>` on a registered root records the current identity and
  keeps its entries, `unregister` forgets it. Stability of `f_fsid` across
  reboots on every filesystem is unverified.
- Why: an unmounted disk looks like a deleted tree; wiping its baseline on that
  evidence loses data.

## Commands

### `register` and `unregister` arguments (new)

- Spec: L249 "Supports both files and directories."
- Does: `register` accepts directories only, canonicalises the path, adds it and
  scans that root. `unregister` needs a path that exactly matches a registry
  entry (exit 4 otherwise) and removes the entry and all index entries under it.
- Why: the walk is rooted at directories; exact matching avoids removing a
  parent by accident.

### `check` (open, #10)

- Spec: L258-L263 `ext check`, `ext -check`, `ext check --full`, `ext -rerun`.
  The author asked for `check` semantics to be discussed.
- Does: one `check` command. A file whose metadata changed and whose digest
  differs is `EDITED`, reported with both digests, and the index is updated. With
  `--full`, a digest change under unchanged, non-racy metadata is a `VIOLATION`
  (exit 2) and is not written. `--accept` writes violations as the new baseline
  and reports them `ACCEPTED` (exit 0). `rebuild` replaces `-rerun`: it clears
  the index, re-hashes, and accepts everything. The `-check` and `-rerun`
  spellings are not accepted. There is no `update` command.
- Why: tampering that preserves metadata is distinguishable from an edit only by
  `--full`, and must not be absorbed silently.

### Exit codes (agreed, #10)

- Spec: L271-L277: 0 OK, 1 not found, 2 mismatch (`check`), 3 ambiguous, 4 usage
  or configuration error.
- Does: 0, 1 (`resolve` found nothing), 2 (an unaccepted violation, the
  mismatch) and 4 (usage, configuration or store error, including the argument
  parser's own errors) as specced. 3 is never emitted: ambiguity needs
  truncation, which is not supported. 5 is an addition: the scan was incomplete
  (`ERROR`, `UNSTABLE` or `REFUSED`) and no violation was found. A violation
  outranks an incomplete scan; a store or database failure during a scan exits 4.
  `MISSING`, `EXCLUDED`, `MOUNT`, `SUBEXTANT` and `ACCEPTED` exit 0. A closed
  output pipe is a quiet stop: `list` and `resolve` exit 0; `check`, `register`
  and `rebuild` exit with the scan's code.
- Why: per-file errors do not abort a scan (L42), so a script needs a code that
  says coverage was partial; reusing 2 would conflate it with tampering.

### Flag forms (agreed, #10)

- Spec: L249-L269.
- Does: subcommands with `-r` and `-u` as aliases of `register` and `unregister`
  (as L269 states); global long options `--d` and `--hex`, and a global `-0`;
  `check` takes `--full` and `--accept`.

### Not implemented

- `ext watch` and the watcher (L267, L324-L338): every run is a metadata scan.
  Issue: new.
- `/dev/ext` (L139-L168): out of scope for the userspace tool.
- Locking: writing commands hold an exclusive lock on the store's `lock` file for
  the whole run and wait for it; `resolve` and `list` do not lock. The spec is
  silent. Issue: #1.
