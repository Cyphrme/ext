DRAFT
https://github.com/Cyphrme/ext
# Extant: Hash Based Naming

Extant is an index containing the digests of files inside registered
directories. Extant supports subdirectory registries (sub-extants) and external
blob services.

# Extant Goals
 - Provide hash based addressing on a system wide and subdirectory basis.
  - Provide cryptographic integrity to files.
 - Incremental behavior. (New changes are added as they occur. No global
   re-hashing)
 - Support external blob services.

## Registration
**Registry**
A registry is simply a list of paths and URIs, newline delimited. For example,
to register a whole system, the registry contains simply the root path, `/`. A subtree such as `/srv/www`
may equally be registered.
The system-wide registry is kept by default in `/var/lib/ext/registry`. Files
may be registered by `ext -r <path>` or by editing the registry file.

**Subdirectory Registration**
A sub-extant keeps its store in `<sub-extant_path>/.ext/`, which holds its
registry. A directory is a sub-extant only if its `.ext/` is a directory
containing a registry, both owned by the owner of the parent's registered
root or by root. Any other `.ext` is ordinary content, so creating one cannot
hide a subtree from the parent. A sub-extant works standalone: `ext init
<dir>`, then `ext --d <dir> ...`.

Sub-extants may be registered to a parent extant.

**External Service Registration**
External services may be registered via

`ext -r <URI>`

For example:
`ext -r https://cyphr.me/e`

## Extant Registry and Index paths
Indexes are kept in `<extant_path>/<index_name>`. The registry and source index
are required, others are optional.

The store directory is never indexed by `ext`; it does not index itself. A
per-file read error is reported and does not abort the scan.

**File Formats**
Registry:   <registered_file_path>
Source:     <digest>:<alg>\t<path>
Path Index: <path>\t<digest>:<alg>
Tag:        <tag>\t<digest>:<alg>
Cache:      <digest>:<alg>\t<path>
Cache Time: <digest>:<alg>\t<time>
Timestamp:  <path>\t<last_checked>\t<mtime>\t<ctime>\t<size>\t<inode>

Index files are TSV as defined in https://github.com/Cyphrme/TSV: fields are
tab delimited, records are newline delimited, and a backslash, tab, or newline
in a field is escaped as `\\`, `\t`, or `\n`. Records are sorted by the raw
bytes of their first field.

A process that writes a store holds an exclusive lock on
`<extant_path>/lock` for its whole run; readers take no lock. An index file is
replaced atomically: it is written to a temporary file in the store and renamed
over the old one, so a reader never sees a partial file.

External service URIs are not stored in the system indexes.

The same digest may appear more than once when multiple paths contain
identical content. Lookup by digest returns every matching path. The path index,
by contrast, has unique paths.

## Digest Naming
**Hash Storage**
Storage uses **reverse digest naming** (reverse form), where the digest appears
before the hash label, `<digest>:<alg>`. The reverse form provides a global
namespace for all hashes.

`oDBDAg4xplHQby6iQ2lZMS1Jz4Op0bNoD5LK3KxEUZo:SHA-256`

**Human Naming**
If the human name doesn't exist, ext does not return the value even if the
digest exists. Why? The digest value can always be sent. If the human readable
value is sent, ext forces interpretation. If you don't need the human name,
don't use it.

The human name is the file's name. It is optional; when given, it must equal
the last component of a path that has the digest. When several paths share
the digest, one match is enough. Tags, other human-readable data describing
a digest, are TODO.

Digest with Human Name
<alg>:<value>:<human_name>

Reverse naming
<value>:<alg>:<human_name>

Ergonomic naming:
<human_name>:<alg>:<value>

Ergonomic naming with extension:
<human_name>:<alg>:<value>.<ext>

## Scheme and URI API
Extant is designed with existing HTTP services in mind. HTTP servers can format
however they would like. The following are a few examples:

Page:
https://cyphr.me/example:SHA-256:2rfHUI84JBkIziYcLmvg4Dbjkr4B_md0gCupblX_JU8

Asset:
https://cyphr.me/File:Example:SHA-256:2rfHUI84JBkIziYcLmvg4Dbjkr4B_md0gCupblX_JU8.png

Simple blog service:
https://cyphr.me/e/SHA-256:2rfHUI84JBkIziYcLmvg4Dbjkr4B_md0gCupblX_JU8

**Hash URI** - Names bytes by digest. The following URI requires support by
implementing systems (such as a browser):

```
hash://SHA-256/oDBDAg4xplHQby6iQ2lZMS1Jz4Op0bNoD5LK3KxEUZo
```

**Hash Scheme Grammar**
```
hash-uri = "hash://" alg "/" digest [tail]
scheme   = "hash://"
alg      = 1 * (ALPHA / DIGIT / "-"); Coz alg. No "/".
digest   = 1*b64ut; 
b64ut    = ALPHA / DIGIT / "-" / "_" ; 
hex      = DIGIT / %x41-46 / %x61-66; 0-9, A-F, a-f
tail     = <Starting at first non-b64ut> 
           (which is of course inclusive of the Hex character set)
```

The b64ut alphabet includes every hex character, so a hex digest is also a
b64ut string. At full length the encoding is decided by length, not by which
characters appear: for SHA-256, 43 characters is b64ut and 64 is hex.

Scheme match is case-insensitive and `digest` is case-sensitive. The `alg`
acts as the URI authority, and generic URI parsers lowercase the authority, so
in a `hash://` URI `alg` is matched case-insensitively against Coz alg names.
Tail is optional and resolution is out of scope.

**Hash Scheme Parsing**
1. After `hash://`, split on first `/`.
2. `digest` is the longest b64ut prefix of the remainder. First non-b64ut char
   starts `tail`.
3. Prefer the decoding whose length equals `alg`'s digest size. Even-length
   hex, in any case, is hex. Otherwise strict b64ut. Non-canonical encoding is an error.
4. When truncation is enabled, a shorter digest is accepted: hex characters only,
   in any case, is hex, anything else is b64ut. Else error.

Identity = (`alg`, raw digest bytes). `tail` is not identity.

SHA-256 is 32 bytes, 43 b64ut chars, or 64 hex chars. No `=`.
Hex is accepted in any case and written uppercase.

## System Integrated Extant: `/dev/ext`
So far described is **userland extant**. The extant service is designed first as
a stand alone, user space service, with a root existing in `/var/lib/ext`.
However, extant has the eventual goal of kernel integration, `/dev/ext`, a
character special file. Due to the difficulty of kernel integration, it is a
later TODO. However, the conceptual model is informative for eventual
architectural goals.

On unix systems, `/dev/null` is for nothing.  It is a black hole. In the same
way there should be a white hole, `/dev/ext`,  an index for all content
addressable files on the system. "Ext" is short for "extant", Latin meaning "to
exist".

Using a symbolic link, this file then can be used as a database:

For example:
ln -s /dev/ext /var/www/website_name/content

**List of existing sources or sinks**
- /dev/null
- /dev/full
- /dev/zero
- /dev/random
- /dev/urandom

**Unix Tools**
`/dev/ext` is a character special file.
 - `cat` lists all digests in the source index.
 - `ls` simply prints the extant, such as `/dev/ext`, just as it does with
   `/dev/null`, `/dev/random` and other such special files.

## Bases
Both Base64 (b64ut) and hex (lower, upper, and mixed case) are supported.
Hex output is uppercase.
However, the default is b64ut.

## Truncation and Collision
Truncation is supported but disabled by default. For example:
 - Full hash: SHA-256:2rfHUI84JBkIziYcLmvg4Dbjkr4B_md0gCupblX_JU8
 - Truncated: SHA-256:2rfHUI84JB

Note that the strength of the integrity protection is lessened with truncation.

**Collision**
A collision is where two distinct inputs resolve to a single digest. This may happen when
using a non-cryptographic hash, truncation, or a broken cryptographic hash.
Although `ext` is designed for cryptographic hashes, there are circumstances
where non-cryptographic hashes are useful, such as speed and smaller lookup
keys. Non-cryptographic algorithms are "locate only": they are never used
for verification, cache admission, or fetching.

On collision for truncation or non-cryptographic hashed, tooling provides top
matches. For cryptographic hashes provided with full sized digests, tooling must
fail as appropriate.

```
AMBIGUOUS SHA-256 2rfHUI84JB 2
2rfHUI84JBkIziYcLmvg4Dbjkr4B_md0gCupblX_JU8:<path_0>
2rfHUI84JBkIziYdK9qPJtG648Epv8MUI248F517dW8:<path_1>
```

## Caching
The cache is used for external services. After external retrieval the digest is
added to the cache.  The cache is a least recently used (LRU) Unix time cache.

The order of operations for the lookups is:

1. Local lookup
2. Local cache
3. Query external services

The cache has two indexes which provide O(log(n)) lookups, the Cache Index
comprised of <dig>:<path> and the Cache Time Index, comprised of <dig>:<time>.
Cache capacity is set in bytes in the config. Once the cache reaches capacity,
the least recently used items are evicted.

A fetched blob is hashed in full with the requested alg and compared with the
requested digest before it is cached or returned. On mismatch it is discarded,
nothing is cached, and the error names the service. Fetch size and timeout
limits are configurable. By default, redirects to a different scheme are not
followed, and a service may not direct `ext` to a loopback or other local
address. A config option can relax both.

A cache record holds the alg and digest, the origin service, the local file
name (derived only from the verified digest), and the last access time.

## Directories
`ext` checks for stores, indexes, and registrations. Default system wide userland
directory: `/var/lib/ext`. This may be set to a different directory using the
environment variable `EXTANT_DIR`.

The waterfall for directories, highest precedence first:
1. Flag value (`--d <path>`)
2. Environment variable, `EXTANT_DIR`
3. Default path, `/var/lib/ext`
4. Current directory
5. Fail if nothing exists.

## Trust
`ext` runs as the invoking user and indexes only what that user can read. A
store must be owned by the user running `ext`, and `ext` refuses any other.
When `ext` runs with elevated privilege, `EXTANT_DIR` and the current
directory are not consulted.

Integrity means detecting change relative to the index, so the index is only
as trustworthy as the store's protection. A system-wide store that serves
queries from other users, filtered to what each may read, is future work.

## Config Flags
The config file is saved as <extant_path>/config. Its format is JSON5.

|Flag - Default Value - Description|
- Aware      - True  - the system only supports digests specified by ext.
- Base64     - True  - Support Base64 encoding.
- Hex        - True  - Support lower, upper, and mixed case hex.
- DefaultEnc - B64   - Default encoding.  B64 is preferred.
- IndexEnc   - B64   - Default index encoding.  (Lookups are converted to target base)
- Truncation - False - Supports truncation.
- Unlabeled  - False - Do not require digest labeling.
- Directory  - CWD   - Specify working directory for `ext`.
- Hash     - SHA-256 - Default hash.

## Commands
`ext init <path>` - Create a `ext` directory with a new registry. If no path is
specified CWD is used.

`ext register`,`ext -r`  - Registration. Supports both files and directories.

`ext unregister`, `ext -u`         - Unregister, removing all references in
indexing. (Deleting a directory also unregisters.)

`ext resolve <dig>` - Print path(s)

`ext list` - prints the source index.

`ext check`, `ext -check` - Re-hash files whose metadata changed (see
Incrementality) and record their new digests as edits. Skip unchanged paths.

`ext check --full` - Re-hash all files and do not skip unchanged paths. A
digest that changed while the file's metadata did not is a violation: it is
reported, the index is not updated, and `check` exits 2.

`ext check --accept` - Record reported violations as the new digests.

`ext -rerun` - Rebuild all indexes and re-hash all files.

`ext --d <path>` - Specifies the working directory for `ext`.

`ext watch` - Starts the watcher that triggers on file change.

`-r` and `-u` are aliases of `register` and `unregister`.

**Exit codes**
|Code - Meaning|
- 0 - OK
- 1 - Not found
- 2 - Mismatch (`check`)
- 3 - Ambiguous
- 4 - Usage or configuration error

## Incrementality
Incrementality uses a persistent timestamp index and an optional continuous
watcher. The timestamp records are advisory for performance. `ext check --full`
ignores them and re-hashes every registered path for a complete integrity
verification.

**Timestamp Index** - For each registered path the following are stored:
- `last_checked` - time of the last examination by `ext`, in nanoseconds
- `mtime`, `ctime` - the file's modification and status-change times, in
  nanoseconds, as observed at that examination
- `size` - the file's size in bytes
- `inode` - the file's inode number (or platform equivalent)

On run (CLI or watcher):

1. A path is skipped only if its current `mtime`, `ctime`, `size`, and `inode`
   all match the stored values, and the entry is not *racy* (below).
2. Otherwise the file is re-hashed, indexes are updated, and the record is
   rewritten.

mtime alone is not sufficient: it can be set by any process (`touch -d`,
`utimensat`, `cp -p`, `rsync -t`, archive extraction), whereas ctime cannot be
set from userspace. A configuration option may disable the ctime and inode
comparisons for filesystems where they are unstable (some FUSE and network
filesystems).

**Racy entries** - A file modified within the filesystem's timestamp
granularity after it was hashed can show unchanged metadata. `last_checked` is
sampled before the file is first examined (before its metadata is read and
before it is hashed). An entry is racy when the later of its `mtime` and
`ctime` is not earlier than `last_checked` minus a fixed window of 2 seconds,
which covers coarse filesystem timestamps without needing to know the
filesystem's granularity. A racy entry is re-hashed on the next run regardless
of matching metadata. This is the same problem and remedy as git's "racy git"
handling.

The rationale is in [docs/incrementality.md](docs/incrementality.md).

**Directories** - Large directories may also be recorded in the timestamp
index as a further optimization. A directory's mtime changes only when an
entry directly inside it is created, removed, or renamed; it does not change
when a file's contents change, or when anything changes in a subdirectory.
An unchanged directory record therefore permits skipping only the re-listing
of that one directory. Every entry in it is still checked by rule 1.

**Watcher** - `ext watch` monitors registered paths via the platform
mechanism (Linux: inotify). inotify is not recursive, so the watcher adds one
watch per directory, and newly created directories are scanned after their
watch is added. Files are re-hashed on close-after-write (`IN_CLOSE_WRITE`)
and on move-in, not on every modification; deleted or moved-out files are
removed. The timestamp index is updated accordingly.

Events can be lost: on queue overflow (`IN_Q_OVERFLOW`), on failure to add a
watch (e.g. the per-user watch limit), and while the watcher is not running.
In each case the watcher performs a full metadata scan of the affected tree
using the rules above. With that rule the watcher is not required for
correctness: any later `ext` invocation observes the same metadata and
produces the same result.

External services are never watched; they are consulted only on cache miss.

## Coz
Extant uses the algorithm hash naming convention and b64ut (RFC 4648 base64 url,
padding truncated, canonical), and expected default digest sizes as specified by
Coz. Hex may be used in place of b64ut. Algorithm names, digest sizes, and
encoded lengths are listed by Coz.

An `ext` client may support a subset of the Coz algorithms. A digest labeled
with an algorithm the client does not support is rejected, not treated as
unlabeled.

## Errors
AMBIGUOUS - Multiple digests complete given string
COLLISION - Two distinct payloads resolve to the same digest.


## Technical Considerations
**Extant Non-goals**
- Not a transport.
- Not a multi-hash registry. Not ni:. Not a filename standard.
  In `hash:` the digest's algorithm is the authority, so ni's empty authority
  (`///`) is not needed.

**Recursion** - A parent's scan skips sub-extants; they are not included by
default. Registering a sub-extant to the parent includes it: the parent hashes
the sub-extant's files itself and does not read the sub-extant's index.

**Digest Labeling** - Unlabeled digests are a security concern: the weakest hash
becomes the security floor of the system overall. A system with unlabeled
digests is only as strong as the weakest supported hash algorithm.

If the hashes are trusted, or for systems that only support one hash type or
otherwise inferred, the label may be dropped, but the responsibility should be
understood to rest completely on the system administration's setup of `ext`. Use
with extreme caution.

**Size Ambiguity** Digests without labels may have an unknown size. Otherwise
the expected digest size is given by the Coz specification.

**The Mining Problem.** Although collisions may be very difficult, even with
weak hashes, specific ranges may be targeted.

The architecture should not assume a uniform, normal distribution of digests.
Instead, it should assume an irregular, unbalanced distribution to avoid any
problems with distribution.

For example, sharding should not be naive. Sharding should measure the sizes in
different directories.

**Operating System Considerations**
Base64 support requires case sensitivity.

Unix: We do not foresee any problems with
other Unix systems.

Windows:There are no naming conflicts with Windows except
`:`.  We suggest `_` be used instead.

**/dev/random**
`/dev/random` waits for the CSPRNG to fully initialize on boot. It never
blocks after bootup after Linux 5.6.

Before 5.6:
- /dev/random  <- May block under low entropy
- /dev/urandom <- non-blocking, including boot up

## FAQ
- base85: We considered base85 support but it appears to be too problematic with
Unix file naming.


## See also
 - https://github.com/Cyphrme/Coz
 - https://github.com/Cyphrme/Path

**Prior art**
- IPFS, Protocol Labs
- Nix store
- git
