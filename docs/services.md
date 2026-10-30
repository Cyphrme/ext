# External Services

Requirements for fetching blobs from external services, and for the local
cache that holds what was fetched. The [README](../README.md) states the rules
briefly; this document is normative detail. The key words MUST, MUST NOT,
SHOULD and MAY are used as in BCP 14 when in capitals.

## Scope

When the local index and the local cache both miss, `ext` MAY fetch a blob by
digest from registered external services. The local extant is the priority
layer. Version 1 builds the `https` backend only, behind an internal backend
contract (see Backend contract) that later backends plug into.

Non-goals: `ext` is not a server (a front end is its own binary); not an index
or mirror of a service; not a relay between services; it never uploads; it keeps
no negative cache of misses. Authentication is a reserved placeholder (ES-20).

Known disclosure: a lookup that misses locally sends the digest and the
client's address to each registered service in turn. A registered service is
trusted with lookup history, never with integrity. `--offline` (ES-32) contacts
nobody.

Terms:

- `Fetchable(d)`: the digest `d` is full length for its algorithm, and the
  algorithm is cryptographic and supported by this client.
- A `Candidate` is untrusted bytes returned by a backend.
- `Verified(c, d)` means `ext` hashed all of candidate `c` with `d.alg` and got
  `d.bytes`.
- Per service, the outcome of an attempt is one of `Hit`, `Missing`, `Error`,
  `Mismatch` or `Skipped`.

## Lookup

**ES-1** Layers MUST be consulted in the order local index, local cache,
services. A layer "answers" when it produces a result: for `resolve`, an index
record or a cache record whose file passes ES-10; for `cat`, a blob verified
under ES-11. No service MUST be contacted once a layer answers.

**ES-2** A service MUST NOT receive a request for a digest that is not
`Fetchable`. Truncated, non-cryptographic, unsupported-algorithm and unlabeled
digests are locate-only (README, Truncation and Collision).

**ES-3** Services MUST be tried one at a time in file order. The first
`Verified` candidate wins and no later service is contacted. At most 64
services are registered.

**ES-4** A backend that cannot address the requested algorithm MUST be
`Skipped` without a request.

**ES-5** For `https`, the final HTTP status MUST classify as follows:

- 200 is a `Candidate`.
- 404, 403 and 410 are `Missing` (403 because S3-style hosting answers 403 for
  an absent object).
- 301, 302, 303, 307 and 308 are redirects (ES-14).
- Every other status, including 401, 204, 206, 304 and all other 3xx, and every
  transport, TLS, framing or limit failure, is `Error`.

A 200 whose `Content-Encoding` is not `identity` is `Error`. An interim 1xx
before the final status is ignored. An empty 200 is a normal candidate: the
empty blob has a digest.

**ES-6** On `Mismatch` (a `Candidate` that is not `Verified`) `ext` MUST
discard the bytes, cache nothing, report `SERVICE <uri> MISMATCH` on stderr and
try the next service. `Error` is reported the same way (`SERVICE <uri> ERROR
<message>`); `Missing` is silent.

**ES-7** A lookup that finds nothing exits with the first matching row:

1. 2, if an index record failed verification under `cat` (ES-11).
2. 5, if any consulted service was `Error` or `Mismatch`, or a private copy or
   cache admission that was needed could not be written (read-only store, no
   space, lock busy past the timeout; ES-11, ES-25).
3. 1 otherwise, including no services, all `Missing` and all `Skipped`.

A hit exits 0 whatever earlier services did; their failures are still
reported. 4 remains usage or configuration error. Exit 1 means no consulted
service delivered the blob; because 403 and 404 are both `Missing`, it is not
proof that the blob does not exist.

## Integrity

**ES-8** A blob MUST be cached, or its bytes delivered (`cat`), only after
`ext` hashed all of it with the requested algorithm and the result equalled the
requested digest. A candidate MUST NOT exist under a final cache name before it
is verified.

**ES-9** A backend's own claims (`Digest`, `ETag`, `Content-Length` as a claim
of content, any header) have no authority: the outcome depends only on the
response status, framing, `Location`, `Content-Encoding` and the bytes. A claim
MAY make `ext` abort early, and then only to `Error`, never to `Hit`.

**ES-10** On `resolve`, a cache record is an answer only if its file is a
regular file (opened without following symlinks) whose size equals the
record's size. Otherwise the record is removed when the lock is available,
and with it the entry at the cache path if that is a regular file or a
symlink; the lookup continues as a miss. Unlinking never follows a symlink, so
its target is untouched. A directory, FIFO, socket or device found at the
cache path is left in place and only its record is removed, because `ext`
never deletes recursively or opens special files. `resolve` does not hash cache or
index hits; the store's protection is the trust boundary (README, Trust).

**ES-11** `ext cat` MUST hash in full every blob it returns, on every layer
(index file, cache file, service). It MUST write nothing to stdout until the
complete content has been read once into a private copy and hashed, and MUST
then write that copy. The copy is a 0600 file in `cache/tmp/` (never a memory
buffer of unbounded size), counted by the sweep and removed on every path. A
read-only store is unsupported for anything that writes, and `cat` always
writes its copy, so `cat` on a read-only store exits 5 even for an indexed
file. If the copy cannot be created or completed (a read error aside), `cat`
stops with exit 5 and a clear error, because the blob may exist; it never
reports 1 in that case. An index or cache file that fails verification is
skipped (a cache file is evicted if the lock is available), the lookup
continues, and a failed index record is reported on stderr.

## Fetch limits and network safety

**ES-12** A fetch MUST NOT write more than `ServiceMaxSize` bytes to disk, nor
read more than `ServiceMaxSize` + 1 bytes of body (the extra byte shows the
body is too long), counted by `ext` itself. A body longer than the limit, or a
`Content-Length` above it, is `Error`.

**ES-13** Each service attempt MUST end by `ServiceIdleTimeout` of no progress
in any phase (connect, the TLS handshake, waiting for response headers and the
body) and by `ServiceTimeout` of total elapsed time (name resolution,
connect, TLS, every redirect hop and the body). A backstop applies to DNS only
where the resolver can be bounded. Both limits are enforced by `ext`, not left
to the HTTP library's defaults.

**ES-14** `ext` MUST follow redirects itself, at most 5 hops, only for the
statuses in ES-5, and MUST apply ES-15, ES-16 and ES-18 to every hop. A
`Location` is resolved against the current URL and must satisfy the services
grammar (ES-21) for its scheme, host, port and path, without userinfo or
fragment; a query string is allowed (presigned and CDN redirects). The scheme
may change only between `https` and `http`, and only when `AllowHTTP`; any
other scheme is `Error`.

**ES-15** `ext` MUST connect only to global-unicast addresses unless
`AllowLocal`. The resolver hook is consulted for every hop, including IP
literals in the URI or `Location`, and every socket address it returns is
judged after `IpAddr::to_canonical()`; the host text is never the judge. The
connection goes only to an address that passed, and the resolver is not
consulted again for that hop. The allowed set is an allow-list:

- IPv6 only within 2000::/3, IPv4 anywhere, in both cases minus every block of
  the IANA IPv4 and IPv6 Special-Purpose Address Registries (RFC 6890 as
  updated) whose Globally Reachable value is False, and minus IPv4
  224.0.0.0/4.
- After canonicalisation a v4-mapped address is judged as IPv4, a 6to4 address
  (2002::/16) by its embedded IPv4, and Teredo (2001::/32) is denied.
- NAT64 and all other space outside 2000::/3 is denied.

The table is a constant. If no returned address is allowed, the attempt is
`Error`.

**ES-16** An `http` service URI MUST be refused at registration (exit 4)
unless `AllowHTTP`. An `http` entry already in the file when `AllowHTTP` is
false MUST be `Error` naming the service, not skipped silently.

**ES-17** TLS certificate and hostname validation MUST NOT be disable-able: no
flag, environment variable or config key turns either off. Trust roots MUST be
loaded once per process, before any service attempt and outside the ES-13
budget, from the operating system's trust store through the platform's native
certificate loader, and MUST NOT come from a list compiled into `ext`, so that
root updates and distrust of a CA are the platform's concern and not a release
of `ext`. `SSL_CERT_FILE` and `SSL_CERT_DIR` are the only environment variables
that may alter the trust roots, and only through that loader. When either is
set, any error the loader reports for a named source (an unreadable file or
directory entry, or a malformed certificate) makes the attempt `Error` naming
the source, even if other roots loaded; entries in a format the loader does not
recognise are not errors. If the loader yields no usable root, or the named
file or directory cannot be read, the attempt is `Error` naming the cause
(ES-19 applies to the path) and there is no fallback to any other root source.
`ext` MUST NOT read any other environment variable or config key that alters
trust, routing or name resolution, and MUST NOT log TLS key material
(`SSLKEYLOGFILE` is ignored). In particular the proxy variables (`HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, in any case) and the resolver-altering
variables (`RES_OPTIONS`, `HOSTALIASES`, `LOCALDOMAIN` and the like) are
ignored, so ES-15 is judged on the real peer. `AllowHTTP` and `AllowLocal` are
settable only in the config file, never by flag or environment.

**ES-18** Every request MUST be `GET` with no body and only the headers
`Host`, `User-Agent: ext/<version>`, `Accept: application/octet-stream`,
`Accept-Encoding: identity` and `Connection`. No cookies are stored or sent.
`ext` MUST NOT send any other method.

**ES-19** Untrusted text printed to a terminal (service-originated text such
as reason phrases and error text, and file paths from the filesystem in `ext`'s
stderr diagnostics) MUST have every byte outside 0x20-0x7E, and the backslash,
escaped as `\xNN` (lowercase hex).

## Authentication (placeholder)

**ES-20** Version 1 sends no credentials and has no config key for them (an
unknown key exits 4). A 401 is `Error` naming the service (ES-5). Whoever adds
credentials MUST first specify that they are never sent over plaintext, never
to another authority than the registered service, and never persisted.

## Services file and registration

`<store>/services` is ASCII with LF-terminated records, one URI per line, no
blank lines or comments. File order is priority. It is written with the
store's existing discipline: store lock held, temporary file in the store,
atomic rename; readers take no lock. The file and `cache/` are subject to the
same owner check as the store (owned by the effective user, not group- or
other-writable), else exit 4; this keeps a root-run `ext` from being steered by
another user. The file is parsed only when a service is needed or by `-r`/`-u`,
so a bad file never fails a locally answered lookup or `cat --offline`.

```
line        = base / template
base        = scheme "://" host [":" port] path          ; no "?" and no "#"
template    = scheme "://" host [":" port] path-q        ; contains {digest} or {hex}
scheme      = "https" / "http"                          ; lowercased on parse
host        = dns-name / IPv4address / "[" IPv6address "]"   ; non-empty; lowercased on parse
dns-name    = 1*( ALPHA / DIGIT / "-" / "." )           ; no "%", no sub-delims
port        = %x31-39 0*4DIGIT                          ; 1..65535, no leading zeros
path        = *( "/" / pchar )
path-q      = *( "/" / "?" / pchar / placeholder )
placeholder = "{alg}" / "{digest}" / "{hex}"
```

`pchar`, `IPv4address` and `IPv6address` are RFC 3986's. There is no
userinfo. A line is at most 2048 bytes. A line equal to an earlier line after
lowercasing scheme and host is a parse error; `https://h` and `https://h/` are
different lines. Any other `{...}` is rejected.

**ES-21** The parser MUST accept exactly a line satisfying the grammar and
reject everything else with exit 4. The error message is
`services:<line>: <reason>`, with a 1-based line number and the reason escaped
per ES-19. An empty host and a port with leading zeros are rejected.

**ES-22** `ext -r <arg>`: `arg` is a service if and only if it matches
`^[A-Za-z][A-Za-z0-9+.-]*://`; otherwise it is a path (a relative path that
looks like a URI is written `./...`).

- A service is appended after the last line. Registering an existing URI
  (after normalisation) is a no-op with exit 0. An invalid URI, or one that
  would be the 65th, is exit 4 and changes nothing.
- `ext -u <arg>` removes the line equal to the normalised URI and nothing else.
  Cached blobs remain: their validity is by content. An absent URI is exit 4.
- The registry holds only absolute paths and the services file only URIs. A
  URI in the registry is a parse error.

## Backend contract

A backend provides the algorithms it can address (ES-4) and `fetch(d, limits)`,
which returns `Hit(temp file)`, `Missing` or `Error(msg)`. The lookup loop
alone applies ES-3 and ES-6 through ES-9. `https` is the only version 1
backend; an external helper protocol is reserved and unspecified. The contract
is internal.

**ES-23** For an `https` base `B`, the request is `GET B'/<alg>:<digest-b64ut>`
where `B'` is `B` without trailing slashes plus one `/`. For a template,
`{alg}` is the Coz algorithm name, `{digest}` the b64ut digest and `{hex}` the
uppercase hex digest. These are legal `pchar` characters, so no escaping
occurs.

## Cache

State:

- Records `(alg, digest, size, atime_ns)` live in the store, in the table
  `cache` of `index.db`, created `IF NOT EXISTS`.
- Files live at `<store>/cache/<ALG>/<HEX>`, with the digest in uppercase hex
  so that case-insensitive filesystems cannot confuse two names.
- In-flight files live in `<store>/cache/tmp/`.
- There is no origin field. The cache is reconstructible and is not exported
  or imported.

Transitions, each under the store lock (fetching never holds it, ES-29):

- **admit**: write a temporary file, fsync, rename it to the final name, then
  in one transaction insert the record and evict until ES-26 holds.
- **evict**: delete the record (commit), then unlink the file.
- **touch**: `atime := max(now, atime)`. Touching a digest with no record is
  a no-op. Admitting a digest that is already resident likewise sets
  `atime := max(old, now)`.
- **sweep**: delete files without a record and unlocked stale temporary files.

**ES-24** Cache directories MUST be created 0700 and files 0600 with explicit
modes, not the umask. A file name MUST be a function of `(alg, digest)` only,
never of service-supplied data.

**ES-25** After a process crash (SIGKILL) at any step there is no record
without a complete verified file, and no final-named file whose hash differs
from its name. An orphan file is permitted. Power loss is not claimed. If the
verified blob cannot be admitted (read-only store, lock unavailable for the 5 s
busy timeout, no space) the lookup (`resolve` or `cat`) stops with exit 5 and a
clear error, no later service is tried, nothing is delivered and nothing
partial remains, unless an earlier row of the ES-7 list (exit 2) matches: the
ES-7 order governs. Temporary files MUST be removed on every error path. A
read-only store supports no writes (private copy, admission, touch,
eviction), but a `resolve` answered from the local index MUST succeed on one.
`cat` always needs its private copy (ES-11), so on a read-only store it exits
5.

**ES-26** After every command, the sum of record sizes is at most
`CacheCapacity` and the files under `cache/` excluding `tmp/` total no more,
modulo orphans left by a failed unlink and swept at the next admit. Eviction
order is ascending `atime`, ties broken by ascending `(alg, digest)` bytes; the
record just admitted is never evicted. A blob larger than the capacity cannot
occur (ES-31).

**ES-27** A cache hit MUST NOT fail or wait on a touch: the touch uses a
non-blocking lock attempt and is skipped when the lock is busy or the store is
read-only. The lookup result is unaffected; LRU is approximate under
contention.

**ES-28** Cached blobs MUST NOT appear in `ext list`, the source index or the
timestamp index, and MUST NOT be scanned or hashed by `check`.

**ES-29** A lookup MUST NOT hold the store write lock while fetching. The lock
is held only for admit, evict, touch and sweep. Concurrent lookups of one
digest both succeed and leave one record. This amends the README's
single-writer rule: a scan holds the lock for its whole run; other writers hold
it per write.

**ES-30** Sweep MUST run at the start of every admit. It MUST NOT remove a
temporary file whose fetch is live or that is younger than 60 s, and MUST
remove an older one whose process died. Each temporary file is `flock`ed by its
fetch; the age floor covers the window between creating a file and locking it.

**ES-31** `ServiceMaxSize` MUST be at most `CacheCapacity`, else the config is
exit 4. Config keys (flat JSON5, as in the README) and their defaults.
`CacheCapacity` and `ServiceMaxSize` are integers in bytes; `ServiceTimeout`
and `ServiceIdleTimeout` are integers in milliseconds.

| Key | Default |
|---|---|
| `CacheCapacity` | 1073741824 (1 GiB) |
| `ServiceMaxSize` | 268435456 (256 MiB) |
| `ServiceTimeout` | 600000 (600 s) |
| `ServiceIdleTimeout` | 30000 (30 s) |
| `AllowHTTP` | false |
| `AllowLocal` | false |

## Commands

- `ext resolve <dig>` follows ES-1. On a service hit it prints the cache path.
  The path is valid until the next `ext` write; a consumer that needs bytes
  MUST use `cat`. `--offline` consults layers 1 and 2 only.
- `ext cat [--offline] <alg>:<digest>` writes verified bytes to stdout (ES-11).
  It requires `Fetchable` (else exit 4). Exit codes are per ES-7. Nothing is
  written to stdout before verification completes; once it has, a closed pipe
  is the consumer's choice and is not an error.
- `ext -r` and `ext -u` accept service URIs (ES-22).

**ES-32** `--offline` MUST cause no DNS lookup and no connection.

**ES-33** The store layout (the SQLite file and the cache paths) is internal
and not an interface. A separate hosting binary MUST use `ext --d <store> cat
--offline <alg>:<digest>` as the supported read path. Absence is exit 1, so a
host maps it to 404; 2 (an indexed file no longer matches) and every other
nonzero code are server errors. `ext` cannot and does not prevent other
access. Authorising callers is the host's job.

## Forbidden states

- F1: a cache record without a verified complete file.
- F2: delivered or cached bytes whose hash differs from the requested digest.
- F3: a service contacted while a layer answers, or for a non-`Fetchable`
  digest.
- F4: a connection to a non-global-unicast address without `AllowLocal`.
- F5: a method other than GET, a header outside ES-18, or any credential sent.
- F6: an unbounded read, write, wait or redirect chain.
- F7: a file path derived from service data.
- F8: service text outside 0x20-0x7E on a terminal.
- F9: the write lock held across a network wait.
- F10: a partial file under a final name (services file, cache).

## Next backends

Not part of version 1; requirements are to come.

**ssh** (`ssh://host/<store>`, running remote `ext --d <store> cat
--offline`): `--` before the host; reject a host, user or store starting with
`-`; port 1-65535; an absolute store without `..`; the system `ssh` with
`BatchMode=yes`, `ClearAllForwardings=yes`, no agent forwarding, host-key
checking on and an environment allow-list. Remote stdout is a `Candidate` under
ES-12 and ES-13; ssh exit 255 is `Error`, remote exit 1 is `Missing`.

**snix-castore** (BLAKE3, gRPC `BlobService.Read`): needs BLAKE3 among the Coz
algorithms and in the client. The protocol is documented as unstable and no
client crate is published, so it is a helper. Streams obey ES-12 and ES-13.

**Helpers** (`ext-service-<scheme>`): hash and admit only after the helper and
its process group have exited (or read from a pipe, never a path the helper can
keep open); `PATH` without empty or `.` elements; an environment allow-list;
bounded protocol lines; behaviour when elevated.

**Excluded.** git: object ids hash `blob <len>\0` plus the content, so no
content digest names one. `printf abc | git hash-object --stdin` gives
`f2ba8f8...` while `sha1sum` gives `a9993e3...`.
