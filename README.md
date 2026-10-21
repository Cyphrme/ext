DRAFT
# Extant: Hash Based Naming, `/dev/ext`

`/dev/ext`, "extant", is a character special file that contains all registered
digests on a system. It also supports subdirectories.

## /dev/ext

On unix systems, `/dev/null` is for nothing.  It is a black hole.

In the same way there should be a white hole, `/dev/ext`, "ext" being short for
"extant". "extant" coming from the Latin meaning "to exist".

`/dev/ext` is an index for all content addressable files on the system.

Using a symbolic link, this file then can be used as a database:

For example:
ln -s target /dev/ext /var/www/website_name/content

Then URLs may look like:

List of existing sources or sinks:
- /dev/null
- /dev/full
- /dev/zero
- /dev/random
- /dev/urandom

# Goals
 - Provide hash based addressing on a system wide and subdirectory basis.
 - Provide cryptographic integrity to files.
 - Explicitly support external blob services.

## Digest Naming
**Hash URI** - Names bytes by digest. The following URI requires support by
implementing systems (such as a browser):

```
hash://SHA-256:oDBDAg4xplHQby6iQ2lZMS1Jz4Op0bNoD5LK3KxEUZo
```

**Hash Storage**

Storage uses __reverse digest naming__. This provides a global namespace for all
hashes. 

oDBDAg4xplHQby6iQ2lZMS1Jz4Op0bNoD5LK3KxEUZo:SHA-256


**Human Naming**
If the human name doesn't exist ext does not return the value even if the digest
exists. (If the human name doesn't exist ext returns nothing.) Why? If you don't
need the human name, don't use it. The alg with the value can always be sent.
If the human readable value is sent, ext forces interpretation.

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
however they would like. The follow are a few examples:

Page:
https://cyphr.me/example:SHA-256:2rfHUI84JBkIziYcLmvg4Dbjkr4B_md0gCupblX_JU8

Asset:
https://cyphr.me/File:Example:SHA-256:2rfHUI84JBkIziYcLmvg4Dbjkr4B_md0gCupblX_JU8.png

Simple blog service:
https://cyphr.me/e/SHA-256:2rfHUI84JBkIziYcLmvg4Dbjkr4B_md0gCupblX_JU8



### Hash Scheme 

**Hash Scheme Grammar**

```
hash-uri = "hash://" alg ":" digest [tail]
scheme   = "hash://"
alg      = 1 * (ALPHA / DIGIT / "-")      ; Coz alg. No ":".
digest   = 1*b64ut
b64ut    = ALPHA / DIGIT / "-" / "_"    ; RFC 4648 base64url, no pad
tail     = <any run starting at first non-b64ut>
```

Scheme match is case-insensitive. `alg` and `digest` are case-sensitive. `alg`
uses Coz labels (`SHA-256`, not `sha-256`).

### Parse

1. After `hash://`, split on first `:`.
2. `digest` is the longest b64ut prefix of the remainder. First non-b64ut char
   starts `tail`.
3. Strict b64ut decode. Non-canonical encoding errors.
4. Decoded length must equal `alg`'s digest size. Else error.

Identity = (`alg`, raw digest bytes). `tail` is not identity.

SHA-256 is 32 bytes, 43 b64ut chars. Full digest only. No truncate. No hex. No
`=`.

## Registry and Indexes
`/dev/.ext/` directory stores indexes and registrations.

**Registry**
The is kept in `/dev/.ext/registry`.  It is simply a list of paths and URIs, new
line delimited.  For example, a to register a whole system the registry would
contain simply the root path, `/`.

**Indexes**
Indexes are kept in `/dev/.ext/<index_name>`.

Required:
Source: <digest>:<path>

Optional:
Path Index: <path>:<digest>
Tag:        <tag>:<digest>
Cache:      <digest>:<path>
Cache Time: <digest>:<time>

## Registration
Files may be registered by `ext -r <path>`.  The simplest registration is simply
registering the whole system, `/`.

**Subdirectory Registration**
Subdirectories may be registered.

`/dev/.ext/<subdirectory_extant_path>`

For example, `/home/z/webserver/asset`, registered as an ext appears as 

`/dev/.ext//home/z/webserver/asset`

**External Service Registration**
External services may be registered via 

`ext -r <URI>`

For example:
`ext -r https://cyphr.me/e`


## Extant server
Instead of integrating with the system at a kernal level, this tool is designed
first as a stand alone server. OS integration is a later TODO.




## Unix Tools
As noted, `/dev/ext` and subdir extants `/dev/.ext/<path>` are character special
files. 
 - `cat` lists all digests in the source index.
 - `ls` simply prints the extant, such as `/dev/ext`, just as it does with
   `/dev/null`, `dev/random` and other such special files.



## Bases
Both Base64 (b64ut) and Hex (upper case) are supported.  However the default is
b64ut.

## Truncation
Truncation is supported but disabled by default.

Example:
Full hash: SHA-256:2rfHUI84JBkIziYcLmvg4Dbjkr4B_md0gCupblX_JU8
Truncated: SHA-256:2rfHUI84JBkIziY

Note that the strength of the integrity protection is lessened with truncation.

## Caching
The cache is used for external services. After external retrieval the digest is
added to the cache.  The cache is an Least Recently Used (LRU) Unix time cache.

The order of operations for the lookups is:

1. Local lookup
2. Local cache
3. Query external services

The cache has two indexes which provides O(n) lookups, the Cache Index comprised
of <dig>:<path> and the Cache Time Index, comprised of <dig>:<time>.  Once the
cache reaches capacity, the oldest items are removed.

## Collisions
If using a non-cryptographic hash, or in the case of a broken hash. 

**Recursion**
Recursion is not supported. If an ext path contains another ext, it is ignored.


### Tail

Optional. Suggested: `;ct=type`, `?src=url`, `/label`. Resolution is out of
scope.

### Coz

`hash://` + Coz external form `ALG:b64ut`. Same value as `SHA-256:…` and
`coz:SHA-256:…`.

### Non-goals
- Not a transport. 
- Not a multi-hash registry. Not ni:. Not hex. Not a filename standard.

## Config Flags
The config is saved in /dev/.ext/

Flag - Default Value - Description
- Aware      - True - the system only supports digests specified by ext.
- Truncation - False - Supports truncation.
- Unlabeled  - False - Do not require digest labeling. (Security concern)

## Commands

`ext -r` - registration Supports both files and directories
`ext -u` - unregister (Deleting a directory also unregisters)
`ext -check` - Re-hash all files and compare digests
`ext -rerun` - rebuild all indexes and re-hash all files.


## Technical Considerations

**System Awareness** - Exant is designed so that system doesn't need necessarily
need to be aware of a

**The Mining Problem** although collisions may be very difficult, even in weak
hashes, specific ranges may be targeted.

The architecture should not assume a uniform, normal distribution of digests.
Instead, it should assume an irregular, unbalanced distribution to avoid any
problems with distribution. 

For example, sharding should not be naive. Sharding should measure the sizes in
different directories.

**Size Ambiguity** Digests without labels may have an unknown size.

**Other Operating Systems Consideration** We do not foresee any problems with
other Unix systems.

**Windows Considerations** There are no naming conflicts with windows except
`:`.  We suggest `_` is used instead.

**/dev/random
 /dev/random , waits for CSPRNG to fully initialized on boot. It never
blocks after bootup after 5.6.

- /dev/random <- May block under low entropy
- /dev/urandom <- non-blocking, including boot up

## FAQ
- base85: We considered base85 support but it appears to be too problematic with
Unix file naming.


## See also 
 - https://github.com/Cyphrme/Coz
 - https://github.com/Cyphrme/Path