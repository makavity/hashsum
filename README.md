# hashsum

CLI to print or verify cryptographic checksums (md5, sha1, sha2 family, belt-hash).

## Install

From local path:

```bash
cargo install --path /Users/makavity/dev/crypto/hashsum
```

From Git repository:

```bash
cargo install --git <git-url> hashsum
```

From crates.io (after publishing):

```bash
cargo install hashsum
```

## Usage

```bash
hashsum [OPTIONS] [FILE]...
```

- When no `FILE` is given, or when `-` is used, input is read from stdin.
- Default algorithm is `md5`.

### Options

- `-a, --algorithm <ALG>`: Hash algorithm (`md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `belt-hash`)
- `-c, --check`: Read checksums from the given files and verify them
- `--ignore-missing` (with `--check`): Do not fail on missing files
- `-q, --quiet` (with `--check`): Do not print `OK` for each successfully verified file
- `--status` (with `--check`): Do not print anything; use exit status only
- `--strict` (with `--check`): Treat malformed lines as fatal errors
- `-w, --warn` (with `--check`): Warn about malformed lines

## Algorithms

- md5
- sha1
- sha224, sha256, sha384, sha512
- belt-hash

## Output format

When computing hashes:

```text
<hex-digest>  <filename>
```

When verifying with `--check`, the input format supported is compatible with common tools:

```text
<hex-digest>  <filename>
<hex-digest> *<filename>
```

On success (unless `--quiet` or `--status`):

```text
<filename>: OK
```

On mismatch:

```text
<filename>: FAILED
```

## Examples

Compute SHA-256 of a file:

```bash
hashsum -a sha256 path/to/file
```

Verify checksums listed in `checksums.txt`:

```bash
hashsum --check checksums.txt
```

Read from stdin:

```bash
cat file | hashsum -a sha1 -
```

## Exit codes

- `0`: success (all requested operations succeeded)
- `1`: at least one file failed, IO error, or malformed line in strict mode


