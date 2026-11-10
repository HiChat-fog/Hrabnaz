# Embedded kernel BTF

Hrabnaz carries a BTF profile for each supported kernel release inside the
binary. aya performs CO-RE relocation in user space and needs the target
kernel's type layout. Kernels from 3.10 through 5.7 usually do not expose
`/sys/kernel/btf/vmlinux`, so the profile ships with the binary.

The loader tries `HRABNAZ_BTF_PATH`, then `/sys/kernel/btf/vmlinux`, then the table
built from this directory.

## Files

`index.tsv` has one line per kernel release:

    release <TAB> blob <TAB> full_btf_sha256

`blob` is the first 16 hex characters of the SHA-256 of the trimmed BTF.
`full_btf_sha256` identifies the source BTF the blob was cut from.

`blobs/<blob>.min.btf` holds the trimmed BTF. Each file contains only the types
and fields the three CO-RE objects (`hrabnaz_main_modern.o`, `hrabnaz_main_legacy.o`,
`hrabnaz_main_ancient.o`) reference. Point releases of the same kernel line share a
type layout, so many releases map to one blob. 425 releases currently use 149
blobs, 322 KB in total.

## Build

`crates/hrabnaz-engine/build.rs` reads `index.tsv`, checks that every blob exists and
that its name matches its content hash, then generates the release table for
`hrabnaz_engine::btf_source`. The build needs neither `bpftool` nor the full BTF
files.

## Add a kernel

    scripts/btf-fetch.sh 4.19.0-27-amd64
    scripts/btf-regen.sh --add 4.19.0-27-amd64

The fetch script caches `<release>.btf.tar.xz` under
`~/.cache/hrabnaz/btf-full`. The regen script extracts it, runs
`bpftool gen min_core_btf`, and writes the blob and index line. Commit the new
line in `index.tsv` and any new file under `blobs/`.

A point release usually reuses an existing blob, so the commit often contains
only the index line.

## Regenerate after eBPF changes

The relocation test checks every embedded blob against the current objects:

    cargo test -p hrabnaz-engine --test btf_relocation_test

If it reports missing types, rebuild the set:

    scripts/btf-regen.sh --all

`--all` fetches any missing archives, trims every release again, and rewrites
`index.tsv`. The build output must exist first (`cargo build -p hrabnaz-engine`).

## Checks

    scripts/btf-regen.sh --check

This verifies the index, the blob hashes and, for cached archives, the source
hash. It also lists blobs that no index line references.

## Support boundary

A release is supported when it has an index line and its blob passes the
relocation test. A kernel that is not listed can still run on modern tiers with
`/sys/kernel/btf/vmlinux`, or with `HRABNAZ_BTF_PATH` pointing at a BTF file.

## Source and license

The files are trimmed from releases in
[aquasecurity/btfhub-archive](https://github.com/aquasecurity/btfhub-archive),
which is distributed under the Apache License 2.0. The `full_btf_sha256` column
ties each blob to its source BTF.
