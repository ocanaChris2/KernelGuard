# Contributing to KernelGuard

Thanks for helping. This is kernel-mode code: small, well-tested changes are much easier to review
than large ones.

## Ground rules

- **Never load the module or driver on a machine you depend on.** On Linux use the QEMU harness
  (`make -C linux test`); on Windows use a disposable VM snapshot. See the README's warnings.
- One logical change per pull request; keep the diff focused.
- Match the surrounding code: kernel style in `linux/` (tabs, 80 columns where practical, `kg_`
  prefix), the existing style in `windows/`.
- New behaviour needs a test (`linux/tests/vm/guest/*.sh` for the module, the known-answer tests
  in `linux/monitor` for `kgmon`) or a note explaining why it cannot be tested.
- Changes to `windows/` that you could not build or run must say so in the PR. `tools/wdk_syntax_check.py` is
  a compile check only; it does not replace an MSBuild build or a run on Windows.

## Building

```sh
./build.sh                 # interactive: asks what to build (Linux: make; Windows: MSBuild + WDK)
make -C linux              # module + kgmon for the running kernel
make -C linux KVER=<ver>   # against another installed header tree
```

## Testing

```sh
make -C linux check        # kgmon known-answer tests (no root, loads nothing)
make -C linux test         # boots a QEMU/KVM guest and runs the module tests there
python3 tools/version.py   # embedded versions match VERSION
python3 tools/wdk_syntax_check.py   # windows/ sources type-check against the WDK/SDK headers (clang; compile only)
python3 tools/test_pe_authenticode.py   # windows/src/pe_authenticode.c against real signed binaries (add --sanitize)
python3 tools/test_digest_table.py      # windows/src/digest_table.c against the generated table (add --sanitize)
python3 tools/import_loldrivers.py --check   # is windows/src/vuln_driver_hashes.h (generated) out of date?
python3 tools/test_blocklist_db.py      # tools/blocklist_db.py on a synthetic dataset (no network)
reuse lint                 # licence headers / REUSE.toml
markdownlint-cli2 "**/*.md"
```

`make test` needs `qemu-system-x86_64`, `busybox`, `cpio`, kernel headers for `KVER`, and a
readable kernel image (`KG_KERNEL=/path/to/vmlinuz`); see the header of
`linux/tests/vm/run-vm.sh`.

## Commits and pull requests

- Imperative subject line (about 72 characters), body explaining *why*.
- Add a `CHANGELOG.md` entry under **Unreleased** for anything user-visible.
- Licence: contributions to `linux/` are GPL-2.0-only; everything else MIT (see `LICENSE`). New
  source files in `linux/` need a GPL-2.0-only SPDX license header (copy one from a neighbouring file).

## Conduct

Be respectful and assume good faith. Harassment or personal attacks are not tolerated; maintainers
may remove comments or block accounts that engage in them.

## Security issues

Do not file public issues for vulnerabilities: follow [SECURITY.md](SECURITY.md).
