This is a cross-toolchain asset, not an AmiNetXDuo release.

GCC still reports 16.2.0b. Asset series 16.2.2 is built from the pinned
`tinic/gcc` commit `243a0096237cc382c075142c80acadad4e07b9e5`, based on
bebbo's `60f21496319754a0e35b1a8e52df9abbac188065`. The single GCC change
prevents an m68k sibling call from overwriting an outgoing a0 argument with
its call target. The same patch is proposed to AmigaPorts as
[PR #67](https://github.com/AmigaPorts/gcc/pull/67). The build driver also
applies a narrow `timersub()` fallback in pinned aros-stuff's libpthread so a
fresh build completes with current host compilers. All other source pins are
listed in `tools/build-toolchain.sh`.

| Host | Asset | Bytes | SHA-256 |
|---|---|---:|---|
| Linux x86-64 | `m68k-amigaos-gcc-16.2.2-ndk3.9-linux-x86_64.tar.xz` | 37,898,936 | `3e57867837642ddf4b3586ceffd9aa83f52f42f2ca865961022bcbda32c77212` |
| macOS arm64 | `m68k-amigaos-gcc-16.2.2-ndk3.9-darwin-arm64.tar.xz` | 32,727,128 | `2ebc324ca0aa51b982cb1eb86fe31886e3034e97089f352c3ce5bcf429e589c1` |

Both hosts built the full pinned toolchain and passed package/extract
round-trip comparison with no dangling symlinks. On macOS, the installed
compiler's regparm 1, 2, and 3 regression sources each pass the pointer
argument in a0 and use `jsr (a1)`, while safe integer and direct-call controls
retain their jumps. The GCC branch's seven new tests passed 21/21 assembly
scans in an independent DejaGnu-semantics replay, and the wider matrix found
77 lost-a0 cases before the patch and zero afterward. This was not a full
GCC `make check` run. These assets do not by themselves fix separate
application-level function-pointer ABI mismatches.
