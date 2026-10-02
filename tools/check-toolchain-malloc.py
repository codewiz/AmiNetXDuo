#!/usr/bin/env python3
"""Verify the pinned newlib allocator in every installed toolchain multilib.

The 16.2.2 packages shipped a bootstrap libc despite pinning fixed newlib
source. For each immutable asset series, compare installed malloc.o bytes
against the known-good newlib build, in both libc.a and libg.a. A future
source, compiler, or flag change must deliberately update this map and its
runtime Enforcer proof; unknown bytes fail closed.
"""

import hashlib
import pathlib
import subprocess
import sys


# Paths are relative to <prefix>/m68k-amigaos/lib. The paired libc/libg
# archive members must match for each variant. One map per asset series; every
# archive in a prefix must match the same series.
EXPECTED_MALLOC_SHA256 = {
    # newlib at -O2 -fomit-frame-pointer. Eight distinct hashes, eleven multilibs.
    "16.2.3": {
        "": "0f2522d271d7094be4c9dd974e24634d13b6af150fd48fc8de89caf1ab4f2c22",
        "libm020": "1531c3f1489f4d1a19b53d69e3fcb3a17abbce21c49216151c323dbdb7e00144",
        "libm020/libm881": "1531c3f1489f4d1a19b53d69e3fcb3a17abbce21c49216151c323dbdb7e00144",
        "libm060": "a60a7c7e936c87f661d7b23430d7f908d5b902c1131dbf5eae792a54a94c4e91",
        "libb": "0085a784fa1bbe184f322df4ae1b48413a0c421ca1daf570d491c4fcc8798316",
        "libb/libm020": "af379f9fbe7da3bab6a5476c094147415e55ea7e9c491d4d94676f17b145e1b1",
        "libb/libm020/libm881": "af379f9fbe7da3bab6a5476c094147415e55ea7e9c491d4d94676f17b145e1b1",
        "libb/libm060": "c486aa7719ae6bedd46d82a37609951019df6d29ad135558c10a5c2285347a3b",
        "libb32/libm020": "07c5767e7ec8e7dd31c3649cab559b9cb5a498743cb3976ff9b5adda352352a2",
        "libb32/libm020/libm881": "07c5767e7ec8e7dd31c3649cab559b9cb5a498743cb3976ff9b5adda352352a2",
        "libb32/libm060": "f7f63dad7cb7ff955678a50a2f778ce46a8988ee2c9ed683e17cf6dd98b5f188",
    },
    # newlib at -Os -fomit-frame-pointer. Eight distinct hashes, eleven multilibs.
    # The fresh-page prev store (malloc.cpp:593) is `move.l 24(sp),4(a0)`:
    # find()'s null result, spilled before __sys_alloc, not a clr.l.
    "16.2.4": {
        "": "8ea1e8bb23083c50a8f391e56264b731e1f9787df4a45628445ea59ee605dbea",
        "libm020": "e7b1be5336bac70a25008e1f14bee229b6788f06934b1667f336a007dce5c21b",
        "libm020/libm881": "e7b1be5336bac70a25008e1f14bee229b6788f06934b1667f336a007dce5c21b",
        "libm060": "966703699ca1463a8c0abfdd772f8d86af788098949da0565541d0cc8b7f342b",
        "libb": "8185202bb931ddc973bc9804810f49fb402b2d99349146b0033d2d15aeefcbe8",
        "libb/libm020": "cd9c271067a7f4f67691923f776b1a7c976db0e37778c3f39cbdf95f0d57fdf2",
        "libb/libm020/libm881": "cd9c271067a7f4f67691923f776b1a7c976db0e37778c3f39cbdf95f0d57fdf2",
        "libb/libm060": "64cc78483d1cd8be8f07198e2d2392f4dbe7f70b50aea1d5ca278972072ef109",
        "libb32/libm020": "07087e90772a0193dfd50298d6aa36928bd6e2e6662eb29595e963517ecc9510",
        "libb32/libm020/libm881": "07087e90772a0193dfd50298d6aa36928bd6e2e6662eb29595e963517ecc9510",
        "libb32/libm060": "8147a07f4f8f3420414277802ff11823658d3eb48b92a89487aa19e728264e41",
    },
}


def main() -> int:
    args = sys.argv[1:]
    series = None
    if len(args) == 3 and args[0] == "--series" and args[1] in EXPECTED_MALLOC_SHA256:
        series = args[1]
        args = args[2:]
    if len(args) != 1:
        print(
            f"usage: {sys.argv[0]} [--series {'|'.join(EXPECTED_MALLOC_SHA256)}] <toolchain-prefix>",
            file=sys.stderr,
        )
        return 2
    prefix = pathlib.Path(args[0]).resolve()
    ar = prefix / "bin/m68k-amigaos-ar"
    gcc = prefix / "bin/m68k-amigaos-gcc"
    libdir = prefix / "m68k-amigaos/lib"
    if not ar.is_file() or not gcc.is_file() or not libdir.is_dir():
        print(f"missing cross-gcc, cross-ar or library directory under {prefix}", file=sys.stderr)
        return 1

    failures = []
    multilibs = subprocess.run(
        [str(gcc), "-print-multi-lib"], check=False, capture_output=True, text=True
    )
    if multilibs.returncode:
        print("cross-gcc could not enumerate multilibs", file=sys.stderr)
        return 1
    compiler_variants = set()
    for line in multilibs.stdout.splitlines():
        if line.strip():
            variant = line.split(";", 1)[0]
            compiler_variants.add("" if variant == "." else variant)
    variants = set(EXPECTED_MALLOC_SHA256["16.2.3"])
    if compiler_variants != variants:
        failures.append(
            "compiler multilib paths differ from pinned allocator map: "
            f"{sorted(compiler_variants)}"
        )

    for archive_name in ("libc.a", "libg.a"):
        expected = {
            str(pathlib.PurePosixPath(variant) / archive_name)
            for variant in variants
        }
        actual = {
            archive.relative_to(libdir).as_posix()
            for archive in libdir.rglob(archive_name)
        }
        for extra in sorted(actual - expected):
            failures.append(f"m68k-amigaos/lib/{extra}: unexpected unverified multilib")
    got = {}
    for variant in sorted(variants):
        for companion in ("crt0.o", "libm.a"):
            path = libdir / variant / companion
            if not path.is_file():
                failures.append(f"{path.relative_to(prefix)}: missing multilib companion")
        for archive_name in ("libc.a", "libg.a"):
            archive = libdir / variant / archive_name
            if not archive.is_file():
                failures.append(f"{archive.relative_to(prefix)}: missing archive")
                continue
            result = subprocess.run(
                [str(ar), "p", str(archive), "malloc.o"],
                check=False,
                capture_output=True,
            )
            if result.returncode or not result.stdout:
                failures.append(f"{archive.relative_to(prefix)}: missing malloc.o")
                continue
            got[archive] = (variant, hashlib.sha256(result.stdout).hexdigest())

    # Every archive must match one series; a prefix mixing two fails.
    candidates = [series] if series else list(EXPECTED_MALLOC_SHA256)
    matched = [
        name for name in candidates
        if all(h == EXPECTED_MALLOC_SHA256[name].get(v) for v, h in got.values())
    ]
    if not matched:
        # Report against the nearest series: a mixed prefix names its strays.
        near = max(
            candidates,
            key=lambda name: sum(
                h == EXPECTED_MALLOC_SHA256[name].get(v) for v, h in got.values()
            ),
        )
        want = EXPECTED_MALLOC_SHA256[near]
        for archive, (variant, h) in got.items():
            if h != want.get(variant):
                failures.append(
                    f"{archive.relative_to(prefix)}: malloc.o {h}, want {want.get(variant)}"
                    f" ({near})"
                )

    if failures:
        print("toolchain allocator verification FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        "toolchain allocator verification passed: 11 libc and 11 libg multilibs,"
        f" series {matched[0]}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
