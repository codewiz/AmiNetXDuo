#!/usr/bin/env python3
"""Verify the pinned newlib allocator in every installed toolchain multilib.

The 16.2.2 packages shipped a bootstrap libc despite pinning fixed newlib
source. For each immutable asset series, compare installed malloc.o bytes
against the known-good newlib build, in both libc.a and libg.a. A future
source, compiler, or flag change must deliberately update this map and its
runtime Enforcer proof; unknown bytes fail closed.

Series whose MemMap::alloc calls __sys_alloc out of line (16.2.4) are also
proven structurally: both fresh allocations, the big node (malloc.cpp:578)
and the small page (malloc.cpp:593), must store zero to Node::prev at 4(aN)
before the next call or return. --object FILE checks one malloc.o that way.
"""

import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile

# Series proven structurally as well as by hash.
STRUCTURAL_SERIES = ("16.2.4",)


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


def _alloc_body(objdump, obj):
    out = subprocess.run([objdump, "-d", str(obj)], check=True,
                         capture_output=True, text=True).stdout
    body, inside = [], False
    for line in out.splitlines():
        if re.match(r"^[0-9a-f]+ [0-9a-f]+ __ZN6MemMap5allocEj:$", line):
            inside = True
            continue
        if inside and re.match(r"^[0-9a-f]+ [0-9a-f]+ \S+:$", line):
            break
        if inside and "\t" in line:
            body.append(line.split("\t")[-1].strip())
    return body


def _is_call(ins):
    return ins.startswith(("jsr", "bsr", "jbsr"))


def prev_stores(objdump, obj):
    """One verdict per __sys_alloc call in MemMap::alloc: proven or why not."""
    body = _alloc_body(objdump, obj)
    verdicts = []
    for i, ins in enumerate(body):
        direct = _is_call(ins) and "__sys_allocj" in ins
        via = (_is_call(ins) and re.fullmatch(r"jsr \((a\d)\)", ins)
               and any("__sys_allocj" in b and b.endswith("," + ins[5:7])
                       for b in body[max(0, i - 3):i]))
        if not (direct or via):
            continue
        m = re.fullmatch(r"movea\.l d0,(a\d)", body[i + 1] if i + 1 < len(body) else "")
        if not m:
            verdicts.append("result not kept in an address register")
            continue
        reg = m.group(1)
        found = None
        for ins2 in body[i + 2:]:
            if _is_call(ins2) or ins2 == "rts":
                break
            if ins2.endswith("," + reg) and not ins2.startswith(("cmp", "tst")):
                break                                   # result register overwritten
            if ins2 == f"clr.l 4({reg})":
                found = "clr"
                break
            st = re.fullmatch(r"move\.l (\d+)\(sp\),4\(" + reg + r"\)", ins2)
            if st and _spilled_null(body[:i], st.group(1)):
                found = "spilled null"
                break
        verdicts.append(found or "no zero store to 4(%s)" % reg)
    return verdicts


def _spilled_null(before, slot):
    """True if slot holds a register proven zero by `movea.l d0,aY; tst.l d0; b{ne}`."""
    for k in range(len(before) - 1, -1, -1):
        m = re.fullmatch(r"move\.l (a\d),%s\(sp\)" % slot, before[k])
        if m:
            reg = m.group(1)
            for j in range(k - 1, 1, -1):
                if before[j].endswith("," + reg) or _is_call(before[j]):
                    return (before[j] == f"movea.l d0,{reg}"
                            and before[j + 1] == "tst.l d0"
                            and before[j + 2].startswith("bne"))
            return False
        if before[k].endswith(",%s(sp)" % slot):
            return False
    return False


def structural(objdump, obj):
    verdicts = prev_stores(objdump, obj)
    if len(verdicts) != 2:
        return f"{len(verdicts)} __sys_alloc call(s) in MemMap::alloc, want 2"
    bad = [v for v in verdicts if v not in ("clr", "spilled null")]
    return "; ".join(bad) if bad else None


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == "--object":
        objdump = pathlib.Path(args[2]).resolve() / "bin/m68k-amigaos-objdump"
        why = structural(str(objdump), args[1])
        verdicts = prev_stores(str(objdump), args[1])
        print(f"malloc_prev_stores={','.join(v.replace(' ', '_') for v in verdicts) or 'none'}"
              f" result={'fail' if why else 'pass'} object={args[1]}")
        return 1 if why else 0
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
    objects = {}
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
            objects[archive] = result.stdout

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

    if matched and matched[0] in STRUCTURAL_SERIES:
        objdump = str(prefix / "bin/m68k-amigaos-objdump")
        with tempfile.TemporaryDirectory() as tmp:
            for archive, data in objects.items():
                obj = pathlib.Path(tmp) / "malloc.o"
                obj.write_bytes(data)
                why = structural(objdump, obj)
                if why:
                    failures.append(f"{archive.relative_to(prefix)}: malloc.o prev stores: {why}")

    if failures:
        print("toolchain allocator verification FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        "toolchain allocator verification passed: 11 libc and 11 libg multilibs,"
        f" series {matched[0]}"
        + (", both prev stores proven" if matched[0] in STRUCTURAL_SERIES else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
