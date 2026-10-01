#!/usr/bin/env python3
#
# Every call that crosses a calling-convention boundary is pinned.
#
#   tools/check-call-abi.py [--root DIR] [--selftest] [--verbose]
#
# The m68k build passes arguments in registers (-mregparm=3).  Anything the C
# compiler does not see as one convention on both sides has to say which one
# it uses: hand-written assembly, the compiler's own runtime calls, the OS,
# and a driver or library from another build.  GCC treats a stack-pinned and
# an unpinned function pointer as the same type and says nothing when one is
# stored in the other, so six of these shipped one at a time (#123, 482f7b17,
# nx_crypto_mem.h, #124, #125, #126).  This reads the source and refuses:
#
#   asm-decl    a C declaration of a routine assembly defines, with no stack
#               pin (AMIGA_ASM_ARGS, __stdargs) visible in its translation
#               unit -- 482f7b17's Supervisor stubs, #124, c68k_p256.h.
#   asm-call    a C function assembly calls by name that reads its arguments
#               in the build's registers -- the shape of ami_alert_report().
#   rt-helper   a definition or declaration of a compiler runtime entry point
#               (__udivsi3 ...) without the pin, or a memcpy/memset/memmove/
#               memcmp definition that cannot see <string.h> -- #123.
#   slot        a function stored into, or passed as an argument for, a
#               pointer of another convention: a plain C function in a pinned
#               vector (#125), a stack-pinned one such as libc's memcpy in an
#               unpinned pointer (nx_crypto_mem.h).
#   escape      a function with arguments whose address leaves the type system
#               -- (APTR)fn, (ULONG)fn, (HOOKFUNC)fn, a vector table -- with
#               neither a pin nor a register for every argument.  Whoever
#               calls it next does not know our convention.
#   shared-type a function-pointer type in a header another binary compiles
#               (include/aminetxduo, developer/include, a fork's copy of one)
#               with no pin and no registers -- #126.
#   libc-decl   our own declaration of a libc or amiga.lib routine that
#               cannot see the toolchain header's __stdargs one.
#   varargs     a function declared with `...' in one place and without it in
#               another: one side pushes everything, the other reads registers.
#
# A function with no arguments, a variadic one, and one with an __asm("reg")
# on every argument are convention-free and always pass.
#
# It reads every branch of every #if, so a crossing in a configuration nobody
# builds today is still a finding -- c68k_p256.h was one, in the 68020 tree.
# A pin is visible to a declaration when it is in the same file or one it
# includes, which is exactly when GCC merges it.
#
# tools/check-call-abi-allow.txt names the crossings that are right as they
# are, each with its reason; a stale entry is itself a failure.
#
# Output: one `call_abi=fail rule=... file=... line=... name=...` line per
# finding, then `call_abi=ok|fail files=N asm_symbols=N findings=N`.
# Exit 0 clean, 1 on a finding, 2 on a usage error.
#
# SPDX-License-Identifier: MIT

import bisect
import os
import re
import sys

PIN_WORDS = {"AMIGA_ASM_ARGS", "__stdargs", "__stkparm__", "stkparm"}
REG_WORDS = {"REGARG", "__reg"}

KEYWORDS = {
    "if", "while", "for", "switch", "return", "sizeof", "else", "do", "case",
    "goto", "__attribute__", "__asm__", "__asm", "asm", "__volatile__",
    "__typeof__", "typeof", "_Static_assert", "static_assert", "defined",
    "__builtin_offsetof", "offsetof", "_Alignof", "__alignof__",
}

# The C library this toolchain links: every one is declared __stdargs in its
# headers, so a pointer to one is a pointer to a stack-convention function.
LIBC_STACK = {
    "memcpy", "memset", "memmove", "memcmp", "memchr", "strlen", "strcmp",
    "strncmp", "strcpy", "strncpy", "strcat", "strncat", "strchr", "strrchr",
    "strstr", "malloc", "calloc", "realloc", "free", "exit", "abort",
    "printf", "sprintf", "snprintf", "vsnprintf", "vsprintf", "fprintf",
    "puts", "putchar", "qsort", "bsearch", "atoi", "atol", "strtol",
    "strtoul", "time", "rand", "srand",
}

# amiga.lib, linked from the toolchain and built the same way; its header
# (clib/alib_protos.h) pins every one.
ALIB_STACK = {
    "NewList", "BeginIO", "CreateExtIO", "DeleteExtIO", "CreatePort",
    "DeletePort", "CreateStdIO", "DeleteStdIO", "CreateTask", "DeleteTask",
    "TimeDelay", "FastRand", "RangeRand", "CallHookA", "CallHook",
    "DoMethodA", "DoMethod", "HookEntry", "ACrypt", "ArgArrayInit",
    "ArgArrayDone", "ArgString", "ArgInt", "HotKey", "InvertString",
}
SYSTEM_PINNING = {"string.h", "stdlib.h", "stdio.h", "clib/alib_protos.h",
                  "proto/alib.h", "clib/alib_stdio_protos.h"}

# GCC emits calls to these by name during expansion and pushes their
# arguments whatever -mregparm says (src/common/ami_udivdi3.c).
RT_HELPER_RE = re.compile(
    r'^__(?:(?:u?(?:div|mod))|mul|ashl|ashr|lshr|neg|cmp|ucmp|clz|ctz|ffs|'
    r'popcount|parity|bswap)[sdt]i[23]$')
# ... and these by name for block moves, with the same stack arguments
# (src/net68k/n68k_memcpy_hook.c).
RT_STRING = {"memcpy", "memset", "memmove", "memcmp"}

UNTYPED_CASTS = (r'APTR|CONST_APTR|ULONG|IPTR|LONG|HOOKFUNC|'
                 r'(?:const\s+)?(?:void|VOID|char|UBYTE|UCHAR)\s*\*|'
                 r'(?:VOID|void|ULONG|LONG|BOOL|int|APTR)\s*\(\s*\*\s*\)\s*'
                 r'\(\s*(?:VOID|void)?\s*\)')
CAST_RE = re.compile(r'\(\s*(?:' + UNTYPED_CASTS + r')\s*\)\s*&?\s*'
                     r'([A-Za-z_]\w*)\b(?!\s*(?:\(|\[|\.|->))')

EQ_RE = re.compile(r'(?<![=!<>+\-*/%&|^])=(?!=)')
RHS_RE = re.compile(r'\s*(?:\([^()]*\)\s*)?&?\s*([A-Za-z_]\w*)\s*;')
OS_CALL_RE = re.compile(r'\b(?:AddTask|CreateTask|SetFunction|RawDoFmt|'
                        r'Supervisor|SetIntVector|AddIntServer|Cause|'
                        r'CreateNewProcTags|CreateNewProc|NewCreateTask|'
                        r'AddResetCallback|SetExcept)\s*\(')
ASM_DEF_RE = re.compile(r'\.glob(?:a)?l\s+(?:([CN]68K_MV_SYM)\s*\(\s*)?_(\w+)')
ASM_REF_RE = re.compile(
    r'(?:\b(?:jsr|jbsr|bsr|jmp|jra|bra)(?:\.[bswl])?\s+(?:%?pc@\()?'
    r'|\blea\s+|\bpea\s+|#|\.long\s+)'
    r'_([A-Za-z]\w*)')
MV_SUFFIX = r'(?:_mv\d+|_mulu|_mulw)'

INCLUDE_RE = re.compile(r'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"]+)[>"]', re.M)
DEFINE_RE = re.compile(r'^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(\()?[^\n]*?'
                       r'[ \t]+(.*)$', re.M)
FP_RE = re.compile(r'\(\s*\*\s*(?:(?:const|volatile|__volatile__|__volatile)'
                   r'\s+)*([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*\)\s*\(')
IDENT_RE = re.compile(r'[A-Za-z_]\w*')

# What a scan covers: our tree, and the parts of the forks the build compiles
# with our flags.  Host-only test drivers are left out -- the pins are no-ops
# off m68k and nothing there is linked into an image.
SCAN = [
    "src", "port", "include", "developer/include", "tests", "tools/profiler",
    "bench", "developer/examples", "install/test", "lto-repro",
    "third_party/netxduo/common", "third_party/netxduo/crypto_libraries",
    "third_party/netxduo/nx_secure/src", "third_party/netxduo/nx_secure/inc",
    "third_party/netxduo/nx_secure/ports",
    "third_party/netxduo/addons/auto_ip", "third_party/netxduo/addons/dhcp",
    "third_party/netxduo/addons/dns", "third_party/netxduo/addons/mdns",
    "third_party/threadx/common",
    "third_party/wifipi/src", "third_party/wifipi/include",
]
SKIP_DIR = {"host", "fuzz", "web", "node_modules", ".git"}
SHARED_HEADERS = ("include/aminetxduo/", "developer/include/")
# A copy of one of ours inside a fork is the same interface.
SHARED_COPY_RE = re.compile(r'(?:^|/)include/aminetxduo/[^/]+\.h$')


def is_host_only(rel):
    parts = rel.split("/")
    # src/<module>/test is the host suite (cmake/HostTests.cmake).
    if len(parts) > 2 and parts[0] == "src" and parts[2] == "test":
        return True
    if "shim" in parts:
        return True
    return False


# ------------------------------------------------------------- lexing ---

LEX_RE = re.compile(r'^[ \t]*#(?:[^\n\\]|\\.|\\\n)*'
                    r'|/\*.*?(?:\*/|\Z)|//[^\n]*'
                    r'|"(?:[^"\\\n]|\\.)*"?|\'(?:[^\'\\\n]|\\.)*\'?',
                    re.M | re.S)


def blank(text):
    """Comments to spaces, string and char literal bodies to spaces, and
    preprocessor lines to spaces; every newline kept.  Returns (code,
    strings) where strings is [(offset, body)] for asm scanning."""
    strings = []

    def spaces(t):
        if "\n" not in t:
            return " " * len(t)
        return "\n".join(" " * len(x) for x in t.split("\n"))

    def sub(m):
        t = m.group(0)
        c = t.lstrip(" \t")[:1]
        if c in "\"'" and len(t) < 2:
            return t            # a stray quote: keep every offset where it was
        if c == '"':
            body = t[1:-1] if len(t) > 1 and t.endswith('"') else t[1:]
            strings.append((m.start(), body))
            return '"' + " " * max(len(t) - 2, 0) + '"'
        if c == "'":
            return "'" + " " * max(len(t) - 2, 0) + "'"
        return spaces(t)

    return LEX_RE.sub(sub, text), strings


PAREN_RE = re.compile(r'[()]')
EXTERN_RE = re.compile(r'\s*extern\b')
CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(')


def match_paren(code, i):
    """code[i] is '(' -> index of the matching ')', or -1."""
    depth = 0
    for m in PAREN_RE.finditer(code, i):
        if code[m.start()] == "(":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return m.start()
    return -1


def split_params(params):
    out, depth, cur = [], 0, []
    for c in params:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    out.append("".join(cur))
    return [p.strip() for p in out]


# ------------------------------------------------------------ the model ---

STACK, REGS, PLAIN, ANY = "stack", "regs", "plain", "any"


class Ctx:
    def __init__(self, root):
        self.root = root
        self.pins = set(PIN_WORDS)
        self.regs = set(REG_WORDS)
        self.files = {}         # rel -> (code, strings, raw)
        self.includes = {}      # rel -> [rel]
        self.funcs = {}         # name -> [Decl]
        self.fptrs = []         # [Decl]
        self.asm_defs = {}      # name -> (rel, line, mv)
        self.asm_refs = []      # (name, rel, line)
        self.casts = []         # (name, rel, line)
        self.assigns = []       # (slot, func, rel, line)
        self.by_base = {}       # basename -> [rel]
        self.closure_cache = {}

    def conv_of(self, prefix, params, trailing=""):
        words = set(IDENT_RE.findall(prefix)) | set(IDENT_RE.findall(trailing))
        if words & self.pins:
            return STACK
        ps = [p for p in split_params(params) if p]
        if not ps or ps == ["void"] or ps == ["VOID"]:
            return ANY
        if ps[-1] == "...":
            return STACK
        regd = 0
        for p in ps:
            if (re.search(r'\b(?:__asm__|__asm|asm)\s*\(\s*"', p) or
                    set(IDENT_RE.findall(p)) & self.regs):
                regd += 1
        if regd == len(ps):
            return REGS
        return PLAIN


class Decl:
    __slots__ = ("name", "rel", "line", "conv", "kind", "is_def", "init",
                 "variadic", "params")

    def __init__(self, name, rel, line, conv, kind, is_def=False, init=None):
        self.name, self.rel, self.line = name, rel, line
        self.conv, self.kind, self.is_def, self.init = conv, kind, is_def, init
        self.variadic = False
        self.params = None


_NL = {}


def line_of(code, pos):
    nl = _NL.get(id(code))
    if nl is None or nl[0] is not code:
        nl = (code, [i for i, c in enumerate(code) if c == "\n"])
        _NL[id(code)] = nl
    return bisect.bisect_left(nl[1], pos) + 1


def ident_before(code, pos):
    """The identifier that ends just before pos, past spaces and one
    [subscript]; None if there is none."""
    i = pos - 1
    while i >= 0 and code[i] in " \t\n":
        i -= 1
    if i >= 0 and code[i] == "]":
        j = code.rfind("[", 0, i)
        if j < 0:
            return None
        i = j - 1
        while i >= 0 and code[i] in " \t\n":
            i -= 1
    end = i + 1
    while i >= 0 and (code[i].isalnum() or code[i] == "_"):
        i -= 1
    word = code[i + 1:end]
    return word if word and not word[0].isdigit() else None


def stmt_start(code, pos):
    """Back from pos to the start of the declaration it sits in: the
    previous ; { } at this depth, or a , ( at this depth."""
    depth = 0
    i = pos - 1
    while i >= 0:
        c = code[i]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                return i + 1
            depth -= 1
        elif c in ";{}" and depth == 0:
            return i + 1
        elif c == "," and depth == 0:
            return i + 1
        i -= 1
    return 0


def after_params(code, close):
    """Text after a parameter list up to ; { = or , -- attributes, asm
    labels -- and the character that ended it."""
    i = close + 1
    n = len(code)
    start = i
    while i < n:
        c = code[i]
        if c == "(":
            j = match_paren(code, i)
            if j < 0:
                break
            i = j + 1
            continue
        if c in ";{=,)":
            return code[start:i], c, i
        i += 1
    return code[start:i], "", i


# ------------------------------------------------------------- scanning ---

def collect_files(root):
    out = []
    for top in SCAN:
        base = os.path.join(root, top)
        if not os.path.isdir(base):
            continue
        for d, dirs, files in os.walk(base):
            dirs[:] = sorted(x for x in dirs if x not in SKIP_DIR)
            for f in sorted(files):
                if f.endswith((".c", ".h", ".S", ".s")):
                    rel = os.path.relpath(os.path.join(d, f), root)
                    if not is_host_only(rel):
                        out.append(rel)
    return out


def read(root, rel):
    with open(os.path.join(root, rel), "r", encoding="latin-1") as fh:
        return fh.read()


def macro_pass(ctx, raws):
    """Macros that expand to a pin, or to a register binding."""
    defs = []
    for raw in raws:
        for m in DEFINE_RE.finditer(raw):
            defs.append((m.group(1), bool(m.group(2)), m.group(3)))
    changed = True
    while changed:
        changed = False
        for name, fnlike, body in defs:
            words = set(IDENT_RE.findall(body))
            if not fnlike and name not in ctx.pins and words & ctx.pins:
                ctx.pins.add(name)
                changed = True
            if (name not in ctx.regs and
                    (re.search(r'\b(?:__asm__|__asm|asm)\s*\(', body) or
                     words & ctx.regs)):
                ctx.regs.add(name)
                changed = True


def scan_asm_text(ctx, rel, text, base_line):
    for m in ASM_DEF_RE.finditer(text):
        name = m.group(2)
        mv = bool(m.group(1))
        if name in ctx.asm_defs:
            # c68k_dispatch.S defines the plain name the _mulu/_mulw twins
            # of c68k_prim*.S stand behind; both facts hold.
            arel, aline, amv = ctx.asm_defs[name]
            ctx.asm_defs[name] = (arel, aline, amv or mv)
        else:
            ctx.asm_defs[name] = (rel, base_line(m.start()), mv)
    for m in ASM_REF_RE.finditer(text):
        ctx.asm_refs.append((m.group(1), rel, base_line(m.start())))


GAS_MACRO_RE = re.compile(r'^[ \t]*\.macro[ \t]+(\w+)[ \t,]*([^\n]*)\n(.*?)'
                          r'^[ \t]*\.endm\b', re.M | re.S)


def expand_gas_macros(text):
    """`.globl _bk_\\name` inside a .macro, and the lines that invoke it:
    append one plain `.globl _bk_add` per invocation, on its line, so the
    symbols a macro defines are as visible as the ones written out."""
    extra = []
    for m in GAS_MACRO_RE.finditer(text):
        name = m.group(1)
        params = [p.split("=")[0].strip() for p in re.split(r'[\s,]+', m.group(2))
                  if p.strip()]
        globs = re.findall(r'\.glob(?:a)?l\s+(_?\w*)\\(\w+)(?:\\\(\))?(\w*)',
                           m.group(3))
        if not globs:
            continue
        for inv in re.finditer(r'^[ \t]*' + re.escape(name) + r'[ \t]+([^\n]*)$',
                               text, re.M):
            args = [a.strip() for a in re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)',
                                                inv.group(1))]
            for pre, param, post in globs:
                if param in params and params.index(param) < len(args):
                    ln = text.count("\n", 0, inv.start())
                    extra.append((ln, ".globl %s%s%s" %
                                  (pre, args[params.index(param)], post)))
    if not extra:
        return text
    lines = text.split("\n")
    for ln, g in extra:
        lines[ln] = lines[ln] + " ; " + g
    return "\n".join(lines)


def scan_c(ctx, rel, code, strings):
    # Top-level asm in a C file: labels it defines and symbols it calls.
    for off, body in strings:
        if ".glob" in body or re.search(r'\b(?:jsr|jbsr|bsr|jmp|jra|lea|pea)\b'
                                        r'|#_', body):
            ln = line_of(code, off)
            scan_asm_text(ctx, rel, body, lambda _p, ln=ln: ln)

    stmt = 0
    body_kind = []      # stack: 'func' / 'struct' / 'init' / 'block' / 'linkage'
    for bm in re.finditer(r'[{};]', code):
        i = bm.start()
        c = code[i]
        if c == "{":
            text = code[stmt:i]
            kind = "block"
            if re.search(r'\bextern\s*"\s*"\s*$', text):
                kind = "linkage"    # extern "C" { -- still file scope
            elif not body_kind or body_kind[-1] in ("struct", "linkage"):
                t = text.rstrip()
                if re.search(r'=\s*$', t) or "=" in re.sub(r'\([^()]*\)', '', t):
                    kind = "init"
                elif re.search(r'\b(?:struct|union|enum)\b[^()]*$', t):
                    kind = "struct"
                elif t.endswith(")") or re.search(r'\)\s*(?:__attribute__\s*'
                                                  r'\(\(.*\)\)\s*)*$', t):
                    kind = "func"
                    func_decl(ctx, rel, code, stmt, i, True)
            elif body_kind[-1] == "init":
                kind = "init"
            body_kind.append(kind)
            stmt = i + 1
        elif c == "}":
            if body_kind:
                body_kind.pop()
            stmt = i + 1
        elif c == ";":
            outer = body_kind[-1] if body_kind else None
            if outer in (None, "linkage"):
                func_decl(ctx, rel, code, stmt, i, False)
            elif outer in ("func", "block"):
                if EXTERN_RE.match(code, stmt, i):
                    func_decl(ctx, rel, code, stmt, i, False)
            stmt = i + 1

    # Every function-pointer declarator, wherever it is.
    for m in FP_RE.finditer(code):
        name = m.group(1)
        st = stmt_start(code, m.start())
        prefix = code[st:m.start()]
        pwords = IDENT_RE.findall(prefix)
        stripped = prefix.strip()
        if (not pwords or "=" in prefix or pwords[-1] in KEYWORDS or
                not re.search(r'[\w*]$', stripped)):
            continue
        if re.search(r'\b(?:return|case|goto)\b', prefix):
            continue
        close = match_paren(code, m.end() - 1)
        if close < 0:
            continue
        params = code[m.end():close]
        trailing, end, at = after_params(code, close)
        conv = ctx.conv_of(prefix, params, trailing)
        kind = "typedef" if "typedef" in pwords else "slot"
        init = None
        if end == "=":
            im = re.match(r'\s*(?:\([^()]*\)\s*)?&?\s*([A-Za-z_]\w*)\s*[;,]',
                          code[at + 1:])
            if im:
                init = im.group(1)
        d = Decl(name, rel, line_of(code, m.start()), conv, kind, init=init)
        ctx.fptrs.append(d)

    # Casts that take a function's address out of the type system.
    for m in CAST_RE.finditer(code):
        ctx.casts.append((m.group(1), rel, line_of(code, m.start())))

    # A bare function name handed to the OS, which calls it in its own
    # convention: AddTask(t, fn, ...), SetFunction(lib, off, fn) ...
    for m in OS_CALL_RE.finditer(code):
        close = match_paren(code, m.end() - 1)
        if close < 0:
            continue
        for arg in split_params(code[m.end():close]):
            am = re.match(r'&?\s*([A-Za-z_]\w*)$', arg)
            if am:
                ctx.casts.append((am.group(1), rel, line_of(code, m.start())))

    # Assignments of a bare name to a member or variable.
    for m in EQ_RE.finditer(code):
        rhs = RHS_RE.match(code, m.end())
        if not rhs:
            continue
        lhs = ident_before(code, m.start())
        if lhs:
            ctx.assigns.append((lhs, rhs.group(1), rel,
                                line_of(code, m.start())))


def func_decl(ctx, rel, code, start, end, is_def):
    text = code[start:end]
    # The declarator: the first NAME( at paren depth 0 that is not a keyword,
    # an attribute, or the (*name)( of a function pointer.
    depth = 0
    for jm in re.finditer(r'[()=]', text):
        j = jm.start()
        ch = text[j]
        if ch == "(":
            if depth == 0:
                mm = re.search(r'([A-Za-z_]\w*)\s*$', text[:j])
                if mm and mm.group(1) not in KEYWORDS and \
                        mm.group(1) not in ctx.pins and \
                        mm.group(1) not in ctx.regs:
                    name = mm.group(1)
                    pre = text[:mm.start()]
                    if "=" in pre or not IDENT_RE.search(pre):
                        return
                    close = match_paren(text, j)
                    if close < 0:
                        return
                    params = text[j + 1:close]
                    trailing = text[close + 1:]
                    if re.match(r'\s*\(', trailing):
                        return      # returns a function pointer; leave it
                    conv = ctx.conv_of(pre, params, trailing)
                    static = bool(re.search(r'\bstatic\b', pre))
                    d = Decl(name, rel, line_of(code, start + mm.start()),
                             conv, "static" if static else "func", is_def)
                    d.variadic = params.rstrip().endswith("...")
                    d.params = params
                    ctx.funcs.setdefault(name, []).append(d)
                    return
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            return              # an initializer, not a declaration


def typed_slots(ctx):
    """Members and variables declared through a function-pointer typedef."""
    tds = {}
    for d in ctx.fptrs:
        if d.kind == "typedef":
            tds.setdefault(d.name, []).append(d)
    if not tds:
        return
    rx = re.compile(r'\b(' + "|".join(map(re.escape, tds)) +
                    r')\s+(?:const\s+|volatile\s+)*([A-Za-z_]\w*)\s*'
                    r'(?:\[[^\]]*\]\s*)*([;=,)])')
    for rel, (code, _s, _r) in ctx.files.items():
        for m in rx.finditer(code):
            # The typedef this file sees; a fork's copy of the same name is
            # another type.
            vis = closure(ctx, rel)
            seen = [t for t in tds[m.group(1)] if t.rel in vis] or tds[m.group(1)]
            for conv in {t.conv for t in seen}:
                init = None
                if m.group(3) == "=":
                    im = re.match(r'\s*(?:\([^()]*\)\s*)?&?\s*([A-Za-z_]\w*)\s*[;,]',
                                  code[m.end():])
                    if im:
                        init = im.group(1)
                ctx.fptrs.append(Decl(m.group(2), rel, line_of(code, m.start()),
                                      conv, "slot", init=init))


# ---------------------------------------------------------- resolution ---

def resolve_include(ctx, rel, target):
    here = os.path.dirname(rel)
    cand = os.path.normpath(os.path.join(here, target))
    if cand in ctx.files:
        return cand
    base = os.path.basename(target)
    hits = [r for r in ctx.by_base.get(base, ()) if r.endswith("/" + target)
            or r == target]
    if len(hits) == 1:
        return hits[0]
    if hits:
        top = rel.split("/")[0]
        same = [h for h in hits if h.split("/")[0] == top]
        return (same or hits)[0]
    return None


def closure(ctx, rel):
    if rel in ctx.closure_cache:
        return ctx.closure_cache[rel]
    seen = {rel}
    todo = [rel]
    while todo:
        r = todo.pop()
        for inc in ctx.includes.get(r, ()):
            if inc not in seen:
                seen.add(inc)
                todo.append(inc)
    ctx.closure_cache[rel] = seen
    return seen


def system_includes(ctx, rel):
    out = set()
    for r in closure(ctx, rel):
        raw = ctx.files[r][2]
        for m in INCLUDE_RE.finditer(raw):
            if m.group(1) == "<":
                out.add(m.group(2))
    return out


def visible_conv(ctx, name, rel):
    """The conventions a TU that is (or includes) rel sees for name."""
    vis = closure(ctx, rel)
    convs = {d.conv for d in ctx.funcs.get(name, ()) if d.rel in vis}
    if name in LIBC_STACK and "string.h" in system_includes(ctx, rel):
        convs.add(STACK)
    return convs


def func_conv(ctx, name, rel, fallback=True):
    """The convention of the function `name` as seen from rel: what its own
    declarations say there, else every declaration in the tree."""
    if name == "main" and ctx.main_pinned:
        return {STACK}
    vis = visible_conv(ctx, name, rel)
    if vis or not fallback:
        return vis
    if name in LIBC_STACK and name not in ctx.funcs:
        return {STACK}
    return {d.conv for d in ctx.funcs.get(name, ()) if d.kind != "static"}


# ---------------------------------------------------------------- rules ---

def asm_name_of(ctx, name):
    """The assembly symbol a C name refers to, if any."""
    if name in ctx.asm_defs:
        return name
    m = re.match(r'^(\w+?)' + MV_SUFFIX + r'$', name)
    if m and m.group(1) in ctx.asm_defs and ctx.asm_defs[m.group(1)][2]:
        return m.group(1)
    return None


def run(root, allow_path, verbose=False, files=None):
    ctx = Ctx(root)
    if files is not None:
        raws = dict(files)
    else:
        raws = {rel: read(root, rel) for rel in collect_files(root)}
    macro_pass(ctx, raws.values())
    for rel, raw in raws.items():
        ctx.by_base.setdefault(os.path.basename(rel), []).append(rel)
        if rel.endswith((".S", ".s")):
            ctx.files[rel] = ("", [], raw)
        else:
            code, strings = blank(raw)
            ctx.files[rel] = (code, strings, raw)
    for rel, (code, strings, raw) in ctx.files.items():
        incs = []
        for m in INCLUDE_RE.finditer(raw):
            r = resolve_include(ctx, rel, m.group(2))
            if r:
                incs.append(r)
        ctx.includes[rel] = incs
        if rel.endswith((".S", ".s")):
            text = "\n".join(l.split("|", 1)[0] if not l.lstrip().startswith("#")
                             else "" for l in raw.split("\n"))
            text = expand_gas_macros(text)
            scan_asm_text(ctx, rel, text,
                          lambda p, t=text: t.count("\n", 0, p) + 1)
        else:
            scan_c(ctx, rel, code, strings)
    typed_slots(ctx)

    tc = os.path.join(root, "cmake/toolchain-m68k-amigaos.cmake")
    tctext = open(tc).read() if os.path.exists(tc) else ""
    ctx.main_pinned = bool(re.search(r'-mregparm=\$\{AMINETXDUO_REGPARM\}[^"\n]*'
                                     r'-include[^"\n]*asm_main\.h', tctext)) or \
        files is not None

    allow = load_allow(allow_path)
    used = set()
    findings = []

    def flag(rule, rel, line, name, why):
        key = (rule, rel, name)
        if key in allow:
            used.add(key)
            return
        findings.append((rule, rel, line, name, why))

    # asm-decl
    for name, decls in ctx.funcs.items():
        sym = asm_name_of(ctx, name)
        if sym is None:
            continue
        for d in decls:
            if d.conv != PLAIN:
                continue
            if STACK in visible_conv(ctx, name, d.rel) or \
                    REGS in visible_conv(ctx, name, d.rel):
                continue
            arel, aline, _mv = ctx.asm_defs[sym]
            flag("asm-decl", d.rel, d.line, name,
                 "assembly defines _%s (%s:%d) and reads the stack; this "
                 "declaration passes registers" % (sym, arel, aline))

    # asm-call
    seen = set()
    for name, rel, line in ctx.asm_refs:
        if name in ctx.asm_defs or name not in ctx.funcs:
            continue
        if (name, rel) in seen:
            continue
        seen.add((name, rel))
        convs = {d.conv for d in ctx.funcs[name]}
        if name == "main" and ctx.main_pinned:
            continue
        if PLAIN in convs and not (convs & {STACK, REGS}):
            d = ctx.funcs[name][0]
            flag("asm-call", rel, line, name,
                 "assembly calls _%s, declared at %s:%d with its arguments "
                 "in the build's registers" % (name, d.rel, d.line))

    # rt-helper
    for name, decls in ctx.funcs.items():
        if RT_HELPER_RE.match(name):
            for d in decls:
                if d.conv in (PLAIN, REGS):
                    flag("rt-helper", d.rel, d.line, name,
                         "GCC calls %s with stack arguments; pin it "
                         "AMIGA_ASM_ARGS" % name)
        elif name in RT_STRING:
            for d in decls:
                if d.is_def and d.conv == PLAIN and \
                        STACK not in visible_conv(ctx, name, d.rel):
                    flag("rt-helper", d.rel, d.line, name,
                         "a definition of %s that cannot see <string.h>'s "
                         "__stdargs declaration reads registers" % name)

    # slot: by declarator initializer, and by assignment to a known slot.
    slots = {}
    for d in ctx.fptrs:
        if d.kind == "slot":
            slots.setdefault(d.name, []).append(d)

    def check_slot(sconvs, fname, rel, line, sname):
        if fname in KEYWORDS or fname in ("NULL", "NX_NULL", "0"):
            return
        if fname not in ctx.funcs and fname not in LIBC_STACK and \
                asm_name_of(ctx, fname) is None:
            return
        fconvs = func_conv(ctx, fname, rel)
        if asm_name_of(ctx, fname) is not None and not (fconvs - {PLAIN}):
            fconvs = {STACK}
        if not fconvs or ANY in fconvs:
            return
        sconvs = sconvs - {ANY}
        if not sconvs or len(sconvs) > 1:
            return
        sc = next(iter(sconvs))
        if sc not in fconvs:
            flag("slot", rel, line, "%s=%s" % (sname, fname),
                 "a %s-convention function stored in a %s-convention "
                 "pointer" % ("/".join(sorted(fconvs)), sc))

    for d in ctx.fptrs:
        if d.init:
            check_slot({d.conv}, d.init, d.rel, d.line, d.name)

    # ... and by argument: a function named as the argument of a call whose
    # parameter there is a function pointer of the other convention.
    tdconv = {}
    for d in ctx.fptrs:
        if d.kind == "typedef":
            tdconv.setdefault(d.name, set()).add(d.conv)
    fp_params = {}
    for name, decls in ctx.funcs.items():
        for d in decls:
            if not d.params:
                continue
            for i, prm in enumerate(split_params(d.params)):
                m = FP_RE.search(prm + "(") if "(*" in prm.replace(" ", "") else None
                conv = None
                if m:
                    inner = prm[m.end() - 1:] if prm[m.end() - 1:].startswith("(") else ""
                    pm = re.search(r'\)\s*\((.*)\)\s*$', prm)
                    conv = ctx.conv_of(prm[:m.start()], pm.group(1) if pm else "")
                else:
                    words = IDENT_RE.findall(prm)
                    for w in words:
                        if w in tdconv and len(tdconv[w]) == 1:
                            conv = next(iter(tdconv[w]))
                            break
                if conv is not None:
                    fp_params.setdefault(name, {}).setdefault(i, set()).add(conv)
    if fp_params:
        for rel, (code, _s, _r) in ctx.files.items():
            for m in CALL_RE.finditer(code):
                if m.group(1) not in fp_params:
                    continue
                close = match_paren(code, m.end() - 1)
                if close < 0:
                    continue
                args = split_params(code[m.end():close])
                for i, convs in fp_params[m.group(1)].items():
                    if i < len(args):
                        am = re.match(r'(?:\([^()]*\)\s*)?&?\s*([A-Za-z_]\w*)$',
                                      args[i])
                        if am:
                            check_slot(set(convs), am.group(1), rel,
                                       line_of(code, m.start()),
                                       "%s#%d" % (m.group(1), i + 1))
    for sname, fname, rel, line in ctx.assigns:
        if sname not in slots:
            continue
        vis = closure(ctx, rel)
        local = [d for d in slots[sname] if d.rel in vis]
        cand = local or slots[sname]
        check_slot({d.conv for d in cand}, fname, rel, line, sname)

    # escape
    seen = set()
    for name, rel, line in ctx.casts:
        if name not in ctx.funcs or (name, rel) in seen:
            continue
        seen.add((name, rel))
        convs = func_conv(ctx, name, rel, fallback=False)
        if asm_name_of(ctx, name) is not None:
            continue            # asm-decl owns those
        if convs and convs <= {PLAIN}:
            d = ctx.funcs[name][0]
            flag("escape", rel, line, name,
                 "the address of %s (%s:%d) leaves the type system, and it "
                 "takes its arguments in the build's registers" %
                 (name, d.rel, d.line))

    # libc-decl: our own declaration of a toolchain library routine that
    # cannot see the toolchain's pinned one.
    for name in (LIBC_STACK | ALIB_STACK) & set(ctx.funcs):
        for d in ctx.funcs[name]:
            if d.kind == "static" or d.is_def or d.conv in (STACK, ANY):
                continue
            if STACK in visible_conv(ctx, name, d.rel) or \
                    system_includes(ctx, d.rel) & SYSTEM_PINNING:
                continue
            flag("libc-decl", d.rel, d.line, name,
                 "the toolchain's %s reads the stack; this declaration "
                 "passes registers" % name)

    # varargs: a variadic function passes everything on the stack, so a
    # declaration that disagrees with its definition about `...' disagrees
    # about where every argument is.
    for name, decls in ctx.funcs.items():
        glob = [d for d in decls if d.kind != "static"]
        kinds = {d.variadic for d in glob}
        if len(kinds) > 1:
            d = [x for x in glob if not x.variadic][0]
            v = [x for x in glob if x.variadic][0]
            flag("varargs", d.rel, d.line, name,
                 "declared without `...' here and with it at %s:%d" %
                 (v.rel, v.line))

    # shared-type
    for d in ctx.fptrs:
        if (d.rel.startswith(SHARED_HEADERS) or SHARED_COPY_RE.search(d.rel)) \
                and d.conv == PLAIN:
            flag("shared-type", d.rel, d.line, d.name,
                 "a function-pointer type another binary compiles, with "
                 "neither a pin nor a register for every argument")

    for key in sorted(set(allow) - used):
        findings.append(("allow-stale", allow_path_rel(root, allow_path), 0,
                         "%s:%s:%s" % key,
                         "the allow list names a crossing the tree no longer has"))

    if verbose:
        for name in sorted(ctx.asm_defs):
            rel, line, mv = ctx.asm_defs[name]
            print("asm_symbol=%s file=%s line=%d%s" %
                  (name, rel, line, " multiversion=1" if mv else ""))
    return ctx, findings


def allow_path_rel(root, p):
    return os.path.relpath(p, root) if p else "-"


def load_allow(path):
    out = {}
    if not path or not os.path.exists(path):
        return out
    with open(path) as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 3)
            if len(parts) < 4:
                print("call_abi=bad-allow line=%r (want: rule file name reason)"
                      % raw, file=sys.stderr)
                sys.exit(2)
            out[(parts[0], parts[1], parts[2])] = parts[3]
    return out


# ------------------------------------------------------------ selftest ---
#
# The six instances that shipped, in miniature.  Each must fail as it shipped
# and pass as it was fixed; a rule that stops seeing one is a gate that has
# quietly gone away.

ASM_ABI = '#define AMIGA_ASM_ARGS __attribute__((__stkparm__))\n'

CASES = [
    ("#123 runtime helper unpinned", "rt-helper", {
        "src/common/rt.c": "unsigned __udivsi3(unsigned n, unsigned d) { return n; }\n",
    }, {
        "src/common/rt.c": ASM_ABI + "unsigned AMIGA_ASM_ARGS __udivsi3(unsigned n, unsigned d) { return n; }\n",
    }),
    ("482f7b17 Supervisor stub unpinned", "asm-decl", {
        "src/netdev/c.c": '__asm__(".globl _nd_super_call\\n_nd_super_call:\\n move.l 12(%sp),%a5\\n rts\\n");\n'
                          'extern void nd_super_call(void (*fn)(void), void *op, void *sb);\n',
    }, {
        "src/netdev/c.c": ASM_ABI + '__asm__(".globl _nd_super_call\\n_nd_super_call:\\n move.l 12(%sp),%a5\\n rts\\n");\n'
                          'extern AMIGA_ASM_ARGS void nd_super_call(void (*fn)(void), void *op, void *sb);\n',
    }),
    ("nx_crypto_mem.h libc memcpy in an unpinned pointer", "slot", {
        "include/aminetxduo/m.h": '#include <string.h>\nstatic inline void *cp(void *d, const void *s, unsigned n)\n'
                                  '{ void *(*volatile fn)(void *, const void *, unsigned) = memcpy; return fn(d, s, n); }\n',
    }, {
        "include/aminetxduo/m.h": ASM_ABI + '#include <string.h>\nstatic inline void *cp(void *d, const void *s, unsigned n)\n'
                                  '{ AMIGA_ASM_ARGS void *(*volatile fn)(void *, const void *, unsigned) = memcpy; return fn(d, s, n); }\n',
    }),
    ("#124 crypto68k extern re-declared unpinned in the fork", "asm-decl", {
        "src/crypto68k/p.S": "        .globl  _c68k_add\n_c68k_add:\n        rts\n",
        "third_party/netxduo/crypto_libraries/src/h.c": "extern unsigned c68k_add(unsigned *r, const unsigned *b, unsigned n);\n",
    }, {
        "src/crypto68k/p.S": "        .globl  _c68k_add\n_c68k_add:\n        rts\n",
        "third_party/netxduo/crypto_libraries/src/h.c": "extern __attribute__((__stkparm__)) unsigned c68k_add(unsigned *r, const unsigned *b, unsigned n);\n",
    }),
    ("#125 C default stored in a pinned vector", "slot", {
        "src/crypto68k/cpu.c": ASM_ABI + "unsigned c68k_addmul_1_c(unsigned *r, const unsigned *b, unsigned n, unsigned a) { return a; }\n"
                               "AMIGA_ASM_ARGS unsigned (*c68k_vec_addmul_1)(unsigned *, const unsigned *, unsigned, unsigned) = c68k_addmul_1_c;\n",
    }, {
        "src/crypto68k/cpu.c": ASM_ABI + "AMIGA_ASM_ARGS unsigned c68k_addmul_1_c(unsigned *r, const unsigned *b, unsigned n, unsigned a) { return a; }\n"
                               "AMIGA_ASM_ARGS unsigned (*c68k_vec_addmul_1)(unsigned *, const unsigned *, unsigned, unsigned) = c68k_addmul_1_c;\n",
    }),
    ("#126 anxs2ext.h driver callbacks unpinned", "shared-type", {
        "include/aminetxduo/anxs2ext.h": "typedef unsigned char *(*AnxdS2RxDirect)(void *ios2_data, unsigned long len);\n",
    }, {
        "include/aminetxduo/anxs2ext.h": "#define ANXD_S2_STDARGS __stdargs\n"
                                         "typedef ANXD_S2_STDARGS unsigned char *(*AnxdS2RxDirect)(void *ios2_data, unsigned long len);\n",
    }),
    ("asm calling an unpinned C function", "asm-call", {
        "src/common/g.c": '__asm__(".globl _t\\n_t:\\n move.l %d7,-(%sp)\\n jsr _report\\n addq.l #4,%sp\\n rts\\n");\n'
                          'void report(unsigned long n) { (void)n; }\n',
    }, {
        "src/common/g.c": ASM_ABI + '__asm__(".globl _t\\n_t:\\n move.l %d7,-(%sp)\\n jsr _report\\n addq.l #4,%sp\\n rts\\n");\n'
                          'AMIGA_ASM_ARGS void report(unsigned long n) { (void)n; }\n',
    }),
    ("a stack-reading kernel handed through an unpinned parameter", "slot", {
        "tests/perf/k.S": "        .globl  _k_add\n_k_add:\n        move.l 4(sp),d0\n        rts\n",
        "tests/perf/k.c": "extern __stdargs void k_add(unsigned long reps);\n"
                          "typedef void (*KERNEL)(unsigned long);\n"
                          "static void time_it(KERNEL fn) { fn(1); }\n"
                          "void run(void) { time_it(k_add); }\n",
    }, {
        "tests/perf/k.S": "        .globl  _k_add\n_k_add:\n        move.l 4(sp),d0\n        rts\n",
        "tests/perf/k.c": "extern __stdargs void k_add(unsigned long reps);\n"
                          "typedef __stdargs void (*KERNEL)(unsigned long);\n"
                          "static void time_it(KERNEL fn) { fn(1); }\n"
                          "void run(void) { time_it(k_add); }\n",
    }),
    ("a libc routine re-declared without its header", "libc-decl", {
        "src/tools/t.c": "extern void *memset(void *d, int c, unsigned long n);\n",
    }, {
        "src/tools/t.c": "#include <string.h>\nextern void *memset(void *d, int c, unsigned long n);\n",
    }),
    ("variadic in one place, fixed in another", "varargs", {
        "src/common/a.h": "long ami_log(const char *fmt, long a);\n",
        "src/common/a.c": '#include "a.h"\nlong ami_log(const char *fmt, ...) { return 0; }\n',
    }, {
        "src/common/a.h": "long ami_log(const char *fmt, ...);\n",
        "src/common/a.c": '#include "a.h"\nlong ami_log(const char *fmt, ...) { return 0; }\n',
    }),
    ("an OS callback with stack-less arguments", "escape", {
        "src/netdev/i.c": "static unsigned long on_int(void *data) { return data != 0; }\n"
                          "void arm(struct Interrupt *is) { is->is_Code = (void (*)())on_int; }\n",
    }, {
        "src/netdev/i.c": 'static unsigned long on_int(register void *data __asm("a1")) { return data != 0; }\n'
                          "void arm(struct Interrupt *is) { is->is_Code = (void (*)())on_int; }\n",
    }),
]


def selftest():
    bad = 0
    for title, rule, broken, fixed in CASES:
        _c, f1 = run("/nonexistent", None, files=broken)
        _c, f2 = run("/nonexistent", None, files=fixed)
        hit = [f for f in f1 if f[0] == rule]
        ok = bool(hit) and not f2
        print("call_abi_selftest=%s case=%r rule=%s broken_findings=%d "
              "fixed_findings=%d" % ("ok" if ok else "FAIL", title, rule,
                                     len(hit), len(f2)))
        if not ok:
            for f in f1 + f2:
                print("  %s %s:%d %s -- %s" % f)
            bad += 1
    print("call_abi_selftest=%s cases=%d failed=%d" %
          ("ok" if not bad else "fail", len(CASES), bad))
    return 1 if bad else 0


def main(argv):
    root = None
    verbose = False
    test = False
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--root" and args:
            root = args.pop(0)
        elif a == "--selftest":
            test = True
        elif a == "--verbose":
            verbose = True
        else:
            print(__doc__ or "usage: check-call-abi.py [--root DIR] [--selftest]",
                  file=sys.stderr)
            return 2
    if test:
        return selftest()
    if root is None:
        root = os.path.normpath(os.path.join(os.path.dirname(
            os.path.abspath(__file__)), ".."))
    allow = os.path.join(root, "tools", "check-call-abi-allow.txt")
    ctx, findings = run(root, allow, verbose)
    for rule, rel, line, name, why in findings:
        print("call_abi=fail rule=%s file=%s line=%d name=%s why=%r" %
              (rule, rel, line, name, why))
    print("call_abi=%s files=%d functions=%d fptrs=%d asm_symbols=%d "
          "asm_refs=%d findings=%d" %
          ("ok" if not findings else "fail", len(ctx.files), len(ctx.funcs),
           len(ctx.fptrs), len(ctx.asm_defs), len(ctx.asm_refs), len(findings)))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
