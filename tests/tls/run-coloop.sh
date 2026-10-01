#!/usr/bin/env bash
# tls.library server against tls.library client in one task, under vamos.
#
#   tests/tls/run-coloop.sh [-b builddir] [-c "68000 68020 68040"]
#
# No emulator, ROM, card or peer: TlsCoLoop (tls_coloop.c) hands TLSOpen() a
# fake socket base over a memory pipe and runs both ends as coroutines, so the
# shipped tls.library from <builddir> is the whole of what is under test.  An
# RSA key holds the server at TLS 1.2 (ChaCha20-Poly1305 first), an EC key
# reaches TLS 1.3; both rounds run on every CPU given.
#
# VAMOS names the vamos binary (default: vamos on PATH, else
# ~/vamos-venv/bin/vamos).  vamos exits non-zero after a clean run, from
# expunging the library with no task, so the verdict is the guest's RESULT=
# line and never vamos's exit status.
#
# Output: key=value, RESULT=PASS|FAIL last.  Exit 0 pass, 1 fail, 2 refused.
#
# SPDX-License-Identifier: MIT

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD="${AMINETXDUO_BUILD:-build/cm}"
CPUS="68000 68020 68040"

while getopts "b:c:" opt; do
    case "$opt" in
        b) BUILD="$OPTARG" ;;
        c) CPUS="$OPTARG" ;;
        *) echo "usage: $0 [-b builddir] [-c cpus]" >&2; exit 2 ;;
    esac
done

case "$BUILD" in /*) ;; *) BUILD="$ROOT/$BUILD" ;; esac

VAMOS="${VAMOS:-$(command -v vamos || echo "$HOME/vamos-venv/bin/vamos")}"
LIB="$BUILD/src/tlslib/tls.library"
BIN="$BUILD/tests/tls/TlsCoLoop"

for f in "$VAMOS" "$LIB" "$BIN"; do
    [ -x "$f" ] || [ -f "$f" ] || {
        echo "coloop_refused=missing:$f"
        echo "RESULT=refused"
        exit 2
    }
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/coloop.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/libs" "$WORK/pki"
cp "$LIB" "$WORK/libs/tls.library"
PKI="$WORK/pki"

# The same PKI shape as run-tlsloop.sh: a root, and an EC and an RSA leaf for
# tlsloop.test under it.
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' \
    > "$PKI/ca.cnf"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:tlsloop.test\nsubjectKeyIdentifier=hash\n' \
    > "$PKI/leaf.cnf"
openssl genrsa -out "$PKI/root.key.pem" 2048 2>/dev/null
openssl req -new -x509 -key "$PKI/root.key.pem" -sha256 -days 3650 \
    -subj "/CN=TlsCoLoop Root" -extensions v3 -config <(
        printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n'
        cat "$PKI/ca.cnf") \
    -out "$PKI/root.cert.pem" 2>/dev/null
for kind in ec rsa; do
    if [ "$kind" = ec ]; then
        openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/$kind.key.pem" 2>/dev/null
        openssl ec -in "$PKI/$kind.key.pem" -outform DER -out "$PKI/$kind.key.der" 2>/dev/null
    else
        openssl genrsa -out "$PKI/$kind.key.pem" 2048 2>/dev/null
        openssl rsa -in "$PKI/$kind.key.pem" -outform DER -traditional \
            -out "$PKI/$kind.key.der" 2>/dev/null
    fi
    openssl req -new -key "$PKI/$kind.key.pem" -subj "/CN=tlsloop.test" \
        -out "$PKI/$kind.csr" 2>/dev/null
    openssl x509 -req -in "$PKI/$kind.csr" -sha256 -days 3650 \
        -CA "$PKI/root.cert.pem" -CAkey "$PKI/root.key.pem" -CAcreateserial \
        -extfile "$PKI/leaf.cnf" -out "$PKI/$kind.cert.pem" 2>/dev/null
    openssl x509 -in "$PKI/$kind.cert.pem" -outform DER -out "$PKI/$kind.cert.der" 2>/dev/null
done
python3 "$ROOT/tools/mkcertstore.py" --output "$PKI/store" "$PKI/root.cert.pem" > /dev/null

fails=0
for cpu in $CPUS; do
    for kind in rsa ec; do
        case "$kind" in rsa) want=0x303 kt=RSA ;; ec) want=0x304 kt=EC ;; esac
        log="$WORK/$kind-$cpu.log"
        timeout 120 "$VAMOS" -C "$cpu" -V "anxlibs:$WORK/libs" -a LIBS:anxlibs: \
            -V "pki:$PKI" "$BIN" CERT "pki:$kind.cert.der" KEY "pki:$kind.key.der" \
            KEYTYPE "$kt" STORE pki:store HOST tlsloop.test > "$log" 2>&1
        if grep -qx "RESULT=PASS" "$log" && grep -qx "coloop_version=$want" "$log"; then
            echo "coloop_${kind}_${cpu}=PASS suite=$(sed -n 's/^coloop_suite=//p' "$log")"
        else
            echo "coloop_${kind}_${cpu}=FAIL"
            grep -E "^coloop_|^RESULT=|CPU HW Exception" "$log" | sed 's/^/  /' | head -12
            fails=$((fails + 1))
        fi
    done
done

if [ "$fails" -eq 0 ]; then
    echo "RESULT=PASS"
    exit 0
fi
echo "RESULT=FAIL failures=$fails"
exit 1
