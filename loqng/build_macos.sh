#!/bin/sh
# Build loqdave for macOS, Apple Silicon and Intel, as ONE universal binary,
# then sign it with a Developer ID and notarize it.
# Runs on a Mac; build_targets.ps1 -Mac drives it over ssh from Windows.
#
#     sh build_macos.sh              build, sign, check both slices, notarize
#     sh build_macos.sh --no-check   skip the corpus check
#     sh build_macos.sh --no-sign    leave the linker's ad-hoc signature
#
# Needs rustup with aarch64-apple-darwin and x86_64-apple-darwin, and the
# Xcode command line tools for the linker, lipo, codesign and notarytool. The
# x86_64 slice is checked under Rosetta, so that has to be installed on an
# Apple Silicon Mac.
#
# Signing uses the Developer ID in the login keychain. Over ssh that keychain
# is locked, and codesign then fails with errSecInternalComponent, so the
# script unlocks it first -- which asks for the Mac password, and needs a
# terminal (ssh -t). Notarization uses an App Store Connect API key and needs
# no keychain at all.
#
# The target directory stays on the Mac's own disk: the source may be an SMB
# share of the Windows checkout, whose target/ belongs to Windows.

set -eu

ROOT=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/loqng-target}"
export CARGO_PROFILE_RELEASE_STRIP=debuginfo

# By SHA-1, not name: the expiring G1 and the new G2 Developer ID certificates
# share a name that matches two identities, making codesign refuse because of ambiguity.
SIGN_ID="${LOQ_SIGN_ID:-303D624AEF460613E64D9F807DBB15B7939369B9}"
NOTARY_KEY_ID="${LOQ_NOTARY_KEY_ID:-Y6PN7AAF76}"
NOTARY_ISSUER="${LOQ_NOTARY_ISSUER:-cf1db9e5-65cc-4af6-a1a5-a6516e4b1d88}"
NOTARY_KEY="${LOQ_NOTARY_KEY:-$HOME/Desktop/AuthKey_$NOTARY_KEY_ID.p8}"

CHECK=1
SIGN=1
for a in "$@"; do
    case "$a" in
        --no-check) CHECK=0 ;;
        --no-sign) SIGN=0 ;;
        *) echo "unknown option $a" >&2; exit 2 ;;
    esac
done

ARM=aarch64-apple-darwin
X86=x86_64-apple-darwin
OUT="$ROOT/dist/loqdave-macos-universal"

for t in $ARM $X86; do
    rustup target list --installed | grep -qx "$t" || rustup target add "$t"
done

cd "$ROOT"
cargo build --release -p loqdave --target $ARM --target $X86

mkdir -p "$ROOT/dist"
lipo -create -output "$OUT" \
    "$CARGO_TARGET_DIR/$ARM/release/loqdave" \
    "$CARGO_TARGET_DIR/$X86/release/loqdave"
ARCHS=$(lipo -archs "$OUT")
case "$ARCHS" in
    *arm64*x86_64*|*x86_64*arm64*) echo "slices: $ARCHS" ;;
    *) echo "expected arm64 and x86_64, got: $ARCHS" >&2; exit 1 ;;
esac

# Signed before the check, so the corpus runs through the file that ships.
# Hardened runtime needs no entitlements here: the guest window is mapped
# read/write, never executable.
sign() {
    codesign --force --options runtime --timestamp \
        --identifier com.wags.loqdave --sign "$SIGN_ID" "$OUT"
}
if [ $SIGN = 1 ]; then
    if ! sign; then
        echo "codesign failed; unlocking the login keychain and retrying"
        security unlock-keychain login.keychain
        sign
    fi
    codesign --verify --strict --verbose=2 "$OUT"
fi
ls -l "$OUT"

if [ $CHECK = 1 ]; then
    # Each slice runs the whole corpus, through its built-in tree and from disk.
    if [ "$(uname -m)" = "arm64" ]; then
        python3 tools/packcheck.py --exe "$OUT" --run "arch -arm64"
        python3 tools/packcheck.py --exe "$OUT" --run "arch -x86_64"
    else
        python3 tools/packcheck.py --exe "$OUT"
    fi
fi

[ $SIGN = 1 ] || exit 0

# A bare Mach-O cannot be stapled, so the ticket lives with Apple and
# Gatekeeper fetches it on first run. notarytool only takes zip, pkg or dmg.
if [ ! -f "$NOTARY_KEY" ]; then
    echo "no notary key at $NOTARY_KEY - signed but NOT notarized" >&2
    exit 1
fi
ZIP=$(mktemp -d)/loqdave-macos-universal.zip
ditto -c -k --keepParent "$OUT" "$ZIP"
RESULT=$(xcrun notarytool submit "$ZIP" --wait --output-format plist \
    --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER")
STATUS=$(printf '%s' "$RESULT" | plutil -extract status raw -)
SUBMISSION=$(printf '%s' "$RESULT" | plutil -extract id raw -)
echo "notarization $SUBMISSION: $STATUS"
if [ "$STATUS" != "Accepted" ]; then
    xcrun notarytool log "$SUBMISSION" \
        --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER"
    exit 1
fi
rm -f "$ZIP"
