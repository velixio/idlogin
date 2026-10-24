#!/bin/sh
# Downloads a pinned Zitadel release (API binary with the console), checks the
# SHA-256 sums published with the release, and unpacks into $PREFIX. The
# sign-in UI is idlogin (this repository), so Zitadel's Login UI bundle is not
# downloaded.
#
#   scripts/install.sh                     # local: $IDLOGIN_DEV_HOME
#   PREFIX=/opt/zitadel scripts/install.sh # production
set -eu

VERSION="${ZITADEL_VERSION:-v4.19.5}"
# Local state lives outside the repository so it survives worktrees.
PREFIX="${PREFIX:-${IDLOGIN_DEV_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/idlogin}}"
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

DL="$PREFIX/dl/$VERSION"
mkdir -p "$DL"
base="https://github.com/zitadel/zitadel/releases/download/$VERSION"
for f in checksums.txt "zitadel-linux-$ARCH.tar.gz"; do
  [ -s "$DL/$f" ] || curl -fsSL -o "$DL/$f" "$base/$f"
done

# The release lists paths as .artifacts/pack/<file>; strip the prefix.
(cd "$DL" && sed 's#\.artifacts/pack/##' checksums.txt |
  grep -E " zitadel-linux-$ARCH\.tar\.gz$" | sha256sum -c -)

rm -rf "$PREFIX/zitadel"
mkdir -p "$PREFIX/zitadel"
tar -xzf "$DL/zitadel-linux-$ARCH.tar.gz" -C "$PREFIX/zitadel" --strip-components=1
echo "$VERSION" > "$PREFIX/VERSION"
"$PREFIX/zitadel/zitadel" --version
