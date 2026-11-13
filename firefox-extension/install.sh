#!/usr/bin/env bash
# install.sh — install the native messaging manifest where Firefox looks for it.
#
# Firefox does not install native manifests; the OS does. On Linux the per-user
# location is ~/.mozilla/native-messaging-hosts/<name>.json. The manifest points
# at this checkout, so re-run this after moving the repository.
#
#   ./install.sh            # per-user (~/.mozilla/...)
#   sudo ./install.sh --system   # /usr/lib/mozilla/native-messaging-hosts
set -euo pipefail

NAME="anubis_solver"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="$HERE/native-host/anubis_native.py"
MANIFEST_SRC="$HERE/native-host/anubis_solver.json"

if [ ! -f "$HOST" ]; then
  echo "error: $HOST is missing" >&2
  exit 1
fi
chmod +x "$HOST"

case "$(uname -s)" in
  Linux)
    if [ "${1:-}" = "--system" ]; then
      DEST_DIR="/usr/lib/mozilla/native-messaging-hosts"
    else
      DEST_DIR="$HOME/.mozilla/native-messaging-hosts"
    fi
    ;;
  Darwin)
    if [ "${1:-}" = "--system" ]; then
      DEST_DIR="/Library/Application Support/Mozilla/NativeMessagingHosts"
    else
      DEST_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
    fi
    ;;
  *)
    echo "error: this script handles Linux and macOS. On Windows, create the" >&2
    echo "       registry key HKCU\\Software\\Mozilla\\NativeMessagingHosts\\$NAME" >&2
    echo "       with its default value set to the absolute path of" >&2
    echo "       $MANIFEST_SRC" >&2
    exit 1
    ;;
esac

mkdir -p "$DEST_DIR"
DEST="$DEST_DIR/$NAME.json"

python3 - "$MANIFEST_SRC" "$DEST" "$HOST" <<'PY'
import json, sys, pathlib
src, dest, host = sys.argv[1:4]
manifest = json.loads(pathlib.Path(src).read_text())
manifest["path"] = str(pathlib.Path(host).resolve())
pathlib.Path(dest).write_text(json.dumps(manifest, indent=2) + "\n")
print(f"wrote {dest}")
print(f"  path = {manifest['path']}")
print(f"  allowed_extensions = {manifest['allowed_extensions']}")
PY

echo
echo "next:"
echo "  1. about:debugging -> This Firefox -> Load Temporary Add-on -> $HERE/manifest.json"
echo "     (or zip the directory and install it as a signed add-on)"
echo "  2. open a page showing an Anubis challenge and click the toolbar button"
echo
echo "if it says 'No such native application $NAME':"
echo "  - check the add-on ID matches allowed_extensions: anubis-solver@celikfana-lab"
echo "  - check this file exists: $DEST"
echo "  - restart Firefox (native manifests are read at startup)"
