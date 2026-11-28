#!/usr/bin/env bash
# build-xpi.sh — package this directory as a Firefox add-on (.xpi).
#
# An .xpi is a zip with manifest.json at its root, nothing else required. Two
# things make the difference between "a zip" and "an add-on that works":
#
#   * the extension ID must match the `allowed_extensions` in the native host's
#     manifest (native-host/anubis_solver.json), or Firefox says
#     "No such native application anubis_solver" no matter what else is right;
#   * only the files the manifest names go in. A README or install.sh in the
#     archive is harmless but a native host script or a test in it is clutter
#     that AMO reviewers have to read.
#
#   ./build-xpi.sh            # -> build/anubis-solver-firefox-<version>.xpi
#   ./build-xpi.sh --sign     # the same, then `web-ext sign` (needs AMO keys)
#
# The unsigned .xpi loads through about:debugging for the current session. A
# permanent install needs a signature: AMO signs it for you on upload, or
# `web-ext sign` with AMO_API_KEY / AMO_API_SECRET in the environment.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$HERE"

python3 - <<'PY'
import json, pathlib, sys

here = pathlib.Path(".")
man = json.loads((here / "manifest.json").read_text())
fail = []

version = man.get("version", "")
if not version:
    fail.append("manifest.json has no version")
if man.get("manifest_version") not in (2, 3):
    fail.append("manifest_version must be 2 or 3")
if "nativeMessaging" not in man.get("permissions", []):
    fail.append("the extension cannot reach the host without the nativeMessaging permission")

gecko = (man.get("browser_specific_settings") or man.get("applications") or {}).get("gecko", {})
ext_id = gecko.get("id", "")
if not ext_id:
    fail.append("no browser_specific_settings.gecko.id: Firefox matches native hosts by ID")

host = json.loads((here / "native-host" / "anubis_solver.json").read_text())
if ext_id and ext_id not in host.get("allowed_extensions", []):
    fail.append(f"extension id {ext_id!r} is not in allowed_extensions "
                f"{host.get('allowed_extensions')}")

referenced = []
for key in ("background",):
    for script in man.get(key, {}).get("scripts", []):
        referenced.append(script)
for key in ("content_scripts",):
    for block in man.get(key, []):
        referenced.extend(block.get("js", []))
for table in ("icons",):
    referenced.extend((man.get(table) or {}).values())
for entry in man.get("web_accessible_resources", []):
    # a glob like "wasm/*": every file under it must exist and be packaged
    if entry.endswith("*"):
        base = here / entry[:-1]
        if not base.is_dir():
            fail.append(f"web_accessible_resources names {entry}, which is not a directory")
        else:
            referenced.extend(str(p.relative_to(here)) for p in base.rglob("*")
                              if p.is_file())
referenced.extend((man.get("browser_action", {}).get("default_icon") or {}).values())
for rel in dict.fromkeys(referenced):
    if not (here / rel).exists():
        fail.append(f"manifest references {rel}, which is not here")

if fail:
    for line in fail:
        print(f"error: {line}", file=sys.stderr)
    sys.exit(1)
print(f"manifest ok: {man['name']} {version}, id {ext_id}, "
      f"host {host['name']}")
PY

VERSION="$(python3 -c 'import json;print(json.load(open("manifest.json"))["version"])')"
OUT="$ROOT/build/anubis-solver-firefox-$VERSION.xpi"
mkdir -p "$ROOT/build"
rm -f "$OUT"

# -X keeps timestamps and extra attributes out, so the same tree gives the same
# bytes; that makes the sha256 below meaningful rather than decorative.
zip -q -X -r "$OUT" manifest.json block.js background.js content.js icons wasm webgpu

echo
echo "built $OUT"
echo "  $(du -h "$OUT" | cut -f1)  sha256 $(sha256sum "$OUT" | cut -d' ' -f1)"
unzip -l "$OUT" | sed -n '1,12p'

if [ "${1:-}" = "--sign" ]; then
  if [ -z "${AMO_API_KEY:-}" ] || [ -z "${AMO_API_SECRET:-}" ]; then
    echo
    echo "error: --sign needs AMO_API_KEY and AMO_API_SECRET (from" >&2
    echo "       https://addons.mozilla.org/developers/addon/api/key/)" >&2
    exit 1
  fi
  echo
  echo "signing with web-ext sign (listed channel)..."
  npx --yes web-ext sign --channel=unlisted --source-dir . \
      --artifacts-dir "$ROOT/build" --api-key "$AMO_API_KEY" \
      --api-secret "$AMO_API_SECRET" || {
        echo "signing failed; the unsigned .xpi is still at $OUT" >&2
        exit 1
      }
fi

cat <<EOT

install:
  1. native host, once per checkout (it writes the OS manifest Firefox reads):
       ./install.sh            # per-user
  2. temporary add-on, for the current session:
       about:debugging -> This Firefox -> Load Temporary Add-on -> $OUT
  3. permanent, needs a signature:
       upload $OUT at https://addons.mozilla.org/developers/ (AMO signs it),
       or run ./build-xpi.sh --sign and install the signed file it leaves.

after a restart, Firefox reads native manifests at startup only: if the host was
just installed, restart the browser before the button works.
EOT
