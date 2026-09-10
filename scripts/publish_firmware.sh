#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Uso: $0 RUTA_AL_BIN VERSION" >&2
  exit 2
fi

bin_path="$1"
version="$2"
if [[ ! -f "$bin_path" ]]; then
  echo "No existe el binario: $bin_path" >&2
  exit 1
fi

mkdir -p public/firmware
target="public/firmware/bomb-manager-${version}.bin"
cp "$bin_path" "$target"
size="$(wc -c < "$target" | tr -d ' ')"
sha256="$(shasum -a 256 "$target" | awk '{print $1}')"

python3 - "$version" "$target" "$size" "$sha256" <<'PY'
import json
import sys

version, target, size, sha256 = sys.argv[1:]
with open("release.json", "w", encoding="utf-8") as handle:
    json.dump({
        "product": "bomb-manager",
        "channel": "stable",
        "version": version,
        "firmware_url": "/firmware/" + target.split("/", 1)[1],
        "sha256": sha256,
        "size": int(size),
    }, handle, indent=2)
    handle.write("\n")
PY

echo "Publicado $target"
echo "SHA-256: $sha256"
echo "Tamano: $size bytes"
