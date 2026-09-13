#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Uso: $0 RUTA_AL_BIN VERSION [stable|beta|dev]" >&2
  exit 2
fi

bin_path="$1"
version="$2"
channel="${3:-stable}"
case "$channel" in stable|beta|dev) ;; *) echo "Canal inválido: $channel" >&2; exit 2 ;; esac
if [[ ! -f "$bin_path" ]]; then
  echo "No existe el binario: $bin_path" >&2
  exit 1
fi

mkdir -p public/firmware
target="public/firmware/bomb-manager-${version}.bin"
if [[ "$channel" != "stable" ]]; then
  target="public/firmware/bomb-manager-${channel}-${version}.bin"
fi
cp "$bin_path" "$target"
size="$(wc -c < "$target" | tr -d ' ')"
sha256="$(shasum -a 256 "$target" | awk '{print $1}')"

manifest="release.json"
if [[ "$channel" != "stable" ]]; then manifest="release-${channel}.json"; fi

python3 - "$version" "$channel" "$target" "$size" "$sha256" "$manifest" <<'PY'
import json
import sys

version, channel, target, size, sha256, manifest = sys.argv[1:]
with open(manifest, "w", encoding="utf-8") as handle:
    json.dump({
        "product": "bomb-manager",
        "channel": channel,
        "version": version,
        "firmware_url": "/" + target.split("public/", 1)[1],
        "sha256": sha256,
        "size": int(size),
        "catalog_schema_version": 1,
    }, handle, indent=2)
    handle.write("\n")
PY

echo "Publicado $target"
echo "SHA-256: $sha256"
echo "Tamano: $size bytes"
