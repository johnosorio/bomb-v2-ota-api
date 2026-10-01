#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 || "$1" != "--descriptor" || "$3" != "--repo" ]]; then
  echo "Uso: $0 --descriptor RUTA_DESCRIPTOR.json --repo RUTA_REPOSITORIO" >&2
  echo "La interfaz antigua RUTA_BIN VERSION [CANAL] ya no es segura; migra al descriptor validado." >&2
  exit 2
fi

descriptor_path="$2"
repository_path="$4"
if [[ ! -f "$descriptor_path" ]]; then
  echo "No existe el descriptor: $descriptor_path" >&2
  exit 1
fi
if [[ ! -d "$repository_path" ]]; then
  echo "No existe el repositorio: $repository_path" >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
descriptor_path="$(cd -- "$(dirname -- "$descriptor_path")" && pwd)/$(basename -- "$descriptor_path")"
repository_path="$(cd -- "$repository_path" && pwd)"
cd -- "$script_dir/.."

node --input-type=module - "$descriptor_path" "$repository_path" <<'NODE'
import { prepareRelease } from "./scripts/lib/release-artifact.mjs";

const [, , descriptorPath, repositoryPath] = process.argv;
const result = await prepareRelease(repositoryPath, descriptorPath);
process.stdout.write(`${result.changed ? "Preparado" : "Ya preparado"}: ${result.paths.descriptor}\n`);
NODE
