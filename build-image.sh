#!/usr/bin/env bash
# Construye localmente por defecto. Publicar exige PUBLISH=1 de forma explicita.
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")" && pwd)"
VERSION_APP="$(tr -d ' \r\n' < "$RAIZ/VERSION")"
[[ "$VERSION_APP" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(d|rc)[0-9]+)?$ ]] || {
  echo "VERSION debe usar MAJOR.MINOR.PATCH, con sufijo opcional -dN o -rcN" >&2
  exit 2
}

NOMBRE_IMAGEN="${NPMG_IMAGE_NAME:-ghcr.io/ezr43l/npm-guardian-s}"
ETIQUETA="$NOMBRE_IMAGEN:$VERSION_APP"
if [[ -n "${PLATFORMS:-}" ]]; then
  PLATAFORMAS="$PLATFORMS"
else
  case "$(docker version --format '{{.Server.Arch}}')" in
    amd64|x86_64) PLATAFORMAS=linux/amd64 ;;
    arm64|aarch64) PLATAFORMAS=linux/arm64 ;;
    *) echo "Arquitectura local no soportada; define PLATFORMS" >&2; exit 2 ;;
  esac
fi
PUBLICAR="${PUBLISH:-0}"
REVISION="${VCS_REF:-$(git -C "$RAIZ" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)}"
FECHA="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LICENCIA="${LICENSE_SPDX:-Apache-2.0}"

[[ "$PUBLICAR" == 0 || "$PUBLICAR" == 1 ]] || {
  echo "PUBLISH debe valer 0 o 1" >&2; exit 2;
}
if [[ "$PUBLICAR" == 0 && "$PLATAFORMAS" == *,* ]]; then
  echo "Varias plataformas requieren PUBLISH=1; una imagen multiarch no se puede cargar localmente" >&2
  exit 2
fi

argumentos=(
  --platform "$PLATAFORMAS"
  --target runtime
  --build-arg "APP_VERSION=$VERSION_APP"
  --build-arg "VCS_REF=$REVISION"
  --build-arg "BUILD_DATE=$FECHA"
  --build-arg "LICENSE=$LICENCIA"
  -f "$RAIZ/docker/guardian/Dockerfile"
  -t "$ETIQUETA"
)

if [[ "$PUBLICAR" == 1 ]]; then
  echo "Construyendo y publicando $ETIQUETA para $PLATAFORMAS"
  docker buildx build "${argumentos[@]}" --provenance=mode=max --sbom=true --push "$RAIZ"
else
  echo "Construyendo $ETIQUETA para $PLATAFORMAS (sin publicar)"
  docker buildx build "${argumentos[@]}" --load "$RAIZ"
fi

echo "Imagen lista: $ETIQUETA"
