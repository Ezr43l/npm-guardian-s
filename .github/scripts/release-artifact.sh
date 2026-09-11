#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'release-artifact: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "falta el comando requerido: $1"
}

require_value() {
  local name="$1"
  local value="${!name:-}"
  test -n "$value" || die "falta la variable requerida: $name"
}

is_not_found_error() {
  local error_file="$1"
  LC_ALL=C grep -Eiq '(^|[^[:alnum:]])(404|not[[:space:]-]+found|manifest[[:space:]]+unknown|name[[:space:]]+unknown)([^[:alnum:]]|$)' "$error_file"
}

require_digest() {
  local digest="$1"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "digest OCI no valido: $digest"
}

temp_file() {
  local temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
  test -d "$temp_root" || die "el directorio temporal no existe: $temp_root"
  mktemp "$temp_root/release-artifact.XXXXXX"
}

manifest_digest() {
  local manifest_file="$1"
  jq -er '.digest | strings | select(test("^sha256:[0-9a-f]{64}$"))' "$manifest_file"
}

inspect_tag_manifest() {
  local image="$1"
  local version="$2"
  local manifest_file="$3"
  local error_file="$4"

  if ! docker buildx imagetools inspect "${image}:${version}" \
      --format '{{json .Manifest}}' >"$manifest_file" 2>"$error_file"; then
    cat "$error_file" >&2
    die "no se pudo resolver ${image}:${version}"
  fi
}

resolve_artifact() {
  require_command gh
  require_command docker
  require_command jq
  require_value GITHUB_REPOSITORY
  require_value GITHUB_REF_NAME
  require_value IMAGE_NAME
  require_value VERSION
  require_value GITHUB_OUTPUT

  local release_error release_file image_error manifest_file status digest
  local image_name image_version release_count release_id release_draft release_immutable
  image_name="${IMAGE_NAME-}"
  image_version="${VERSION-}"
  release_error="$(temp_file)"
  release_file="$(temp_file)"
  image_error="$(temp_file)"
  manifest_file="$(temp_file)"

  if gh api --paginate --slurp \
      -H 'X-GitHub-Api-Version: 2026-03-10' \
      "repos/${GITHUB_REPOSITORY}/releases?per_page=100" \
      >"$release_file" 2>"$release_error"; then
    :
  else
    status=$?
    cat "$release_error" >&2
    rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
    die "no se pudo consultar las GitHub Releases (codigo $status)"
  fi
  release_count="$(jq -r --arg tag "$GITHUB_REF_NAME" \
    '[.[][]? | select(.tag_name == $tag)] | length' "$release_file")"
  case "$release_count" in
    0) ;;
    1)
      release_id="$(jq -er --arg tag "$GITHUB_REF_NAME" \
        '.[][] | select(.tag_name == $tag) | .id' "$release_file")"
      release_draft="$(jq -er --arg tag "$GITHUB_REF_NAME" \
        '.[][] | select(.tag_name == $tag) | .draft' "$release_file")"
      release_immutable="$(jq -r --arg tag "$GITHUB_REF_NAME" \
        '.[][] | select(.tag_name == $tag) | (.immutable // false)' "$release_file")"
      if test "$release_draft" != "true" || test "$release_immutable" = "true"; then
        rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
        die "la GitHub Release publicada ${GITHUB_REF_NAME} ya existe y bloquea la reejecucion"
      fi
      if gh api --method DELETE \
          -H 'X-GitHub-Api-Version: 2026-03-10' \
          "repos/${GITHUB_REPOSITORY}/releases/${release_id}" \
          >/dev/null 2>"$release_error"; then
        :
      else
        status=$?
        cat "$release_error" >&2
        rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
        die "no se pudo eliminar el draft parcial ${release_id} (codigo $status)"
      fi
      printf 'Se elimino el draft parcial %s; el tag Git se conserva.\n' "$release_id"
      ;;
    *)
      rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
      die "hay ${release_count} releases asociadas a ${GITHUB_REF_NAME}"
      ;;
  esac

  if docker buildx imagetools inspect "${image_name}:${image_version}" \
      --format '{{json .Manifest}}' >"$manifest_file" 2>"$image_error"; then
    if ! digest="$(manifest_digest "$manifest_file")"; then
      rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
      die "el tag existente no expone un digest OCI valido"
    fi
    require_digest "$digest"
    printf 'exists=true\ndigest=%s\n' "$digest" >>"$GITHUB_OUTPUT"
  else
    status=$?
    if ! is_not_found_error "$image_error"; then
      cat "$image_error" >&2
      rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
      die "no se pudo comprobar si existe la imagen (codigo $status)"
    fi
    printf 'exists=false\ndigest=\n' >>"$GITHUB_OUTPUT"
  fi

  rm -f -- "$release_error" "$release_file" "$image_error" "$manifest_file"
}

assert_tag_digest() {
  local image="$1"
  local version="$2"
  local expected_digest="$3"
  local manifest_file error_file actual_digest

  require_command docker
  require_command jq
  require_digest "$expected_digest"
  manifest_file="$(temp_file)"
  error_file="$(temp_file)"
  inspect_tag_manifest "$image" "$version" "$manifest_file" "$error_file"
  actual_digest="$(manifest_digest "$manifest_file")" || {
    rm -f -- "$manifest_file" "$error_file"
    die "el tag no expone un digest OCI valido"
  }
  rm -f -- "$manifest_file" "$error_file"
  test "$actual_digest" = "$expected_digest" || \
    die "el tag ${image}:${version} cambio de ${expected_digest} a ${actual_digest}"
}

validate_artifact() {
  local image="$1"
  local version="$2"
  local digest="$3"
  local expected_source="$4"
  local expected_revision="$5"
  local expected_license="$6"
  local manifest_file error_file image_file tag_digest arch count child_digest
  local actual_os actual_arch key expected actual

  require_command docker
  require_command jq
  require_digest "$digest"
  manifest_file="$(temp_file)"
  error_file="$(temp_file)"
  image_file="$(temp_file)"
  inspect_tag_manifest "$image" "$version" "$manifest_file" "$error_file"
  tag_digest="$(manifest_digest "$manifest_file")" || {
    rm -f -- "$manifest_file" "$error_file" "$image_file"
    die "el tag no expone un digest OCI valido"
  }
  test "$tag_digest" = "$digest" || {
    rm -f -- "$manifest_file" "$error_file" "$image_file"
    die "el tag ${image}:${version} no apunta al digest efectivo ${digest}"
  }

  for arch in amd64 arm64; do
    count="$(jq -r --arg arch "$arch" \
      '[.manifests[]? | select(.platform.os == "linux" and .platform.architecture == $arch)] | length' \
      "$manifest_file")"
    test "$count" = "1" || {
      rm -f -- "$manifest_file" "$error_file" "$image_file"
      die "se esperaba un unico manifiesto linux/${arch}; encontrados: ${count}"
    }
    child_digest="$(jq -er --arg arch "$arch" \
      '.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch) | .digest' \
      "$manifest_file")"
    require_digest "$child_digest"

    if ! docker buildx imagetools inspect "${image}@${child_digest}" \
        --format '{{json .Image}}' >"$image_file" 2>"$error_file"; then
      cat "$error_file" >&2
      rm -f -- "$manifest_file" "$error_file" "$image_file"
      die "no se pudo inspeccionar linux/${arch}@${child_digest}"
    fi
    actual_os="$(jq -er '.os | strings' "$image_file")"
    actual_arch="$(jq -er '.architecture | strings' "$image_file")"
    test "$actual_os/$actual_arch" = "linux/$arch" || {
      rm -f -- "$manifest_file" "$error_file" "$image_file"
      die "la configuracion de ${child_digest} declara ${actual_os}/${actual_arch}"
    }

    for key in \
      org.opencontainers.image.version \
      org.opencontainers.image.revision \
      org.opencontainers.image.source \
      org.opencontainers.image.licenses; do
      case "$key" in
        org.opencontainers.image.version) expected="$version" ;;
        org.opencontainers.image.revision) expected="$expected_revision" ;;
        org.opencontainers.image.source) expected="$expected_source" ;;
        org.opencontainers.image.licenses) expected="$expected_license" ;;
      esac
      if ! actual="$(jq -er --arg key "$key" '.config.Labels[$key] | strings' "$image_file")"; then
        rm -f -- "$manifest_file" "$error_file" "$image_file"
        die "falta la etiqueta OCI ${key} en linux/${arch}"
      fi
      test "$actual" = "$expected" || {
        rm -f -- "$manifest_file" "$error_file" "$image_file"
        die "etiqueta OCI ${key} invalida en linux/${arch}: ${actual}"
      }
    done
  done

  rm -f -- "$manifest_file" "$error_file" "$image_file"
}

case "${1:-}" in
  resolve)
    test "$#" -eq 1 || die 'uso: release-artifact.sh resolve'
    resolve_artifact
    ;;
  validate)
    test "$#" -eq 7 || \
      die 'uso: release-artifact.sh validate IMAGE VERSION DIGEST SOURCE REVISION LICENSE'
    validate_artifact "$2" "$3" "$4" "$5" "$6" "$7"
    ;;
  assert)
    test "$#" -eq 4 || die 'uso: release-artifact.sh assert IMAGE VERSION DIGEST'
    assert_tag_digest "$2" "$3" "$4"
    ;;
  *)
    die 'subcomando requerido: resolve, validate o assert'
    ;;
esac
