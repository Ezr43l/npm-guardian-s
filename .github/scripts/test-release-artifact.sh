#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="$repo_root/.github/scripts/release-artifact.sh"
test_root="$(mktemp -d)"
mock_bin="$test_root/bin"
output_file="$test_root/github-output"
delete_marker="$test_root/draft-deleted"
mkdir -p "$mock_bin"
trap 'rm -rf -- "$test_root"' EXIT

cat >"$mock_bin/gh" <<'MOCK_GH'
#!/usr/bin/env bash
if printf '%s\n' "$*" | grep -Fq -- '--method DELETE'; then
  test -n "${MOCK_GH_DELETE_MARKER:-}" && printf 'deleted\n' >"$MOCK_GH_DELETE_MARKER"
  exit 0
fi
case "${MOCK_GH_MODE:-absent}" in
  published) printf '[[{"id":41,"tag_name":"%s","draft":false,"immutable":true}]]\n' "$GITHUB_REF_NAME" ;;
  draft) printf '[[{"id":42,"tag_name":"%s","draft":true,"immutable":false}]]\n' "$GITHUB_REF_NAME" ;;
  absent) printf '[[]]\n' ;;
  error) printf 'gh: Service Unavailable (HTTP 503)\n' >&2; exit 1 ;;
  *) exit 97 ;;
esac
MOCK_GH

cat >"$mock_bin/docker" <<'MOCK_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
test "${1:-} ${2:-} ${3:-}" = 'buildx imagetools inspect'
ref="${4:-}"

emit_manifest() {
  cat <<JSON
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "digest": "${MOCK_DIGEST}",
  "manifests": [
    {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"${MOCK_AMD_DIGEST}","platform":{"os":"linux","architecture":"amd64"}}
    $(if test "${MOCK_IMAGE_MODE}" != 'missing-arm'; then printf ',{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","platform":{"os":"linux","architecture":"arm64"}}' "$MOCK_ARM_DIGEST"; fi),
    {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"${MOCK_ATTEST_DIGEST}","platform":{"os":"unknown","architecture":"unknown"}}
  ]
}
JSON
}

emit_image() {
  local arch="$1"
  local source="$MOCK_SOURCE"
  if test "${MOCK_IMAGE_MODE}" = 'bad-label' && test "$arch" = 'arm64'; then
    source='https://github.com/example/wrong'
  fi
  cat <<JSON
{"architecture":"${arch}","os":"linux","config":{"Labels":{"org.opencontainers.image.version":"${MOCK_VERSION}","org.opencontainers.image.revision":"${MOCK_REVISION}","org.opencontainers.image.source":"${source}","org.opencontainers.image.licenses":"${MOCK_LICENSE}"}}}
JSON
}

case "$ref" in
  "${MOCK_IMAGE}:${MOCK_VERSION}")
    case "${MOCK_IMAGE_MODE}" in
      absent) printf 'manifest unknown: not found (404)\n' >&2; exit 1 ;;
      transient) printf 'registry service unavailable (503)\n' >&2; exit 1 ;;
      moved)
        MOCK_DIGEST="${MOCK_MOVED_DIGEST}" emit_manifest
        ;;
      *) emit_manifest ;;
    esac
    ;;
  "${MOCK_IMAGE}@${MOCK_AMD_DIGEST}") emit_image amd64 ;;
  "${MOCK_IMAGE}@${MOCK_ARM_DIGEST}") emit_image arm64 ;;
  *) printf 'unexpected mock reference: %s\n' "$ref" >&2; exit 98 ;;
esac
MOCK_DOCKER
chmod +x "$mock_bin/gh" "$mock_bin/docker"

image='ghcr.io/example/app-s'
version='1.2.3'
repository='Example/app-s'
release_tag='v1.2.3'
source_url='https://github.com/Example/app-s'
revision='0123456789abcdef0123456789abcdef01234567'
license='Apache-2.0'
digest="sha256:$(printf 'a%.0s' {1..64})"
amd_digest="sha256:$(printf 'b%.0s' {1..64})"
arm_digest="sha256:$(printf 'c%.0s' {1..64})"
attest_digest="sha256:$(printf 'd%.0s' {1..64})"
moved_digest="sha256:$(printf 'e%.0s' {1..64})"

run_gate() {
  env \
    PATH="$mock_bin:$PATH" \
    GITHUB_REPOSITORY="$repository" \
    GITHUB_REF_NAME="$release_tag" \
    IMAGE_NAME="$image" \
    VERSION="$version" \
    GITHUB_OUTPUT="$output_file" \
    RUNNER_TEMP="$test_root" \
    MOCK_IMAGE="$image" \
    MOCK_VERSION="$version" \
    MOCK_SOURCE="$source_url" \
    MOCK_REVISION="$revision" \
    MOCK_LICENSE="$license" \
    MOCK_DIGEST="$digest" \
    MOCK_AMD_DIGEST="$amd_digest" \
    MOCK_ARM_DIGEST="$arm_digest" \
    MOCK_ATTEST_DIGEST="$attest_digest" \
    MOCK_MOVED_DIGEST="$moved_digest" \
    MOCK_GH_DELETE_MARKER="$delete_marker" \
    "$@"
}

expect_failure() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'se esperaba un fallo: %s\n' "$name" >&2
    exit 1
  fi
}

: >"$output_file"
run_gate env MOCK_GH_MODE=absent MOCK_IMAGE_MODE=absent bash "$gate" resolve
grep -Fx 'exists=false' "$output_file"
grep -Fx 'digest=' "$output_file"

: >"$output_file"
run_gate env MOCK_GH_MODE=absent MOCK_IMAGE_MODE=valid bash "$gate" resolve
grep -Fx 'exists=true' "$output_file"
grep -Fx "digest=$digest" "$output_file"

: >"$output_file"
rm -f -- "$delete_marker"
run_gate env MOCK_GH_MODE=draft MOCK_IMAGE_MODE=valid bash "$gate" resolve
grep -Fx 'deleted' "$delete_marker"
grep -Fx 'exists=true' "$output_file"

run_gate env MOCK_IMAGE_MODE=valid bash "$gate" validate \
  "$image" "$version" "$digest" "$source_url" "$revision" "$license"
run_gate env MOCK_IMAGE_MODE=valid bash "$gate" assert "$image" "$version" "$digest"

expect_failure 'GitHub Release publicada' \
  run_gate env MOCK_GH_MODE=published MOCK_IMAGE_MODE=absent bash "$gate" resolve
expect_failure 'error de GitHub distinto de 404' \
  run_gate env MOCK_GH_MODE=error MOCK_IMAGE_MODE=absent bash "$gate" resolve
expect_failure 'error de registro distinto de no encontrado' \
  run_gate env MOCK_GH_MODE=absent MOCK_IMAGE_MODE=transient bash "$gate" resolve
expect_failure 'manifiesto ARM64 ausente' \
  run_gate env MOCK_IMAGE_MODE=missing-arm bash "$gate" validate \
    "$image" "$version" "$digest" "$source_url" "$revision" "$license"
expect_failure 'etiqueta OCI incorrecta' \
  run_gate env MOCK_IMAGE_MODE=bad-label bash "$gate" validate \
    "$image" "$version" "$digest" "$source_url" "$revision" "$license"
expect_failure 'tag movido tras fijar digest' \
  run_gate env MOCK_IMAGE_MODE=moved bash "$gate" assert "$image" "$version" "$digest"

workflow="$repo_root/.github/workflows/release.yml"
line_of() {
  grep -m 1 -nF -- "$1" "$workflow" | cut -d: -f1
}
draft_line="$(line_of 'release_flags=(--verify-tag --draft')"
assets_line="$(line_of 'verify_assets "$draft_json"')"
publish_line="$(line_of '-F draft=false')"
immutable_line="$(line_of '.draft == false and .immutable == true')"
before_draft_tag_line="$(line_of 'verify_remote_tag "antes de crear el draft"')"
before_publish_tag_line="$(line_of 'verify_remote_tag "antes de publicar"')"
after_publish_tag_line="$(line_of 'verify_remote_tag "despues de publicar"')"
test "$before_draft_tag_line" -lt "$draft_line"
test "$draft_line" -lt "$assets_line"
test "$assets_line" -lt "$before_publish_tag_line"
test "$before_publish_tag_line" -lt "$publish_line"
test "$assets_line" -lt "$publish_line"
test "$publish_line" -lt "$immutable_line"
test "$immutable_line" -lt "$after_publish_tag_line"
grep -Fq "printf '%s\\n' SHA256SUMS image-digest.txt" "$workflow"
grep -Fq 'sbom-amd64.spdx.json sbom-arm64.spdx.json' "$workflow"
grep -Fq 'subject-digest: ${{ steps.effective.outputs.digest }}' "$workflow"
grep -Fq 'DIGEST: ${{ steps.effective.outputs.digest }}' "$workflow"
test "$(grep -Fc 'flavor: latest=false' "$workflow")" = "1"
test "$(grep -Fc 'tags: type=raw,value=${{ steps.version.outputs.value }}' "$workflow")" = "1"
test "$(grep -Ec '^[[:space:]]+(tags:[[:space:]]+)?type=' "$workflow")" = "1"
grep -Fq 'test "$GENERATED_TAGS" = "${IMAGE_NAME}:${VERSION}"' "$workflow"
if grep -Eq 'latest=(auto|true)' "$workflow"; then
  printf 'release workflow must never publish latest\n' >&2
  exit 1
fi
grep -Fq 'IMMUTABLE_RELEASES_ENABLED: ${{ vars.IMMUTABLE_RELEASES_ENABLED }}' "$workflow"
grep -Fq 'test "$IMMUTABLE_RELEASES_ENABLED" = "true"' "$workflow"
grep -Fq 'remote_tag_refs="$(git ls-remote --tags origin "$tag_ref" "$peeled_ref")"' "$workflow"
grep -Fq 'echo "tag_oid=$tag_oid"' "$workflow"
grep -Fq 'echo "peeled_oid=$peeled_oid"' "$workflow"
grep -Fq '} >> "$GITHUB_OUTPUT"' "$workflow"
grep -Fq 'TAG_OID: ${{ steps.version.outputs.tag_oid }}' "$workflow"
grep -Fq 'PEELED_OID: ${{ steps.version.outputs.peeled_oid }}' "$workflow"
grep -Fq 'tag_oid=%s\npeeled_commit=%s\ndigest=%s' "$workflow"
test "$(grep -Fc 'verify_remote_tag "' "$workflow")" = "3"
if grep -Fq 'target_commitish' "$workflow"; then
  printf 'release workflow must not trust target_commitish\n' >&2
  exit 1
fi

printf 'release artifact gate tests: OK\n'
