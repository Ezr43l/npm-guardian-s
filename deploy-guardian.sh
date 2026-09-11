#!/usr/bin/env bash
# Despliegue remoto opcional. No conoce servidores, redes ni repositorios.
#
# Ejemplo:
#   NODES_CONFIG='node-a:192.0.2.11:key-a,node-b:192.0.2.12:key-b' \
#   NPMG_ACTIVE_NODE=node-a SECRETS_DIR=/ruta/claves \
#   NPMG_SESSION_SECRET=... NPMG_CLUSTER_TOKEN=... \
#   ./deploy-guardian.sh
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")" && pwd)"
VERSION_APP="$(tr -d ' \r\n' < "$RAIZ/VERSION")"
[[ "$VERSION_APP" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(d|rc)[0-9]+)?$ ]] || {
  echo "VERSION debe usar MAJOR.MINOR.PATCH, con sufijo opcional -dN o -rcN" >&2
  exit 2
}
NODOS_CRUDOS="${NODES_CONFIG:-}"
NODO_ACTIVO="${NPMG_ACTIVE_NODE:-}"
SECRETS_DIR="${SECRETS_DIR:-}"
PUERTO="${NPMG_PUBLIC_PORT:-6061}"
CONTENEDOR="${NPMG_CONTAINER_NAME:-npm-guardian}"
IMAGEN="${NPMG_IMAGE:-ghcr.io/ezr43l/npm-guardian-s:$VERSION_APP}"
CONTROL_ANTIGUO="npm-guardian-docker-control"
RED_CONTROL_ANTIGUA="npm-guardian-control"
DATOS_NPM="${NPM_DATA_DIR:-}"
LE_NPM="${NPM_LETSENCRYPT_DIR:-}"
DATOS_GUARDIAN="${NPMG_DATA_DIR:-/var/lib/npm-guardian}"
CONTENEDOR_NPM="${NPMG_NPM_CONTAINER:-npm}"
URL_KEEPALIVED="${NPMG_KEEPALIVED_URL_TEMPLATE:-${NPMG_KEEPALIVED_URL:-https://__NODE_IP__:6060}}"
SERVICIO_KEEPALIVED="${NPMG_KEEPALIVED_SERVICE:-npm}"
# Los Guardian deben alcanzarse entre ellos. La proteccion del portal no se
# basa en ocultar el puerto: las mutaciones exigen HTTPS desde un proxy de
# confianza, salvo que el operador acepte expresamente el perfil LAN inseguro.
BIND_ADDRESS="${NPMG_BIND_ADDRESS:-0.0.0.0}"
PUBLIC_URL="${NPMG_PUBLIC_URL:-}"
ALLOW_PORTAL="${NPMG_ALLOW_INSECURE_PORTAL:-0}"
TRUSTED_PROXIES="${NPMG_TRUSTED_PROXY_IPS:-}"
SESSION_MINUTES="${NPMG_SESSION_MINUTES:-15}"
NPM_API_SCHEME="${NPMG_NPM_API_SCHEME:-https}"
NPM_API_SCHEME="${NPM_API_SCHEME,,}"
NPM_API_PORT="${NPMG_NPM_API_PORT:-443}"
NPM_HTTPS_PORT="${NPMG_NPM_HTTPS_PORT:-443}"
NPM_CA_FILE="${NPMG_NPM_CA_FILE:-}"
ALLOW_NPM_API="${NPMG_ALLOW_INSECURE_NPM_API:-0}"
KEEPALIVED_CA_FILE="${NPMG_KEEPALIVED_CA_FILE:-}"
ALLOW_KEEPALIVED="${NPMG_ALLOW_INSECURE_KEEPALIVED_API:-0}"
DRY_RUN=0

normalizar_booleano() {
  local nombre="$1" valor="${2,,}"
  case "$valor" in
    1|true|yes|si|on) printf '1' ;;
    0|false|no|off|'') printf '0' ;;
    *) echo "$nombre debe ser 0 o 1" >&2; return 2 ;;
  esac
}

validar_puerto() {
  local nombre="$1" valor="$2"
  if ! [[ "$valor" =~ ^[1-9][0-9]{0,4}$ ]] || (( valor > 65535 )); then
    echo "$nombre debe ser un puerto entre 1 y 65535" >&2
    return 2
  fi
}

sin_saltos() {
  local nombre="$1" valor="$2"
  [[ "$valor" != *$'\n'* && "$valor" != *$'\r'* ]] || {
    echo "$nombre no puede contener saltos de linea" >&2
    return 2
  }
}

resolver_secreto() {
  local nombre="$1" nombre_fichero="${1}_FILE" directo="${!1:-}"
  local ruta="${!nombre_fichero:-}" valor=""
  if [[ -n "$directo" && -n "$ruta" ]]; then
    echo "Usa $nombre o $nombre_fichero, no ambos" >&2
    return 2
  fi
  if [[ -n "$ruta" ]]; then
    [[ -f "$ruta" ]] || { echo "$nombre_fichero no es un fichero" >&2; return 2; }
    [[ "$(wc -c < "$ruta")" -le 65536 ]] || {
      echo "$nombre_fichero supera 64 KiB" >&2; return 2;
    }
    valor="$(<"$ruta")"
  else
    valor="$directo"
  fi
  printf -v "$nombre" '%s' "$valor"
  export "${nombre?}"
}

ALLOW_PORTAL="$(normalizar_booleano NPMG_ALLOW_INSECURE_PORTAL "$ALLOW_PORTAL")"
ALLOW_NPM_API="$(normalizar_booleano NPMG_ALLOW_INSECURE_NPM_API "$ALLOW_NPM_API")"
ALLOW_KEEPALIVED="$(normalizar_booleano NPMG_ALLOW_INSECURE_KEEPALIVED_API "$ALLOW_KEEPALIVED")"
resolver_secreto NPMG_SESSION_SECRET
resolver_secreto NPMG_CLUSTER_TOKEN
resolver_secreto NPMG_KEEPALIVED_API_TOKEN
while [[ -n "$PUBLIC_URL" && "$PUBLIC_URL" == */ ]]; do PUBLIC_URL="${PUBLIC_URL%/}"; done

if [[ "${1:-}" == "--dry-run" ]]; then DRY_RUN=1; shift; fi
[[ -n "$NODOS_CRUDOS" ]] || { echo "Falta NODES_CONFIG (nombre:ip:fichero-clave,...)" >&2; exit 2; }
[[ -d "$SECRETS_DIR" ]] || { echo "Falta SECRETS_DIR o no es una carpeta" >&2; exit 2; }
[[ -n "$DATOS_NPM" && -n "$LE_NPM" ]] || { echo "Define NPM_DATA_DIR y NPM_LETSENCRYPT_DIR" >&2; exit 2; }
[[ -n "${NPMG_SESSION_SECRET:-}" ]] || { echo "Falta NPMG_SESSION_SECRET" >&2; exit 2; }
[[ -n "${NPMG_CLUSTER_TOKEN:-}" ]] || { echo "Falta NPMG_CLUSTER_TOKEN" >&2; exit 2; }
for secreto in NPMG_SESSION_SECRET NPMG_CLUSTER_TOKEN; do
  valor_secreto="${!secreto}"
  [[ "$valor_secreto" != *$'\n'* && "$valor_secreto" != *$'\r'* && ${#valor_secreto} -ge 32 ]] || {
    echo "$secreto debe tener al menos 32 caracteres y una sola linea" >&2; exit 2;
  }
done
if [[ -n "$NPMG_KEEPALIVED_API_TOKEN" ]]; then
  [[ "$NPMG_KEEPALIVED_API_TOKEN" != *[[:space:]]* && ${#NPMG_KEEPALIVED_API_TOKEN} -le 4096 ]] || {
    echo "NPMG_KEEPALIVED_API_TOKEN no admite espacios y debe ocupar como máximo 4096 caracteres" >&2
    exit 2
  }
fi
[[ "$IMAGEN" == *":$VERSION_APP" ]] || {
  echo "NPMG_IMAGE debe terminar en :$VERSION_APP (valor actual: $IMAGEN)" >&2; exit 2;
}
validar_puerto NPMG_PUBLIC_PORT "$PUERTO"
validar_puerto NPMG_NPM_API_PORT "$NPM_API_PORT"
validar_puerto NPMG_NPM_HTTPS_PORT "$NPM_HTTPS_PORT"
if ! [[ "$SESSION_MINUTES" =~ ^[0-9]+$ ]] || \
    (( SESSION_MINUTES < 5 || SESSION_MINUTES > 60 )); then
  echo "NPMG_SESSION_MINUTES debe estar entre 5 y 60" >&2; exit 2;
fi
[[ "$BIND_ADDRESS" =~ ^[A-Za-z0-9_.:-]+$ ]] || {
  echo "NPMG_BIND_ADDRESS no es una direccion valida" >&2; exit 2;
}
if [[ -n "$PUBLIC_URL" ]]; then
  [[ "$PUBLIC_URL" == http://* || "$PUBLIC_URL" == https://* ]] || {
    echo "NPMG_PUBLIC_URL debe ser una URL http o https" >&2; exit 2;
  }
  [[ "$PUBLIC_URL" != *[[:space:]\'\"]* ]] || {
    echo "NPMG_PUBLIC_URL contiene caracteres no admitidos" >&2; exit 2;
  }
fi
if [[ "$ALLOW_PORTAL" == "0" ]]; then
  [[ -n "$TRUSTED_PROXIES" ]] || { echo "Falta NPMG_TRUSTED_PROXY_IPS para el proxy HTTPS" >&2; exit 2; }
  [[ -n "$PUBLIC_URL" && "$PUBLIC_URL" == https://* ]] || {
    echo "El perfil seguro exige NPMG_PUBLIC_URL con https" >&2; exit 2;
  }
fi
[[ "$NPM_API_SCHEME" == "https" || "$NPM_API_SCHEME" == "http" ]] || {
  echo "NPMG_NPM_API_SCHEME debe ser https o http" >&2; exit 2;
}
if [[ "$NPM_API_SCHEME" == "http" && "$ALLOW_NPM_API" == "0" ]]; then
  echo "La API de NPM usa HTTP: declara NPMG_ALLOW_INSECURE_NPM_API=1 o configura HTTPS" >&2
  exit 2
fi
for par in \
  "NPMG_SESSION_SECRET:${NPMG_SESSION_SECRET}" \
  "NPMG_CLUSTER_TOKEN:${NPMG_CLUSTER_TOKEN}" \
  "NPMG_TRUSTED_PROXY_IPS:$TRUSTED_PROXIES" \
  "NPMG_NPM_CA_FILE:$NPM_CA_FILE" \
  "NPMG_KEEPALIVED_CA_FILE:$KEEPALIVED_CA_FILE" \
  "NPMG_KEEPALIVED_API_TOKEN:$NPMG_KEEPALIVED_API_TOKEN" \
  "NPMG_KEEPALIVED_URL_TEMPLATE:$URL_KEEPALIVED" \
  "NPMG_KEEPALIVED_SERVICE:$SERVICIO_KEEPALIVED" \
  "NPMG_PUBLIC_URL:$PUBLIC_URL" \
  "NPMG_NPM_CONTAINER:$CONTENEDOR_NPM" \
  "TZ:${TZ:-UTC}"; do
  sin_saltos "${par%%:*}" "${par#*:}"
done
[[ "$CONTENEDOR" =~ ^[A-Za-z0-9_.-]+$ ]] || {
  echo "NPMG_CONTAINER_NAME contiene caracteres no admitidos" >&2; exit 2;
}
[[ "$IMAGEN" =~ ^[A-Za-z0-9._/:@-]+$ ]] || {
  echo "NPMG_IMAGE contiene caracteres no admitidos" >&2; exit 2;
}
for par in "NPMG_NPM_CA_FILE:$NPM_CA_FILE" "NPMG_KEEPALIVED_CA_FILE:$KEEPALIVED_CA_FILE"; do
  [[ -z "${par#*:}" || "${par#*:}" == /* ]] || {
    echo "${par%%:*} debe ser una ruta absoluta dentro del contenedor" >&2; exit 2;
  }
done
for par in \
  "NPM_DATA_DIR:$DATOS_NPM" \
  "NPM_LETSENCRYPT_DIR:$LE_NPM" \
  "NPMG_DATA_DIR:$DATOS_GUARDIAN"; do
  valor="${par#*:}"
  sin_saltos "${par%%:*}" "$valor"
  [[ "$valor" == /* ]] || {
    echo "${par%%:*} debe ser una ruta absoluta del host remoto" >&2; exit 2;
  }
  [[ "$valor" != *\'* ]] || {
    echo "${par%%:*} no puede contener comillas simples" >&2; exit 2;
  }
done

IFS=',' read -r -a NODOS <<< "$NODOS_CRUDOS"
declare -a OBJETIVOS=("$@")

campo() { printf '%s' "$1" | cut -d: -f"$2"; }
seleccionado() {
  [[ ${#OBJETIVOS[@]} -eq 0 ]] && return 0
  local candidato="$1"; local objetivo
  for objetivo in "${OBJETIVOS[@]}"; do [[ "$candidato" == "$objetivo" ]] && return 0; done
  return 1
}

TABLA_NODOS=""
for entrada in "${NODOS[@]}"; do
  nombre="$(campo "$entrada" 1)"; ip="$(campo "$entrada" 2)"; fichero_clave="$(campo "$entrada" 3)"
  [[ "$nombre" =~ ^[A-Za-z0-9_.-]+$ && "$ip" =~ ^[A-Za-z0-9_.-]+$ && -n "$fichero_clave" ]] || {
    echo "Entrada NODES_CONFIG no valida: $entrada" >&2; exit 2;
  }
  TABLA_NODOS+="${TABLA_NODOS:+,}$nombre:$ip"
done

for objetivo in "${OBJETIVOS[@]}"; do
  existe=0
  for entrada in "${NODOS[@]}"; do
    [[ "$(campo "$entrada" 1)" == "$objetivo" ]] && { existe=1; break; }
  done
  [[ $existe -eq 1 ]] || { echo "Nodo objetivo desconocido: $objetivo" >&2; exit 2; }
done

declare -a NODOS_DESPLIEGUE=()
if [[ -n "$NODO_ACTIVO" ]]; then
  activo_encontrado=0
  for entrada in "${NODOS[@]}"; do
    if [[ "$(campo "$entrada" 1)" == "$NODO_ACTIVO" ]]; then
      activo_encontrado=1
    else
      NODOS_DESPLIEGUE+=("$entrada")
    fi
  done
  [[ $activo_encontrado -eq 1 ]] || {
    echo "NPMG_ACTIVE_NODE no figura en NODES_CONFIG: $NODO_ACTIVO" >&2; exit 2;
  }
  for entrada in "${NODOS[@]}"; do
    [[ "$(campo "$entrada" 1)" == "$NODO_ACTIVO" ]] && NODOS_DESPLIEGUE+=("$entrada")
  done
else
  NODOS_DESPLIEGUE=("${NODOS[@]}")
fi

for entrada in "${NODOS_DESPLIEGUE[@]}"; do
  nombre="$(campo "$entrada" 1)"; ip="$(campo "$entrada" 2)"; fichero_clave="$(campo "$entrada" 3)"
  seleccionado "$nombre" || continue
  clave="$SECRETS_DIR/$fichero_clave"
  [[ -f "$clave" ]] || { echo "Falta la clave SSH de $nombre: $clave" >&2; exit 2; }
  pares=""
  for otro in "${NODOS[@]}"; do
    otro_nombre="$(campo "$otro" 1)"; otro_ip="$(campo "$otro" 2)"
    [[ "$otro_nombre" == "$nombre" ]] && continue
    pares+="${pares:+,}$otro_nombre=http://$otro_ip:$PUERTO"
  done
  keepalived="${URL_KEEPALIVED/__NODE_IP__/$ip}"
  case "$keepalived" in
    https://*) ;;
    http://*)
      [[ "$ALLOW_KEEPALIVED" == "1" ]] || {
        echo "La API de Keepalived de $nombre usa HTTP: declara NPMG_ALLOW_INSECURE_KEEPALIVED_API=1" >&2
        exit 2
      } ;;
    *) echo "NPMG_KEEPALIVED_URL_TEMPLATE debe generar una URL http o https" >&2; exit 2 ;;
  esac
  env_remoto="$DATOS_GUARDIAN/runtime.env"
  echo "Desplegando $nombre ($ip) · $IMAGEN"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "  pares=$pares keepalived=$keepalived puerto=$PUERTO"
    continue
  fi

  SSH=(ssh -i "$clave" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 "root@$ip")
  secretos_remotos="$DATOS_GUARDIAN/secrets"
  sesion_remota="$secretos_remotos/session_secret"
  cluster_remoto="$secretos_remotos/cluster_token"
  keepalived_remoto="$secretos_remotos/keepalived_api_token"
  "${SSH[@]}" "mkdir -p '$DATOS_GUARDIAN' '$secretos_remotos' && chmod 700 '$DATOS_GUARDIAN' '$secretos_remotos'"
  printf '%s' "$NPMG_SESSION_SECRET" | "${SSH[@]}" "umask 077; cat > '$sesion_remota'"
  printf '%s' "$NPMG_CLUSTER_TOKEN" | "${SSH[@]}" "umask 077; cat > '$cluster_remoto'"
  if [[ -n "$NPMG_KEEPALIVED_API_TOKEN" ]]; then
    printf '%s' "$NPMG_KEEPALIVED_API_TOKEN" | "${SSH[@]}" "umask 077; cat > '$keepalived_remoto'"
  fi
  {
    printf 'NPMG_NODE_NAME=%s\n' "$nombre"
    printf 'NPMG_NODE_ADDRESS=%s\n' "$ip"
    printf 'NPMG_PEERS=%s\n' "$pares"
    printf 'NPMG_NODES=%s\n' "$TABLA_NODOS"
    printf 'NPMG_KEEPALIVED_URL=%s\n' "$keepalived"
    printf 'NPMG_KEEPALIVED_SERVICE=%s\n' "$SERVICIO_KEEPALIVED"
    if [[ -n "$NPMG_KEEPALIVED_API_TOKEN" ]]; then
      printf 'NPMG_KEEPALIVED_API_TOKEN_FILE=%s\n' "/datos/secrets/keepalived_api_token"
    fi
    printf 'NPMG_PUBLIC_PORT=%s\n' "$PUERTO"
    printf 'NPMG_PUBLIC_URL=%s\n' "$PUBLIC_URL"
    printf 'NPMG_ALLOW_INSECURE_PORTAL=%s\n' "$ALLOW_PORTAL"
    printf 'NPMG_TRUSTED_PROXY_IPS=%s\n' "$TRUSTED_PROXIES"
    printf 'NPMG_SESSION_MINUTES=%s\n' "$SESSION_MINUTES"
    printf 'NPMG_NPM_CONTAINER=%s\n' "$CONTENEDOR_NPM"
    printf 'NPMG_DOCKER_SOCKET=%s\n' "/var/run/docker.sock"
    printf 'NPMG_NPM_API_PORT=%s\n' "$NPM_API_PORT"
    printf 'NPMG_NPM_HTTPS_PORT=%s\n' "$NPM_HTTPS_PORT"
    printf 'NPMG_NPM_API_SCHEME=%s\n' "$NPM_API_SCHEME"
    printf 'NPMG_ALLOW_INSECURE_NPM_API=%s\n' "$ALLOW_NPM_API"
    printf 'NPMG_NPM_CA_FILE=%s\n' "$NPM_CA_FILE"
    printf 'NPMG_ALLOW_INSECURE_KEEPALIVED_API=%s\n' "$ALLOW_KEEPALIVED"
    printf 'NPMG_KEEPALIVED_CA_FILE=%s\n' "$KEEPALIVED_CA_FILE"
    printf 'NPMG_SESSION_SECRET_FILE=%s\n' "/datos/secrets/session_secret"
    printf 'NPMG_CLUSTER_TOKEN_FILE=%s\n' "/datos/secrets/cluster_token"
    printf 'TZ=%s\n' "${TZ:-UTC}"
  } | "${SSH[@]}" "umask 077; cat > '$env_remoto'"

  # DockerMan convierte WebUI e Icon de la plantilla en etiquetas del
  # contenedor. Al desplegar directamente con Docker hay que conservarlas de
  # forma explicita; sin ellas el panel responde, pero Unraid no muestra el
  # acceso WebUI en el menu del contenedor.
  webui="${PUBLIC_URL:+$PUBLIC_URL/}"
  webui="${webui:-http://[IP]:[PORT:6061]/}"
  icono="${PUBLIC_URL:+$PUBLIC_URL/icono.png}"
  icono="${icono:-http://$ip:$PUERTO/icono.png}"
  respaldo="${CONTENEDOR}-rollback"
  if ! "${SSH[@]}" "set -e
docker image inspect '$IMAGEN' >/dev/null 2>&1 || docker pull '$IMAGEN' >/dev/null
if docker container inspect '$respaldo' >/dev/null 2>&1; then
  echo 'Existe el contenedor de recuperacion $respaldo; revisalo antes de desplegar' >&2
  exit 12
fi
restaurar() {
  set +e
  docker rm -f '$CONTENEDOR' >/dev/null 2>&1
  if docker container inspect '$respaldo' >/dev/null 2>&1; then
    docker rename '$respaldo' '$CONTENEDOR'
    docker start '$CONTENEDOR' >/dev/null
  fi
}
trap restaurar ERR
if docker container inspect '$CONTENEDOR' >/dev/null 2>&1; then
  docker stop '$CONTENEDOR' >/dev/null
  docker rename '$CONTENEDOR' '$respaldo'
fi
docker run -d --name '$CONTENEDOR' --restart unless-stopped --init --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 256 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  -p '$BIND_ADDRESS:$PUERTO:6061' --env-file '$env_remoto' \
  --label 'net.unraid.docker.managed=dockerman' --label 'net.unraid.docker.webui=$webui' \
  --label 'net.unraid.docker.icon=$icono' --label 'org.opencontainers.image.title=NPM Guardian' \
  --label 'org.opencontainers.image.version=$VERSION_APP' \
  --label 'org.opencontainers.image.source=https://github.com/Ezr43l/npm-guardian-s' \
  -v '$DATOS_NPM:/npm' -v '$LE_NPM:/npm-letsencrypt' -v '$DATOS_GUARDIAN:/datos' \
  -v /var/run/docker.sock:/var/run/docker.sock \
  '$IMAGEN' >/dev/null
trap - ERR"; then
    echo "No se pudo preparar el contenedor de $nombre; no se elimina el anterior" >&2
    exit 1
  fi

  restaurar_anterior() {
    "${SSH[@]}" "set +e; docker rm -f '$CONTENEDOR' >/dev/null 2>&1; if docker container inspect '$respaldo' >/dev/null 2>&1; then docker rename '$respaldo' '$CONTENEDOR' && docker start '$CONTENEDOR' >/dev/null; fi"
  }

  listo=0
  for _ in $(seq 1 12); do
    if "${SSH[@]}" "curl -fsS --max-time 3 'http://127.0.0.1:$PUERTO/api/health' >/dev/null"; then listo=1; break; fi
    sleep 2
  done
  [[ $listo -eq 1 ]] || {
    echo "El panel de $nombre no supera /api/health; se restaura el contenedor anterior" >&2
    restaurar_anterior
    exit 1
  }
  if ! VERSION_REMOTA="$("${SSH[@]}" "docker exec '$CONTENEDOR' python3 -c \"import json, urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:6061/api/version', timeout=5))['version'])\"")"; then
    echo "No se pudo consultar /api/version en $nombre; se restaura el contenedor anterior" >&2
    restaurar_anterior
    exit 1
  fi
  [[ "$VERSION_REMOTA" == "$VERSION_APP" ]] || {
    echo "El panel de $nombre anuncia $VERSION_REMOTA, se esperaba $VERSION_APP" >&2
    restaurar_anterior
    exit 1
  }
  if ! IMAGEN_REMOTA="$("${SSH[@]}" "docker inspect -f '{{.Config.Image}}' '$CONTENEDOR'")"; then
    echo "No se pudo verificar la imagen del contenedor de $nombre; se restaura el anterior" >&2
    restaurar_anterior
    exit 1
  fi
  [[ "$IMAGEN_REMOTA" == "$IMAGEN" ]] || {
    echo "El contenedor de $nombre usa $IMAGEN_REMOTA, se esperaba $IMAGEN" >&2
    restaurar_anterior
    exit 1
  }
  if ! OCI_REMOTA="$("${SSH[@]}" "docker image inspect -f '{{index .Config.Labels \"org.opencontainers.image.version\"}}' '$IMAGEN'")"; then
    echo "No se pudo verificar la etiqueta OCI de $nombre; se restaura el contenedor anterior" >&2
    restaurar_anterior
    exit 1
  fi
  [[ "$OCI_REMOTA" == "$VERSION_APP" ]] || {
    echo "La imagen de $nombre anuncia OCI $OCI_REMOTA, se esperaba $VERSION_APP" >&2
    restaurar_anterior
    exit 1
  }
  if ! "${SSH[@]}" "set -e
tmp_icon=\"\$(mktemp /tmp/npm-guardian-icon.XXXXXX.png)\"
trap 'rm -f \"\$tmp_icon\"' EXIT
curl -fsS --max-time 10 -o \"\$tmp_icon\" 'http://127.0.0.1:$PUERTO/icono.png'
test \"\$(file -b --mime-type \"\$tmp_icon\")\" = image/png
file -b \"\$tmp_icon\" | grep -Eq 'PNG image data, 128 x 128'
for destino in \\
  '/var/local/emhttp/plugins/dynamix.docker.manager/images/$CONTENEDOR-icon.png' \\
  '/var/lib/docker/unraid/images/$CONTENEDOR-icon.png'; do
  mkdir -p \"\$(dirname \"\$destino\")\"
  install -m 0644 \"\$tmp_icon\" \"\$destino.new\"
  mv -f \"\$destino.new\" \"\$destino\"
done
esperada=\"\$(sha256sum \"\$tmp_icon\" | awk '{print \$1}')\"
test \"\$esperada\" = \"\$(sha256sum '/var/local/emhttp/plugins/dynamix.docker.manager/images/$CONTENEDOR-icon.png' | awk '{print \$1}')\"
test \"\$esperada\" = \"\$(sha256sum '/var/lib/docker/unraid/images/$CONTENEDOR-icon.png' | awk '{print \$1}')\""; then
    echo "El icono de $nombre no quedó instalado en las dos cachés; se restaura el contenedor anterior" >&2
    restaurar_anterior
    exit 1
  fi
  if ! "${SSH[@]}" "set -e
docker rm -f '$respaldo' '$CONTROL_ANTIGUO' >/dev/null 2>&1 || true
if docker network inspect '$RED_CONTROL_ANTIGUA' >/dev/null 2>&1 && \
   [ \"\$(docker network inspect -f '{{len .Containers}}' '$RED_CONTROL_ANTIGUA')\" = 0 ]; then
  docker network rm '$RED_CONTROL_ANTIGUA' >/dev/null
fi"; then
    echo "El contenedor funciona, pero no se pudo completar la limpieza de restos en $nombre" >&2
    exit 1
  fi
  echo "  verificado; un único contenedor activo y sin rollback"
done
