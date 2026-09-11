"""Configuracion persistente y portable de NPM Guardian.

La topologia de cada nodo (su nombre, sus pares, rutas y la API de Keepalived)
viene del entorno porque es distinta en cada servidor. La configuracion que
pertenece al *cluster* vive aqui y se replica: calendario, automatizacion de
Namecheap, credenciales cifradas y cuenta administradora.

Los nombres ``NPMHA_*`` se mantienen como alias de migracion. Las instalaciones
nuevas deben usar ``NPMG_*``.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import stat
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:  # pragma: no cover - solo permite explicar bien una imagen rota
    Fernet = None
    InvalidToken = Exception


class ErrorConfiguracion(ValueError):
    """Un ajuste no es valido o no se puede proteger."""


def _secreto_entorno(nombre, legado):
    """Lee un secreto directo o desde ``*_FILE``, nunca de ambos sitios.

    Los alias NPMHA se conservan exclusivamente para migraciones. Limitar el
    tamaño evita leer por accidente dispositivos o ficheros no destinados a
    contener un secreto pequeño.
    """
    directos = [(clave, os.environ.get(clave, ""))
                for clave in (nombre, legado)
                if (os.environ.get(clave) or "").strip()]
    ficheros = [(clave, os.environ.get(clave, ""))
                for clave in (nombre + "_FILE", legado + "_FILE")
                if (os.environ.get(clave) or "").strip()]
    if len(directos) + len(ficheros) > 1:
        usados = ", ".join(clave for clave, _ in directos + ficheros)
        raise ErrorConfiguracion(
            f"configuracion ambigua para {nombre}: usa solo una de {usados}")
    if directos:
        return directos[0][1].strip()
    if not ficheros:
        return ""
    clave, ruta = ficheros[0]
    ruta_validada = fichero_regular(clave, ruta, maximo=16 * 1024)
    try:
        contenido = ruta_validada.read_bytes()
    except OSError as error:
        raise ErrorConfiguracion(f"no se puede leer {clave}: {error}") from error
    try:
        return contenido.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ErrorConfiguracion(f"{clave} debe apuntar a un fichero UTF-8") from error


def fichero_regular(variable, ruta, maximo):
    """Valida antes de leer: no sigue enlaces, dispositivos ni ficheros enormes."""
    path = Path(str(ruta or ""))
    if not path.is_absolute():
        raise ErrorConfiguracion(f"{variable} debe usar una ruta absoluta")
    try:
        metadatos = path.lstat()
    except OSError as error:
        raise ErrorConfiguracion(f"no se puede leer {variable}: {type(error).__name__}") from error
    if stat.S_ISLNK(metadatos.st_mode) or not stat.S_ISREG(metadatos.st_mode):
        raise ErrorConfiguracion(f"{variable} debe apuntar a un fichero regular, no un enlace")
    if metadatos.st_size > maximo:
        raise ErrorConfiguracion(f"{variable} supera el tamaño permitido")
    return path


def fichero_ca(variable):
    ruta = (os.environ.get(variable) or "").strip()
    if not ruta:
        return None
    return str(fichero_regular(variable, ruta, maximo=10 * 1024 * 1024))


DATOS = os.environ.get("NPMG_DATA_DIR", os.environ.get("NPMHA_DATOS", "/datos"))
RUTA = os.environ.get("NPMG_CONFIG_FILE", os.path.join(DATOS, "guardian.json"))
RUTA_BACKUP = RUTA + ".bak"
SECRETO_SESION = _secreto_entorno("NPMG_SESSION_SECRET", "NPMHA_SESSION_SECRET")
TOKEN_CLUSTER = _secreto_entorno("NPMG_CLUSTER_TOKEN", "NPMHA_CLUSTER_TOKEN")
_candado = threading.RLock()
_candado_operativo = threading.RLock()
_cache = None
ESQUEMA = 1
MARCA_CONFIG_INICIAL = "1970-01-01T00:00:00+00:00"
MARCA_CONFIG_BOOTSTRAP = "1970-01-01T00:00:01+00:00"
SECCIONES = {
    "sync": {"enabled", "cron"},
    "namecheap": {"enabled", "api_user", "api_key"},
    "renewal": {"days_before_expiry", "warning_days", "max_automatic_attempts"},
    "npm_api": {"user", "password", "port", "https_port", "timeout_seconds"},
}
CAMPOS_CUENTA = {
    "id", "username", "display_name", "auth_provider", "npm_user_id",
    "session_version", "created_at", "totp", "password_hash",
}
CAMPOS_TOTP = {"enabled", "secret", "pending_secret", "recovery_code_hashes"}
RAIZ_CONFIG = {"schema", "revision", "updated_at", "settings", "account"}
CAMPOS_CUENTA_OBLIGATORIOS = CAMPOS_CUENTA - {"password_hash"}


def validar_secretos():
    """Falla rápido ante placeholders, claves cortas o reutilizadas."""
    valores = {
        "NPMG_SESSION_SECRET": SECRETO_SESION,
        "NPMG_CLUSTER_TOKEN": TOKEN_CLUSTER,
    }
    for nombre, valor in valores.items():
        compacto = str(valor or "").strip()
        predecible = compacto.casefold()
        if (len(compacto) < 32 or len(set(compacto)) < 10 or
                any(marca in predecible for marca in
                    ("replace-with", "changeme", "example", "placeholder"))):
            raise ErrorConfiguracion(
                f"{nombre} debe ser aleatorio, tener al menos 32 caracteres y no ser un placeholder")
    if hmac.compare_digest(SECRETO_SESION, TOKEN_CLUSTER):
        raise ErrorConfiguracion(
            "NPMG_SESSION_SECRET y NPMG_CLUSTER_TOKEN deben ser valores distintos")
    return True


def identificadores_secretos():
    """Identificadores no reversibles para comprobar coherencia entre nodos."""
    def identificador(nombre, valor):
        return hmac.new(
            str(valor).encode(), f"npm-guardian/{nombre}/key-id".encode(),
            hashlib.sha256).hexdigest()[:16]
    return {
        "session": identificador("session", SECRETO_SESION),
        "cluster": identificador("cluster", TOKEN_CLUSTER),
    }


def _ahora():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _entero(nombre, legado, por_omision):
    texto = os.environ.get(nombre, os.environ.get(legado, str(por_omision)))
    try:
        return int(texto)
    except (TypeError, ValueError):
        return por_omision


def _booleano(nombre, por_omision=False):
    valor = os.environ.get(nombre)
    if valor is None:
        return por_omision
    return valor.strip().lower() in ("1", "true", "yes", "si", "sí", "on")


def _fernet():
    if not SECRETO_SESION or Fernet is None:
        return None
    import base64
    import hashlib
    clave = base64.urlsafe_b64encode(hashlib.sha256(SECRETO_SESION.encode()).digest())
    return Fernet(clave)


def cifrar(valor):
    """Cifra un secreto antes de persistirlo o enviarlo a un par."""
    if not valor:
        return ""
    caja = _fernet()
    if caja is None:
        raise ErrorConfiguracion(
            "NPMG_SESSION_SECRET es obligatorio para guardar credenciales o activar 2FA")
    return "fernet:" + caja.encrypt(str(valor).encode()).decode("ascii")


def descifrar(valor):
    if not valor:
        return ""
    if not str(valor).startswith("fernet:"):
        # Compatibilidad de una sola lectura con borradores anteriores. Nunca se
        # devuelve por API y la proxima escritura lo deja cifrado.
        return str(valor)
    caja = _fernet()
    if caja is None:
        raise ErrorConfiguracion("falta NPMG_SESSION_SECRET para leer las credenciales")
    try:
        return caja.decrypt(str(valor)[7:].encode("ascii")).decode()
    except (InvalidToken, UnicodeError) as e:
        raise ErrorConfiguracion(
            "NPMG_SESSION_SECRET no coincide con la que cifro la configuracion") from e


def _inicial():
    usuario_nc = (os.environ.get("NPMG_NAMECHEAP_API_USER") or
                  os.environ.get("NPMHA_NAMECHEAP_USUARIO") or "").strip()
    clave_nc = (os.environ.get("NPMG_NAMECHEAP_API_KEY") or
                os.environ.get("NPMHA_NAMECHEAP_CLAVE") or "").strip()
    usuario_npm = (os.environ.get("NPMG_NPM_API_USER") or
                   os.environ.get("NPMHA_NPM_USUARIO") or "").strip()
    clave_npm = (os.environ.get("NPMG_NPM_API_PASSWORD") or
                 os.environ.get("NPMHA_NPM_CLAVE") or "").strip()

    # En una migracion, la presencia de las credenciales antiguas conserva el
    # comportamiento que ya habia. Una instalacion nueva nace con Namecheap
    # apagado y funciona como replicador HA sin pedir datos que no necesita.
    namecheap_activo = _booleano("NPMG_NAMECHEAP_ENABLED", bool(usuario_nc and clave_nc))
    return {
        "schema": ESQUEMA,
        "revision": 1,
        # El primer documento debe ser idéntico en todos los nodos. Las claves
        # de entorno se usan como fallback de solo lectura hasta que el usuario
        # las guarda desde el portal; cifrarlas aquí introduciría un nonce Fernet
        # distinto en cada nodo y partiría el clúster antes del primer login.
        "updated_at": MARCA_CONFIG_INICIAL,
        "settings": {
            "sync": {
                "enabled": _booleano("NPMG_SYNC_ENABLED", True),
                "cron": os.environ.get("NPMG_SYNC_CRON", "*/15 * * * *").strip(),
            },
            "namecheap": {
                "enabled": namecheap_activo,
                "api_user": usuario_nc,
                "api_key": "",
            },
            "renewal": {
                "days_before_expiry": _entero("NPMG_RENEW_DAYS", "NPMHA_DIAS_RENOVAR", 35),
                "warning_days": _entero("NPMG_WARNING_DAYS", "NPMHA_DIAS_AVISO", 15),
                "max_automatic_attempts": _entero("NPMG_MAX_RENEWAL_ATTEMPTS", "", 4),
            },
            "npm_api": {
                "user": usuario_npm,
                "password": str(),
                "port": _entero("NPMG_NPM_API_PORT", "NPMHA_NPM_PUERTO", 443),
                "https_port": _entero("NPMG_NPM_HTTPS_PORT", "NPMHA_NPM_HTTPS_PUERTO", 443),
                "timeout_seconds": _entero("NPMG_NPM_RENEW_TIMEOUT", "", 720),
            },
        },
        "account": None,
    }


def _validar_contrato(datos):
    if not isinstance(datos, dict):
        raise ErrorConfiguracion("la configuracion debe ser un objeto")
    if (isinstance(datos.get("schema"), bool) or
            not isinstance(datos.get("schema"), int) or
            datos.get("schema") != ESQUEMA):
        raise ErrorConfiguracion(
            f"schema de configuracion no compatible: {datos.get('schema')!r}")
    campos_raiz = set(datos)
    if campos_raiz != RAIZ_CONFIG:
        faltan = RAIZ_CONFIG - campos_raiz
        sobran = campos_raiz - RAIZ_CONFIG
        detalle = []
        if faltan:
            detalle.append("faltan " + ", ".join(sorted(faltan)))
        if sobran:
            detalle.append("sobran " + ", ".join(sorted(sobran)))
        raise ErrorConfiguracion("contrato de configuracion incompleto: " + "; ".join(detalle))
    if isinstance(datos.get("revision"), bool) or not isinstance(datos.get("revision"), int):
        raise ErrorConfiguracion("revision debe ser un entero")
    if not isinstance(datos.get("updated_at"), str) or not datos["updated_at"].strip():
        raise ErrorConfiguracion("updated_at debe ser una fecha no vacia")
    ajustes = datos.get("settings")
    if not isinstance(ajustes, dict):
        raise ErrorConfiguracion("settings debe ser un objeto")
    if set(ajustes) != set(SECCIONES):
        raise ErrorConfiguracion("settings debe contener exactamente: " +
                                 ", ".join(sorted(SECCIONES)))
    for seccion, permitidos in SECCIONES.items():
        valor = ajustes.get(seccion)
        if not isinstance(valor, dict):
            raise ErrorConfiguracion(f"settings.{seccion} debe ser un objeto")
        if set(valor) != permitidos:
            raise ErrorConfiguracion(
                f"settings.{seccion} debe contener exactamente: " +
                ", ".join(sorted(permitidos)))
    sync = ajustes["sync"]
    nc = ajustes["namecheap"]
    renovacion = ajustes["renewal"]
    api = ajustes["npm_api"]
    if type(sync["enabled"]) is not bool or not isinstance(sync["cron"], str):
        raise ErrorConfiguracion("settings.sync contiene tipos no válidos")
    from planificador import validar_cron
    validar_cron(sync["cron"])
    if (type(nc["enabled"]) is not bool or
            not all(isinstance(nc[campo], str) for campo in ("api_user", "api_key")) or
            len(nc["api_user"]) > 256 or len(nc["api_key"]) > 8192):
        raise ErrorConfiguracion("settings.namecheap contiene tipos no válidos")
    numeros_renovacion = [renovacion[campo] for campo in
                          ("days_before_expiry", "warning_days",
                           "max_automatic_attempts")]
    if any(isinstance(v, bool) or not isinstance(v, int) for v in numeros_renovacion):
        raise ErrorConfiguracion("settings.renewal debe contener enteros")
    if (not 31 <= renovacion["days_before_expiry"] <= 60 or
            not 1 <= renovacion["warning_days"] <= renovacion["days_before_expiry"] or
            not 1 <= renovacion["max_automatic_attempts"] <= 4):
        raise ErrorConfiguracion("settings.renewal está fuera de los límites seguros")
    if (not isinstance(api["user"], str) or not isinstance(api["password"], str) or
            len(api["user"]) > 256 or len(api["password"]) > 8192):
        raise ErrorConfiguracion("settings.npm_api contiene credenciales no válidas")
    for campo in ("port", "https_port", "timeout_seconds"):
        if isinstance(api[campo], bool) or not isinstance(api[campo], int):
            raise ErrorConfiguracion(f"settings.npm_api.{campo} debe ser entero")
    if (not 1 <= api["port"] <= 65535 or not 1 <= api["https_port"] <= 65535 or
            not 360 <= api["timeout_seconds"] <= 1800):
        raise ErrorConfiguracion("settings.npm_api está fuera de límites")
    cuenta = datos.get("account")
    if cuenta is not None:
        if not isinstance(cuenta, dict):
            raise ErrorConfiguracion("account debe ser un objeto o null")
        extras = set(cuenta) - CAMPOS_CUENTA
        faltan = CAMPOS_CUENTA_OBLIGATORIOS - set(cuenta)
        if extras or faltan:
            raise ErrorConfiguracion(
                "contrato de cuenta no compatible" +
                (("; faltan " + ", ".join(sorted(faltan))) if faltan else "") +
                (("; sobran " + ", ".join(sorted(extras))) if extras else ""))
        totp = cuenta.get("totp")
        if not isinstance(totp, dict) or set(totp) != CAMPOS_TOTP:
            raise ErrorConfiguracion("la estructura TOTP no es compatible")
        if (type(totp["enabled"]) is not bool or
                not isinstance(totp["secret"], str) or
                not isinstance(totp["pending_secret"], str) or
                not isinstance(totp["recovery_code_hashes"], list) or
                not all(isinstance(v, str) and len(v) == 64
                        for v in totp["recovery_code_hashes"])):
            raise ErrorConfiguracion("los tipos TOTP no son válidos")
        for campo in ("id", "username", "display_name", "auth_provider",
                      "npm_user_id"):
            if not isinstance(cuenta[campo], str):
                raise ErrorConfiguracion(f"account.{campo} debe ser texto")
        for campo in ("session_version", "created_at"):
            if (isinstance(cuenta[campo], bool) or
                    not isinstance(cuenta[campo], (int, float))):
                raise ErrorConfiguracion(f"account.{campo} no es válido")


def _normalizar(datos):
    base = _inicial()
    _validar_contrato(datos)
    base.update({k: copy.deepcopy(v) for k, v in datos.items()
                 if k in ("schema", "revision", "updated_at", "account")})
    for seccion in ("sync", "namecheap", "renewal", "npm_api"):
        recibido = ((datos.get("settings") or {}).get(seccion) or {})
        if isinstance(recibido, dict):
            base["settings"][seccion].update(copy.deepcopy(recibido))
    return base


def _migrar_secretos(datos):
    """Recifra valores legacy y valida ahora los tokens ya cifrados."""
    cambiados = False
    rutas = [
        datos["settings"]["namecheap"],
        datos["settings"]["npm_api"],
    ]
    for objeto, campo in ((rutas[0], "api_key"), (rutas[1], "password")):
        valor = objeto.get(campo)
        if valor:
            claro = descifrar(valor)
            if not str(valor).startswith("fernet:"):
                objeto[campo] = cifrar(claro)
                cambiados = True
    cuenta = datos.get("account") or {}
    totp = cuenta.get("totp") or {}
    for campo in ("secret", "pending_secret"):
        valor = totp.get(campo)
        if valor:
            claro = descifrar(valor)
            if not str(valor).startswith("fernet:"):
                totp[campo] = cifrar(claro)
                cambiados = True
    return cambiados


def leer(refrescar=False):
    global _cache
    with _candado:
        if _cache is not None and not refrescar:
            return copy.deepcopy(_cache)
        recuperado = False

        def cargar(ruta):
            with open(ruta, "r", encoding="utf-8") as f:
                normal = _normalizar(json.load(f))
            migrado = _migrar_secretos(normal)
            return normal, migrado

        try:
            _cache, migrado = cargar(RUTA)
        except FileNotFoundError:
            if not os.path.exists(RUTA_BACKUP):
                _cache, migrado = _inicial(), False
                _guardar_sin_candado(_cache, guardar_backup=False)
            else:
                try:
                    _cache, migrado = cargar(RUTA_BACKUP)
                    recuperado = True
                except (OSError, ValueError, TypeError, UnicodeError,
                        ErrorConfiguracion) as error:
                    raise ErrorConfiguracion(
                        "guardian.json no existe y su copia de seguridad no es válida") from error
        except (OSError, ValueError, TypeError, UnicodeError,
                ErrorConfiguracion):
            try:
                _cache, migrado = cargar(RUTA_BACKUP)
                recuperado = True
            except (OSError, ValueError, TypeError, UnicodeError,
                    ErrorConfiguracion) as error_backup:
                raise ErrorConfiguracion(
                    "guardian.json está corrupto y no hay una copia válida; se bloquea el acceso") \
                    from error_backup
        if migrado:
            _cache["revision"] = int(_cache.get("revision") or 0) + 1
            _cache["updated_at"] = _ahora()
            _guardar_sin_candado(_cache, guardar_backup=not recuperado)
        elif recuperado:
            _guardar_sin_candado(_cache, guardar_backup=False)
        return copy.deepcopy(_cache)


def promover_bootstrap_activo():
    """Da al activo una revisión inequívoca durante el primer arranque.

    Aunque la plantilla sea la misma, esta promoción evita que pequeñas
    diferencias de entorno entre nodos dejen tres documentos de revisión 1 sin
    un ganador. Sólo puede ocurrir sobre el estado inicial, antes de vincular
    una cuenta, y es idempotente.
    """
    with _candado:
        datos = leer()
        if (int(datos.get("revision") or 0) != 1 or datos.get("account") is not None or
                datos.get("updated_at") != MARCA_CONFIG_INICIAL):
            return {"changed": False, "revision": int(datos.get("revision") or 0)}
        datos["revision"] = 2
        # Debe ser exactamente igual en cualquier nodo que se promocione
        # durante una particion inicial. Un reloj real crearia dos documentos
        # distintos de revision 2 y, al recuperar el quorum, ninguno podria
        # imponerse sin relajar la proteccion contra rollback.
        datos["updated_at"] = MARCA_CONFIG_BOOTSTRAP
        _guardar_sin_candado(datos)
        return {"changed": True, "revision": 2}


def _guardar_bytes_seguro(ruta, contenido):
    carpeta = os.path.dirname(ruta) or "."
    fd, temporal = tempfile.mkstemp(prefix=".guardian-", suffix=".json", dir=carpeta)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(contenido)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporal, 0o600)
        os.replace(temporal, ruta)
        descriptor_carpeta = os.open(carpeta, os.O_RDONLY)
        try:
            os.fsync(descriptor_carpeta)
        finally:
            os.close(descriptor_carpeta)
    finally:
        try:
            if os.path.exists(temporal):
                os.unlink(temporal)
        except OSError:
            pass


def _guardar_sin_candado(datos, guardar_backup=True):
    global _cache
    carpeta = os.path.dirname(RUTA) or "."
    os.makedirs(carpeta, exist_ok=True)
    if guardar_backup and os.path.isfile(RUTA):
        try:
            with open(RUTA, "rb") as anterior:
                contenido_anterior = anterior.read()
            anterior_json = json.loads(contenido_anterior.decode())
            _validar_contrato(anterior_json)
            _guardar_bytes_seguro(RUTA_BACKUP, contenido_anterior)
        except (OSError, ValueError, UnicodeError, ErrorConfiguracion):
            pass  # no se reemplaza un backup bueno por un primario inválido
    contenido = (json.dumps(datos, ensure_ascii=False, indent=2) + "\n").encode()
    _guardar_bytes_seguro(RUTA, contenido)
    _cache = copy.deepcopy(datos)
    return copy.deepcopy(datos)


def guardar(datos, incrementar=True):
    with _candado:
        normal = _normalizar(datos)
        if incrementar:
            actual = leer()
            normal["revision"] = max(int(actual.get("revision") or 0),
                                     int(normal.get("revision") or 0)) + 1
            normal["updated_at"] = _ahora()
        return _guardar_sin_candado(normal)


def revertir_no_confirmada(datos):
    """Restaura un snapshot con revisión superior sin respaldar el cambio fallido.

    La mutación que no alcanzó quorum ya dejó el último estado confirmado en
    ``guardian.json.bak``. Copiar ahora el estado no confirmado sobre ese backup
    haría que una corrupción futura pudiera resucitarlo.
    """
    with _candado:
        normal = _normalizar(datos)
        actual = leer()
        normal["revision"] = max(int(actual.get("revision") or 0),
                                 int(normal.get("revision") or 0)) + 1
        normal["updated_at"] = _ahora()
        return _guardar_sin_candado(normal, guardar_backup=False)


def imponer_confirmada(datos, revision_minima=0):
    """Impone el documento respaldado por una mayoría sin aceptar un huérfano.

    Una revisión mayor no demuestra por sí sola que una mutación alcanzara
    quórum: el activo pudo caer justo después de persistirla. El llamador aporta
    la mayor revisión observada durante el *majority read*. Si esa revisión
    pertenece a otro documento, el contenido confirmado se vuelve a publicar
    con una revisión estrictamente superior para que los receptores monotónicos
    puedan sustituir el huérfano sin permitir un rollback ordinario.
    """
    with _candado:
        confirmado = _normalizar(datos)
        if _migrar_secretos(confirmado):
            raise ErrorConfiguracion(
                "la configuración confirmada contiene secretos legacy sin cifrar")
        actual = leer()
        try:
            revision_minima = int(revision_minima)
        except (TypeError, ValueError) as error:
            raise ErrorConfiguracion("la revisión mínima confirmada no es válida") from error
        if revision_minima < 0:
            raise ErrorConfiguracion("la revisión mínima confirmada no es válida")

        canon = lambda valor: json.dumps(  # noqa: E731 - comparación local explícita
            valor, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode()
        revision_actual = int(actual.get("revision") or 0)
        revision_confirmada = int(confirmado.get("revision") or 0)
        mismo_documento = hmac.compare_digest(canon(actual), canon(confirmado))

        if mismo_documento and revision_minima <= revision_actual:
            return {"ok": True, "revision": revision_actual,
                    "idempotent": True, "rebased": False}
        if revision_confirmada > revision_actual and revision_minima <= revision_confirmada:
            _guardar_sin_candado(confirmado)
            return {"ok": True, "revision": revision_confirmada,
                    "idempotent": False, "rebased": False}

        confirmado["revision"] = max(
            revision_actual, revision_confirmada, revision_minima) + 1
        confirmado["updated_at"] = _ahora()
        guardado = _guardar_sin_candado(confirmado, guardar_backup=False)
        return {"ok": True, "revision": guardado["revision"],
                "idempotent": False, "rebased": True}


def actualizar(mutador):
    """Modifica el documento entero bajo un unico candado."""
    with _candado:
        datos = leer()
        mutador(datos)
        return guardar(datos)


def mutar_condicional(mutador):
    """Ejecuta leer/comprobar/mutar/guardar como una sola transacción local.

    ``mutador`` devuelve ``(cambiado, resultado)``. Es la primitiva usada para
    consumos de un solo uso: dos peticiones nunca pueden validar la misma copia.
    """
    with _candado:
        datos = leer()
        cambiado, resultado = mutador(datos)
        if type(cambiado) is not bool:
            raise ErrorConfiguracion("la mutación condicional no devolvió un booleano")
        guardados = guardar(datos) if cambiado else datos
        return copy.deepcopy(guardados), resultado, cambiado


def aplicar_replica(datos):
    """Aplica sólo una revisión nueva; nunca permite retroceder seguridad."""
    with _candado:
        entrante = _normalizar(datos)
        if _migrar_secretos(entrante):
            raise ErrorConfiguracion(
                "la réplica contiene secretos legacy sin cifrar")
        actual = leer()
        revision_entrante = int(entrante["revision"])
        revision_actual = int(actual["revision"])
        canon = lambda valor: json.dumps(  # noqa: E731 - comparación local y explícita
            valor, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode()
        if revision_entrante < revision_actual:
            raise ErrorConfiguracion(
                f"revisión obsoleta ({revision_entrante} < {revision_actual})")
        if revision_entrante == revision_actual:
            huella_entrante = hashlib.sha256(canon(entrante)).digest()
            huella_actual = hashlib.sha256(canon(actual)).digest()
            if not hmac.compare_digest(huella_entrante, huella_actual):
                raise ErrorConfiguracion(
                    "la misma revisión contiene datos distintos; se bloquea el rollback")
            return {"ok": True, "revision": revision_actual, "idempotent": True}
        _guardar_sin_candado(entrante)
        return {"ok": True, "revision": revision_entrante, "idempotent": False}


def validar_replica(datos):
    """Valida el documento completo sin escribirlo."""
    entrante = _normalizar(datos)
    if _migrar_secretos(entrante):
        raise ErrorConfiguracion("la réplica contiene secretos legacy sin cifrar")
    return copy.deepcopy(entrante)


def exportar():
    """Documento cifrado completo para otro Guardian. Nunca se sirve al navegador."""
    return leer()


def ajustes_publicos():
    datos = leer()
    a = datos["settings"]
    return {
        "revision": datos.get("revision"),
        "updated_at": datos.get("updated_at"),
        "sync": copy.deepcopy(a["sync"]),
        "namecheap": {
            "enabled": bool(a["namecheap"].get("enabled")),
            "api_user": a["namecheap"].get("api_user", ""),
            "api_key_configured": bool(
                a["namecheap"].get("api_key") or
                (os.environ.get("NPMG_NAMECHEAP_API_KEY") or
                 os.environ.get("NPMHA_NAMECHEAP_CLAVE") or "").strip()),
        },
        "renewal": copy.deepcopy(a["renewal"]),
        "npm_api": {
            "user": a["npm_api"].get("user", ""),
            "password_configured": bool(
                a["npm_api"].get("password") or
                (os.environ.get("NPMG_NPM_API_PASSWORD") or
                 os.environ.get("NPMHA_NPM_CLAVE") or "").strip()),
            "port": a["npm_api"].get("port", 443),
            "https_port": a["npm_api"].get("https_port", 443),
            "timeout_seconds": a["npm_api"].get("timeout_seconds", 720),
        },
    }


def secretos_namecheap():
    a = leer()["settings"]["namecheap"]
    usuario = (str(a.get("api_user") or "").strip() or
               (os.environ.get("NPMG_NAMECHEAP_API_USER") or
                os.environ.get("NPMHA_NAMECHEAP_USUARIO") or "").strip())
    clave = descifrar(a.get("api_key")) if a.get("api_key") else (
        os.environ.get("NPMG_NAMECHEAP_API_KEY") or
        os.environ.get("NPMHA_NAMECHEAP_CLAVE") or "").strip()
    return usuario, clave


def secretos_npm():
    a = leer()["settings"]["npm_api"]
    usuario = (str(a.get("user") or "").strip() or
               (os.environ.get("NPMG_NPM_API_USER") or
                os.environ.get("NPMHA_NPM_USUARIO") or "").strip())
    clave = descifrar(a.get("password")) if a.get("password") else (
        os.environ.get("NPMG_NPM_API_PASSWORD") or
        os.environ.get("NPMHA_NPM_CLAVE") or "").strip()
    return usuario, clave


def guardar_ajustes(entrada):
    """Valida y guarda el formulario de configuracion del panel."""
    if not isinstance(entrada, dict):
        raise ErrorConfiguracion("el cuerpo de configuracion no es valido")
    if set(entrada) != {"sync", "namecheap", "renewal", "npm_api"}:
        raise ErrorConfiguracion(
            "la configuracion debe contener exactamente sync, namecheap, renewal y npm_api")
    sync = entrada.get("sync")
    nc = entrada.get("namecheap")
    ren = entrada.get("renewal")
    napi = entrada.get("npm_api")
    secciones = {
        "sync": (sync, {"enabled", "cron"}, set()),
        "namecheap": (nc, {"enabled", "api_user", "api_key"}, {"clear_api_key"}),
        "renewal": (ren, {"days_before_expiry", "warning_days",
                           "max_automatic_attempts"}, set()),
        "npm_api": (napi, {"user", "password", "port", "https_port",
                            "timeout_seconds"}, {"clear_password"}),
    }
    for nombre, (seccion, obligatorios, opcionales) in secciones.items():
        if not isinstance(seccion, dict):
            raise ErrorConfiguracion(f"{nombre} debe ser un objeto")
        campos = set(seccion)
        if not obligatorios <= campos or campos - obligatorios - opcionales:
            raise ErrorConfiguracion(f"contrato de {nombre} incompleto o con campos desconocidos")
    for nombre, valor in (("sync.enabled", sync["enabled"]),
                          ("namecheap.enabled", nc["enabled"])):
        if type(valor) is not bool:
            raise ErrorConfiguracion(f"{nombre} debe ser booleano")
    for nombre, seccion, campo in (("namecheap.clear_api_key", nc, "clear_api_key"),
                                   ("npm_api.clear_password", napi, "clear_password")):
        if campo in seccion and type(seccion[campo]) is not bool:
            raise ErrorConfiguracion(f"{nombre} debe ser booleano")
    if nc.get("clear_api_key") and nc.get("api_key") not in (None, ""):
        raise ErrorConfiguracion("no se puede guardar y borrar la clave de Namecheap a la vez")
    if napi.get("clear_password") and napi.get("password") not in (None, ""):
        raise ErrorConfiguracion("no se puede guardar y borrar la contrasena de NPM a la vez")

    from planificador import validar_cron
    expresion = str(sync.get("cron") or "").strip()
    validar_cron(expresion)

    numericos = (
        ren.get("days_before_expiry"), ren.get("warning_days"),
        ren.get("max_automatic_attempts"), napi.get("port"),
        napi.get("https_port"), napi.get("timeout_seconds"),
    )
    if any(isinstance(valor, bool) for valor in numericos):
        raise ErrorConfiguracion("los campos numericos no aceptan booleanos")
    try:
        dias = int(ren.get("days_before_expiry"))
        aviso = int(ren.get("warning_days"))
        intentos = int(ren.get("max_automatic_attempts"))
        puerto = int(napi.get("port"))
        puerto_https = int(napi.get("https_port"))
        espera = int(napi.get("timeout_seconds", 720))
    except (TypeError, ValueError) as e:
        raise ErrorConfiguracion("los campos numericos no son validos") from e
    if not 31 <= dias <= 60:
        raise ErrorConfiguracion("la renovacion automatica debe adelantarse entre 31 y 60 dias")
    if not 1 <= aviso <= dias:
        raise ErrorConfiguracion("el aviso debe estar entre 1 dia y el margen de renovacion")
    # Este limite no se puede ampliar desde la interfaz: siempre queda al menos
    # un intento fuera del automatismo para diagnosticar a mano.
    if not 1 <= intentos <= 4:
        raise ErrorConfiguracion("los intentos automaticos deben estar entre 1 y 4")
    if not (1 <= puerto <= 65535 and 1 <= puerto_https <= 65535):
        raise ErrorConfiguracion("los puertos deben estar entre 1 y 65535")
    if not 360 <= espera <= 1800:
        raise ErrorConfiguracion("el timeout de renovacion debe estar entre 360 y 1800 segundos")

    nc_activo = nc["enabled"]
    usuario_nc = str(nc.get("api_user") or "").strip()
    usuario_npm = str(napi.get("user") or "").strip()
    clave_nc_nueva = nc.get("api_key")
    clave_npm_nueva = napi.get("password")

    def cambiar(datos):
        a = datos["settings"]
        a["sync"] = {"enabled": sync["enabled"], "cron": expresion}
        a["renewal"] = {
            "days_before_expiry": dias,
            "warning_days": aviso,
            "max_automatic_attempts": intentos,
        }
        a["namecheap"]["enabled"] = nc_activo
        a["namecheap"]["api_user"] = usuario_nc
        if clave_nc_nueva is not None and str(clave_nc_nueva) != "":
            a["namecheap"]["api_key"] = cifrar(str(clave_nc_nueva))
        if nc.get("clear_api_key"):
            a["namecheap"]["api_key"] = ""
            if clave_nc_nueva in (None, ""):
                a["namecheap"]["enabled"] = False
        a["npm_api"].update({
            "user": usuario_npm,
            "port": puerto,
            "https_port": puerto_https,
            "timeout_seconds": espera,
        })
        if clave_npm_nueva is not None and str(clave_npm_nueva) != "":
            a["npm_api"]["password"] = cifrar(str(clave_npm_nueva))
        if napi.get("clear_password"):
            a["npm_api"]["password"] = str()

        if a["namecheap"]["enabled"]:
            if not usuario_nc or not a["namecheap"].get("api_key"):
                raise ErrorConfiguracion("Namecheap esta activo pero faltan su usuario o clave API")
            if not usuario_npm or not a["npm_api"].get("password"):
                raise ErrorConfiguracion("la renovacion automatica necesita el acceso API de NPM")

    return actualizar(cambiar)


def estado_operativo():
    """Estado pequeño persistente que no forma parte de la configuracion."""
    with _candado_operativo:
        ruta = os.path.join(DATOS, "operacion.json")
        try:
            with open(ruta, "r", encoding="utf-8") as f:
                datos = json.load(f)
            return datos if isinstance(datos, dict) else {}
        except (OSError, ValueError):
            return {}


def guardar_estado_operativo(cambios):
    if not isinstance(cambios, dict):
        raise ErrorConfiguracion("el estado operativo debe ser un objeto")
    with _candado_operativo:
        ruta = os.path.join(DATOS, "operacion.json")
        datos = estado_operativo()
        datos.update(copy.deepcopy(cambios))
        datos["updated_at"] = _ahora()
        carpeta = os.path.dirname(ruta) or "."
        os.makedirs(carpeta, exist_ok=True)
        contenido = (json.dumps(datos, ensure_ascii=False, indent=2) + "\n").encode()
        _guardar_bytes_seguro(ruta, contenido)
        return copy.deepcopy(datos)
