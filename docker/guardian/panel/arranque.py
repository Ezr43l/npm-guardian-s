"""Arranque y asistente inicial de NPM Guardian.

Las instalaciones nuevas no necesitan declarar la topologia ni los secretos en
Docker. Mientras ``/datos/node.json`` no exista, este proceso sirve un asistente
de configuracion. Al guardarlo, carga el entorno persistente y reemplaza el
proceso por el servidor normal: sigue existiendo un unico contenedor y un unico
proceso principal.

Las variables ``NPMG_*`` antiguas permiten arrancar despliegues existentes hasta
que el operador los migra desde el portal. Cuando existe ``node.json``, el fichero
persistente es la fuente autoritativa de la configuración local.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import ssl
import stat
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


DATOS = Path(os.environ.get("NPMG_DATA_DIR", "/datos"))
RUTA_NODO = DATOS / "node.json"
DIR_SECRETOS = DATOS / "secrets"
RUTA_SESION = DIR_SECRETOS / "session-secret"
RUTA_CLUSTER = DIR_SECRETOS / "cluster-token"
RUTA_KEEPALIVED = DIR_SECRETOS / "keepalived-api-token"
RUTA_KEEPALIVED_CA = DIR_SECRETOS / "keepalived-ca.pem"
RUTA_NPM_CA = DIR_SECRETOS / "npm-ca.pem"
DIR_WEB = Path(os.environ.get("NPMG_WEB", Path(__file__).with_name("web")))
PUERTO = int(os.environ.get("NPMG_PORT", "6061"))
VERSION = (Path(__file__).parents[1] / "APP_VERSION")
NOMBRE_VALIDO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
CANDADO_INICIO = threading.Lock()


class ErrorArranque(ValueError):
    """La configuracion local no es valida."""


def _version():
    try:
        return VERSION.read_text(encoding="utf-8").strip() or "desarrollo"
    except OSError:
        return "desarrollo"


def _booleano(valor):
    if type(valor) is not bool:
        raise ErrorArranque("los permisos inseguros deben ser booleanos")
    return valor


def _texto(valor, nombre, maximo=2048, obligatorio=False):
    if valor is None:
        valor = ""
    if not isinstance(valor, str):
        raise ErrorArranque(f"{nombre} debe ser texto")
    salida = valor.strip()
    if obligatorio and not salida:
        raise ErrorArranque(f"{nombre} es obligatorio")
    if len(salida) > maximo or any(ord(c) < 32 or ord(c) == 127 for c in salida):
        raise ErrorArranque(f"{nombre} contiene caracteres no permitidos")
    return salida


def _puerto(valor, nombre):
    if isinstance(valor, bool):
        raise ErrorArranque(f"{nombre} no es valido")
    try:
        salida = int(valor)
    except (TypeError, ValueError) as error:
        raise ErrorArranque(f"{nombre} no es valido") from error
    if not 1 <= salida <= 65535:
        raise ErrorArranque(f"{nombre} debe estar entre 1 y 65535")
    return salida


def _entero_rango(valor, nombre, minimo, maximo):
    if isinstance(valor, bool):
        raise ErrorArranque(f"{nombre} no es valido")
    try:
        salida = int(valor)
    except (TypeError, ValueError) as error:
        raise ErrorArranque(f"{nombre} no es valido") from error
    if not minimo <= salida <= maximo:
        raise ErrorArranque(
            f"{nombre} debe estar entre {minimo} y {maximo}")
    return salida


def _certificado_ca(valor, nombre):
    if valor is None:
        return ""
    if not isinstance(valor, str):
        raise ErrorArranque(f"{nombre} debe ser texto PEM")
    salida = valor.strip().replace("\r\n", "\n")
    if not salida:
        return ""
    if len(salida.encode("utf-8")) > 256 * 1024 or "\x00" in salida:
        raise ErrorArranque(f"{nombre} supera el tamano permitido")
    try:
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.load_verify_locations(cadata=salida)
    except (ssl.SSLError, ValueError) as error:
        raise ErrorArranque(f"{nombre} no contiene certificados CA validos") from error
    return salida + "\n"


def _url(valor, nombre, obligatoria=True):
    salida = _texto(valor, nombre, obligatorio=obligatoria)
    if not salida:
        return ""
    parsed = urllib.parse.urlparse(salida)
    if (parsed.scheme.lower() not in ("http", "https") or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ErrorArranque(f"{nombre} debe ser una URL http(s) sin credenciales, query ni fragmento")
    return salida.rstrip("/")


def _validar_miembros(entrada, nodo, independiente):
    if not isinstance(entrada, list) or not 1 <= len(entrada) <= 20:
        raise ErrorArranque("declara entre 1 y 20 miembros")
    miembros = []
    nombres = set()
    for item in entrada:
        if not isinstance(item, dict) or set(item) != {"name", "address", "guardian_url"}:
            raise ErrorArranque("cada miembro debe incluir name, address y guardian_url")
        nombre = _texto(item["name"], "nombre de miembro", 63, True)
        if not NOMBRE_VALIDO.fullmatch(nombre):
            raise ErrorArranque(f"el nombre de miembro {nombre!r} no es valido")
        clave = nombre.casefold()
        if clave in nombres:
            raise ErrorArranque(f"el miembro {nombre!r} esta repetido")
        nombres.add(clave)
        direccion = _texto(item["address"], f"direccion de {nombre}", 255, True)
        if any(c in direccion for c in ",=|"):
            raise ErrorArranque(f"la direccion de {nombre!r} contiene un separador no permitido")
        url = _url(item["guardian_url"], f"URL Guardian de {nombre}", obligatoria=clave != nodo.casefold())
        miembros.append({"name": nombre, "address": direccion, "guardian_url": url})
    if nodo.casefold() not in nombres:
        raise ErrorArranque("la lista de miembros debe incluir este nodo")
    if independiente and len(miembros) != 1:
        raise ErrorArranque("el modo independiente admite un unico miembro")
    if not independiente and len(miembros) < 2:
        raise ErrorArranque("un cluster HA necesita al menos dos miembros")
    return miembros


def _decodificar_codigo(codigo):
    try:
        relleno = "=" * (-len(codigo) % 4)
        datos = json.loads(base64.urlsafe_b64decode((codigo + relleno).encode()).decode())
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ErrorArranque("el codigo de incorporacion no es valido") from error
    if (not isinstance(datos, dict) or set(datos) != {"schema", "session", "cluster"} or
            datos.get("schema") != 1):
        raise ErrorArranque("el codigo de incorporacion no pertenece a NPM Guardian")
    for clave in ("session", "cluster"):
        valor = _texto(datos.get(clave), f"secreto {clave}", 4096, True)
        if len(valor) < 32 or len(set(valor)) < 10:
            raise ErrorArranque("el codigo de incorporacion contiene un secreto debil")
    if secrets.compare_digest(datos["session"], datos["cluster"]):
        raise ErrorArranque("el codigo de incorporacion reutiliza el mismo secreto")
    return datos["session"], datos["cluster"]


def _codificar_codigo(secreto_sesion, token_cluster):
    claro = json.dumps({
        "schema": 1, "session": secreto_sesion, "cluster": token_cluster,
    }, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(claro).decode().rstrip("=")


def validar(entrada):
    if not isinstance(entrada, dict) or set(entrada) != {
            "node", "members", "standalone", "keepalived", "portal", "npm", "enrollment_code"}:
        raise ErrorArranque("el formulario de inicio esta incompleto o contiene campos desconocidos")
    nodo = _texto(entrada["node"], "nombre de este nodo", 63, True)
    if not NOMBRE_VALIDO.fullmatch(nodo):
        raise ErrorArranque("el nombre de este nodo no es valido")
    independiente = _booleano(entrada["standalone"])
    miembros = _validar_miembros(entrada["members"], nodo, independiente)

    keepalived = entrada["keepalived"]
    portal = entrada["portal"]
    npm = entrada["npm"]
    if (not isinstance(keepalived, dict) or
            not {"url", "service", "token", "allow_http"} <= set(keepalived) or
            set(keepalived) - {"url", "service", "token", "allow_http", "ca_certificate"}):
        raise ErrorArranque("la configuracion de Keepalived esta incompleta")
    if (not isinstance(portal, dict) or
            not {"public_url", "trusted_proxies", "allow_http"} <= set(portal) or
            set(portal) - {"public_url", "trusted_proxies", "allow_http",
                           "public_port", "session_minutes"}):
        raise ErrorArranque("la configuracion del portal esta incompleta")
    if (not isinstance(npm, dict) or
            not {"container", "scheme", "api_port", "https_port", "allow_http"} <= set(npm) or
            set(npm) - {"container", "scheme", "api_port", "https_port",
                        "allow_http", "ca_certificate"}):
        raise ErrorArranque("la configuracion de NPM esta incompleta")

    keepalived_url = _url(keepalived["url"], "URL de Keepalived", not independiente)
    keepalived_http = _booleano(keepalived["allow_http"])
    if keepalived_url.startswith("http://") and not keepalived_http:
        raise ErrorArranque("autoriza expresamente HTTP para Keepalived o utiliza HTTPS")
    servicio = _texto(keepalived["service"], "servicio de Keepalived", 128,
                      obligatorio=not independiente)
    token_keepalived = _texto(keepalived["token"], "token de Keepalived", 4096)
    if token_keepalived and any(caracter.isspace() for caracter in token_keepalived):
        raise ErrorArranque("el token de Keepalived no admite espacios")
    ca_keepalived = _certificado_ca(
        keepalived.get("ca_certificate", ""), "CA de Keepalived")

    portal_http = _booleano(portal["allow_http"])
    publica = _url(portal["public_url"], "URL publica", obligatoria=False)
    proxies = _texto(portal["trusted_proxies"], "proxies de confianza", 2048)
    puerto_publico = _puerto(portal.get("public_port", PUERTO), "puerto publico")
    minutos_sesion = _entero_rango(
        portal.get("session_minutes", 15), "duracion de sesion", 5, 60)
    if not portal_http:
        if not proxies:
            raise ErrorArranque("indica el proxy de confianza o autoriza el portal HTTP en tu LAN")
        if publica and not publica.startswith("https://"):
            raise ErrorArranque("la URL publica debe usar HTTPS en el perfil seguro")

    esquema_npm = _texto(npm["scheme"], "esquema de NPM", 5, True).lower()
    if esquema_npm not in ("http", "https"):
        raise ErrorArranque("el esquema de NPM debe ser http o https")
    npm_http = _booleano(npm["allow_http"])
    if esquema_npm == "http" and not npm_http:
        raise ErrorArranque("autoriza expresamente HTTP para la API de NPM o utiliza HTTPS")
    contenedor = _texto(npm["container"], "contenedor de NPM", 255, True)
    if any(c in contenedor for c in "/\\"):
        raise ErrorArranque("usa el nombre del contenedor de NPM, no una ruta")
    ca_npm = _certificado_ca(npm.get("ca_certificate", ""), "CA de NPM")

    codigo = _texto(entrada["enrollment_code"], "codigo de incorporacion", 16384)
    return {
        "schema": 1,
        "node": nodo,
        "members": miembros,
        "standalone": independiente,
        "keepalived": {
            "url": keepalived_url, "service": servicio,
            "allow_http": keepalived_http,
        },
        "portal": {
            "public_url": publica, "trusted_proxies": proxies,
            "allow_http": portal_http, "public_port": puerto_publico,
            "session_minutes": minutos_sesion,
        },
        "npm": {
            "container": contenedor, "scheme": esquema_npm,
            "api_port": _puerto(npm["api_port"], "puerto de la API de NPM"),
            "https_port": _puerto(npm["https_port"], "puerto HTTPS de NPM"),
            "allow_http": npm_http,
        },
        "_token_keepalived": token_keepalived,
        "_ca_keepalived": ca_keepalived,
        "_ca_npm": ca_npm,
        "_enrollment_code": codigo,
    }


def _escribir_atomico(ruta, contenido, modo=0o600):
    ruta.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporal = tempfile.mkstemp(prefix=ruta.name + ".", dir=str(ruta.parent))
    try:
        os.fchmod(descriptor, modo)
        with os.fdopen(descriptor, "wb") as fichero:
            fichero.write(contenido)
            fichero.flush()
            os.fsync(fichero.fileno())
        os.replace(temporal, ruta)
        os.chmod(ruta, modo)
    finally:
        try:
            os.unlink(temporal)
        except FileNotFoundError:
            pass


def _configurado(ruta):
    try:
        metadatos = ruta.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(metadatos.st_mode) and not stat.S_ISLNK(metadatos.st_mode) \
        and metadatos.st_size > 0


def _material_entorno(nombre, legado=None, maximo=64 * 1024):
    nombres = tuple(filter(None, (nombre, legado)))
    directos = [(clave, (os.environ.get(clave) or "").strip())
                for clave in nombres if (os.environ.get(clave) or "").strip()]
    ficheros = [(clave + "_FILE", (os.environ.get(clave + "_FILE") or "").strip())
                for clave in nombres if (os.environ.get(clave + "_FILE") or "").strip()]
    if len(directos) + len(ficheros) > 1:
        raise ErrorArranque(
            f"configuracion ambigua para {nombre}: usa un valor o un fichero, no ambos")
    if directos:
        return directos[0][1]
    if not ficheros:
        return ""
    variable, valor = ficheros[0]
    ruta = Path(valor)
    if not ruta.is_absolute():
        raise ErrorArranque(f"{variable} debe usar una ruta absoluta")
    try:
        metadatos = ruta.lstat()
    except OSError as error:
        raise ErrorArranque(f"no se puede leer {variable}") from error
    if (stat.S_ISLNK(metadatos.st_mode) or not stat.S_ISREG(metadatos.st_mode) or
            metadatos.st_size > maximo):
        raise ErrorArranque(f"{variable} no es un fichero regular valido")
    try:
        return ruta.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise ErrorArranque(f"no se puede leer {variable} como UTF-8") from error


def _booleano_entorno(nombre, legado=None, por_omision=False):
    valor = os.environ.get(nombre)
    if valor is None and legado:
        valor = os.environ.get(legado)
    if valor is None:
        return por_omision
    return str(valor).strip().lower() in ("1", "true", "yes", "si", "sí", "on")


def _configuracion_entorno():
    """Normaliza una instalación anterior para poder migrarla desde el portal."""
    nodo = (os.environ.get("NPMG_NODE_NAME") or
            os.environ.get("NPMHA_NODO") or "sin-nombre").strip()
    direccion_local = (os.environ.get("NPMG_NODE_ADDRESS") or
                       os.environ.get("NPMHA_MI_IP") or nodo).strip()
    urls = {}
    pares_crudos = os.environ.get("NPMG_PEERS", os.environ.get("NPMHA_PARES", ""))
    for indice, trozo in enumerate(pares_crudos.split(",")):
        trozo = trozo.strip()
        if not trozo:
            continue
        nombre, url = (trozo.split("=", 1) if "=" in trozo
                       else (f"peer-{indice + 1}", trozo))
        urls[nombre.strip().casefold()] = (nombre.strip(), url.strip().rstrip("/"))

    declarados = []
    nodos_crudos = (os.environ.get("NPMG_NODES") or
                    os.environ.get("NPMHA_NODOS") or "")
    for trozo in nodos_crudos.split(","):
        trozo = trozo.strip()
        if not trozo:
            continue
        if ":" not in trozo:
            raise ErrorArranque("cada entrada de NPMG_NODES debe ser nombre:direccion")
        nombre, direccion = (parte.strip() for parte in trozo.split(":", 1))
        declarados.append((nombre, direccion))
    if not declarados:
        declarados.append((nodo, direccion_local))
        for clave, (nombre, url) in urls.items():
            host = urllib.parse.urlparse(url).hostname or nombre
            if clave != nodo.casefold():
                declarados.append((nombre, host))
    elif nodo.casefold() not in {nombre.casefold() for nombre, _ in declarados}:
        declarados.insert(0, (nodo, direccion_local))

    miembros = []
    for nombre, direccion in declarados:
        clave = nombre.casefold()
        miembros.append({
            "name": nombre,
            "address": direccion_local if clave == nodo.casefold() else direccion,
            "guardian_url": "" if clave == nodo.casefold() else urls.get(clave, ("", ""))[1],
        })
    independiente = _booleano_entorno(
        "NPMG_STANDALONE", por_omision=len(miembros) == 1)
    entrada = {
        "node": nodo,
        "members": miembros,
        "standalone": independiente,
        "keepalived": {
            "url": (os.environ.get("NPMG_KEEPALIVED_URL") or
                    os.environ.get("NPMHA_PANEL_FLOTANTE") or
                    ("" if independiente else "http://host.docker.internal:6060")),
            "service": (os.environ.get("NPMG_KEEPALIVED_SERVICE") or
                        os.environ.get("NPMHA_SERVICIO") or
                        ("" if independiente else "npm")),
            "token": "",  # nosec B105: valor vacío para no persistir el secreto
            "ca_certificate": "",
            "allow_http": _booleano_entorno(
                "NPMG_ALLOW_INSECURE_KEEPALIVED_API", por_omision=independiente),
        },
        "portal": {
            "public_url": os.environ.get("NPMG_PUBLIC_URL", ""),
            "public_port": os.environ.get("NPMG_PUBLIC_PORT", str(PUERTO)),
            "session_minutes": os.environ.get("NPMG_SESSION_MINUTES", "15"),
            "trusted_proxies": os.environ.get("NPMG_TRUSTED_PROXY_IPS", ""),
            "allow_http": _booleano_entorno("NPMG_ALLOW_INSECURE_PORTAL"),
        },
        "npm": {
            "container": (os.environ.get("NPMG_NPM_CONTAINER") or
                          os.environ.get("NPMHA_NPM_CONTENEDOR") or "NPM"),
            "scheme": os.environ.get("NPMG_NPM_API_SCHEME", "https"),
            "api_port": os.environ.get("NPMG_NPM_API_PORT", "443"),
            "https_port": os.environ.get("NPMG_NPM_HTTPS_PORT", "443"),
            "ca_certificate": "",
            "allow_http": _booleano_entorno("NPMG_ALLOW_INSECURE_NPM_API"),
        },
        "enrollment_code": "",
    }
    datos = validar(entrada)
    _separar_material(datos)
    return datos


def _borrar_regular(ruta, nombre):
    try:
        metadatos = ruta.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadatos.st_mode) or not stat.S_ISREG(metadatos.st_mode):
        raise ErrorArranque(f"{nombre} no es un fichero regular")
    ruta.unlink()
    descriptor = os.open(str(ruta.parent), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _separar_material(datos):
    return (
        datos.pop("_enrollment_code"),
        datos.pop("_token_keepalived"),
        datos.pop("_ca_keepalived"),
        datos.pop("_ca_npm"),
    )


def guardar(entrada):
    if RUTA_NODO.exists():
        raise ErrorArranque("este nodo ya esta configurado")
    datos = validar(entrada)
    codigo, token_keepalived, ca_keepalived, ca_npm = _separar_material(datos)
    if codigo:
        secreto_sesion, token_cluster = _decodificar_codigo(codigo)
        codigo_salida = ""
    else:
        secreto_sesion = secrets.token_urlsafe(48)
        token_cluster = secrets.token_urlsafe(48)
        codigo_salida = _codificar_codigo(secreto_sesion, token_cluster)

    DIR_SECRETOS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(DIR_SECRETOS, 0o700)
    _escribir_atomico(RUTA_SESION, (secreto_sesion + "\n").encode())
    _escribir_atomico(RUTA_CLUSTER, (token_cluster + "\n").encode())
    if token_keepalived:
        _escribir_atomico(RUTA_KEEPALIVED, (token_keepalived + "\n").encode())
    if ca_keepalived:
        _escribir_atomico(RUTA_KEEPALIVED_CA, ca_keepalived.encode())
    if ca_npm:
        _escribir_atomico(RUTA_NPM_CA, ca_npm.encode())
    _escribir_atomico(
        RUTA_NODO,
        (json.dumps(datos, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
    )
    return codigo_salida


def _leer_configuracion():
    try:
        metadatos = RUTA_NODO.lstat()
        if stat.S_ISLNK(metadatos.st_mode) or not stat.S_ISREG(metadatos.st_mode):
            raise ErrorArranque("node.json debe ser un fichero regular")
        if metadatos.st_size > 256 * 1024:
            raise ErrorArranque("node.json supera el tamano permitido")
        datos = json.loads(RUTA_NODO.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as error:
        raise ErrorArranque(f"no se puede cargar node.json: {error}") from error
    # Reutilizar el mismo contrato evita aceptar configuracion manual ambigua.
    entrada = dict(datos)
    if entrada.pop("schema", None) != 1:
        raise ErrorArranque("node.json usa un esquema no compatible")
    entrada["enrollment_code"] = ""
    entrada["keepalived"] = dict(
        entrada.get("keepalived") or {}, token="", ca_certificate="")  # nosec B106
    entrada["npm"] = dict(entrada.get("npm") or {}, ca_certificate="")
    normalizada = validar(entrada)
    _separar_material(normalizada)
    return normalizada


def ajustes_publicos():
    persistida = RUTA_NODO.exists()
    datos = _leer_configuracion() if persistida else _configuracion_entorno()
    token_entorno = ("" if persistida else _material_entorno(
        "NPMG_KEEPALIVED_API_TOKEN", "NPMHA_KEEPALIVED_API_TOKEN"))
    return {
        "node": datos["node"],
        "members": datos["members"],
        "standalone": datos["standalone"],
        "keepalived": {
            **datos["keepalived"],
            "token_configured": _configurado(RUTA_KEEPALIVED) or bool(token_entorno),
            "ca_configured": _configurado(RUTA_KEEPALIVED_CA) or (
                not persistida and bool(os.environ.get("NPMG_KEEPALIVED_CA_FILE"))),
        },
        "portal": datos["portal"],
        "npm": {
            **datos["npm"],
            "ca_configured": _configurado(RUTA_NPM_CA) or (
                not persistida and bool(os.environ.get("NPMG_NPM_CA_FILE"))),
        },
        "managed_secrets": {
            "session": _configurado(RUTA_SESION) or (not persistida and bool(
                _material_entorno("NPMG_SESSION_SECRET", "NPMHA_SESSION_SECRET"))),
            "cluster": _configurado(RUTA_CLUSTER) or (not persistida and bool(
                _material_entorno("NPMG_CLUSTER_TOKEN", "NPMHA_CLUSTER_TOKEN"))),
        },
    }


def actualizar(entrada):
    """Actualiza la configuracion local y el material TLS sin exponer secretos."""
    if not isinstance(entrada, dict) or set(entrada) != {
            "node", "members", "standalone", "keepalived", "portal", "npm"}:
        raise ErrorArranque(
            "la configuracion del nodo esta incompleta o contiene campos desconocidos")
    copia = dict(entrada)
    keepalived = dict(copia.get("keepalived") or {})
    npm = dict(copia.get("npm") or {})
    extras_keepalived = {"clear_token", "clear_ca_certificate"}
    extras_npm = {"clear_ca_certificate"}
    if set(keepalived) - {
            "url", "service", "token", "allow_http", "ca_certificate",
            *extras_keepalived}:
        raise ErrorArranque("la configuracion de Keepalived contiene campos desconocidos")
    if set(npm) - {
            "container", "scheme", "api_port", "https_port", "allow_http",
            "ca_certificate", *extras_npm}:
        raise ErrorArranque("la configuracion de NPM contiene campos desconocidos")
    clear_token = keepalived.pop("clear_token", False)
    clear_keepalived_ca = keepalived.pop("clear_ca_certificate", False)
    clear_npm_ca = npm.pop("clear_ca_certificate", False)
    for nombre, valor in (("clear_token", clear_token),
            ("clear_keepalived_ca", clear_keepalived_ca),
            ("clear_npm_ca", clear_npm_ca),
    ):
        if type(valor) is not bool:
            raise ErrorArranque(f"{nombre} debe ser booleano")
    if clear_token and keepalived.get("token"):
        raise ErrorArranque("no se puede guardar y borrar el token de Keepalived a la vez")
    if clear_keepalived_ca and keepalived.get("ca_certificate"):
        raise ErrorArranque("no se puede guardar y borrar la CA de Keepalived a la vez")
    if clear_npm_ca and npm.get("ca_certificate"):
        raise ErrorArranque("no se puede guardar y borrar la CA de NPM a la vez")
    copia["keepalived"] = keepalived
    copia["npm"] = npm
    copia["enrollment_code"] = ""
    datos = validar(copia)
    _, token, ca_keepalived, ca_npm = _separar_material(datos)

    if not RUTA_NODO.exists():
        sesion = _material_entorno("NPMG_SESSION_SECRET", "NPMHA_SESSION_SECRET")
        cluster = _material_entorno("NPMG_CLUSTER_TOKEN", "NPMHA_CLUSTER_TOKEN")
        if not sesion or not cluster:
            raise ErrorArranque(
                "no se pueden migrar los secretos administrados de esta instalacion")
        _escribir_atomico(RUTA_SESION, (sesion + "\n").encode())
        _escribir_atomico(RUTA_CLUSTER, (cluster + "\n").encode())
        if not token and not clear_token:
            token_legacy = _material_entorno(
                "NPMG_KEEPALIVED_API_TOKEN", "NPMHA_KEEPALIVED_API_TOKEN")
            if token_legacy:
                _escribir_atomico(RUTA_KEEPALIVED, (token_legacy + "\n").encode())
        for variable, ruta, nombre in (
                ("NPMG_KEEPALIVED_CA_FILE", RUTA_KEEPALIVED_CA, "CA de Keepalived"),
                ("NPMG_NPM_CA_FILE", RUTA_NPM_CA, "CA de NPM")):
            origen = (os.environ.get(variable) or "").strip()
            if not origen or (ruta == RUTA_KEEPALIVED_CA and (ca_keepalived or clear_keepalived_ca)) \
                    or (ruta == RUTA_NPM_CA and (ca_npm or clear_npm_ca)):
                continue
            ca = _certificado_ca(
                _material_entorno(variable.removesuffix("_FILE"), maximo=256 * 1024),
                nombre)
            if ca:
                _escribir_atomico(ruta, ca.encode())

    if token:
        _escribir_atomico(RUTA_KEEPALIVED, (token + "\n").encode())
    elif clear_token:
        _borrar_regular(RUTA_KEEPALIVED, "el token de Keepalived")
    if ca_keepalived:
        _escribir_atomico(RUTA_KEEPALIVED_CA, ca_keepalived.encode())
    elif clear_keepalived_ca:
        _borrar_regular(RUTA_KEEPALIVED_CA, "CA de Keepalived")
    if ca_npm:
        _escribir_atomico(RUTA_NPM_CA, ca_npm.encode())
    elif clear_npm_ca:
        _borrar_regular(RUTA_NPM_CA, "CA de NPM")
    _escribir_atomico(
        RUTA_NODO,
        (json.dumps(datos, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
    )
    return ajustes_publicos()


def cargar_entorno(datos):
    miembros = datos["members"]
    nodo = datos["node"]
    local = next(miembro for miembro in miembros if miembro["name"].casefold() == nodo.casefold())
    pares = [miembro for miembro in miembros if miembro is not local]
    valores = {
        "NPMG_NODE_NAME": nodo,
        "NPMG_NODE_ADDRESS": local["address"],
        "NPMG_NODES": ",".join(f'{m["name"]}:{m["address"]}' for m in miembros),
        "NPMG_PEERS": ",".join(f'{m["name"]}={m["guardian_url"]}' for m in pares),
        "NPMG_STANDALONE": "1" if datos["standalone"] else "0",
        "NPMG_KEEPALIVED_URL": datos["keepalived"]["url"],
        "NPMG_KEEPALIVED_SERVICE": datos["keepalived"]["service"],
        "NPMG_ALLOW_INSECURE_KEEPALIVED_API": "1" if datos["keepalived"]["allow_http"] else "0",
        "NPMG_PUBLIC_URL": datos["portal"]["public_url"],
        "NPMG_PUBLIC_PORT": str(datos["portal"]["public_port"]),
        "NPMG_TRUSTED_PROXY_IPS": datos["portal"]["trusted_proxies"],
        "NPMG_ALLOW_INSECURE_PORTAL": "1" if datos["portal"]["allow_http"] else "0",
        "NPMG_SESSION_MINUTES": str(datos["portal"]["session_minutes"]),
        "NPMG_NPM_CONTAINER": datos["npm"]["container"],
        "NPMG_NPM_API_SCHEME": datos["npm"]["scheme"],
        "NPMG_NPM_API_PORT": str(datos["npm"]["api_port"]),
        "NPMG_NPM_HTTPS_PORT": str(datos["npm"]["https_port"]),
        "NPMG_ALLOW_INSECURE_NPM_API": "1" if datos["npm"]["allow_http"] else "0",
    }
    for clave, valor in valores.items():
        os.environ[clave] = valor

    for clave in (
            "NPMG_SESSION_SECRET", "NPMHA_SESSION_SECRET",
            "NPMG_SESSION_SECRET_FILE", "NPMHA_SESSION_SECRET_FILE"):
        os.environ.pop(clave, None)
    os.environ["NPMG_SESSION_SECRET_FILE"] = str(RUTA_SESION)
    for clave in (
            "NPMG_CLUSTER_TOKEN", "NPMHA_CLUSTER_TOKEN",
            "NPMG_CLUSTER_TOKEN_FILE", "NPMHA_CLUSTER_TOKEN_FILE"):
        os.environ.pop(clave, None)
    os.environ["NPMG_CLUSTER_TOKEN_FILE"] = str(RUTA_CLUSTER)
    for clave in (
            "NPMG_KEEPALIVED_API_TOKEN", "NPMHA_KEEPALIVED_API_TOKEN",
            "NPMG_KEEPALIVED_API_TOKEN_FILE", "NPMHA_KEEPALIVED_API_TOKEN_FILE"):
        os.environ.pop(clave, None)
    if _configurado(RUTA_KEEPALIVED):
        os.environ["NPMG_KEEPALIVED_API_TOKEN_FILE"] = str(RUTA_KEEPALIVED)
    os.environ.pop("NPMG_KEEPALIVED_CA_FILE", None)
    if _configurado(RUTA_KEEPALIVED_CA):
        os.environ["NPMG_KEEPALIVED_CA_FILE"] = str(RUTA_KEEPALIVED_CA)
    os.environ.pop("NPMG_NPM_CA_FILE", None)
    if _configurado(RUTA_NPM_CA):
        os.environ["NPMG_NPM_CA_FILE"] = str(RUTA_NPM_CA)


def _entorno_legacy_completo():
    return bool((os.environ.get("NPMG_NODE_NAME") or os.environ.get("NPMHA_NODO")) and
                (os.environ.get("NPMG_NODES") or os.environ.get("NPMHA_NODOS")) and
                any(os.environ.get(clave) for clave in
                    ("NPMG_SESSION_SECRET", "NPMHA_SESSION_SECRET",
                     "NPMG_SESSION_SECRET_FILE", "NPMHA_SESSION_SECRET_FILE")) and
                any(os.environ.get(clave) for clave in
                    ("NPMG_CLUSTER_TOKEN", "NPMHA_CLUSTER_TOKEN",
                     "NPMG_CLUSTER_TOKEN_FILE", "NPMHA_CLUSTER_TOKEN_FILE")))


def _ejecutar_servidor():
    servidor = str(Path(__file__).with_name("servidor.py"))
    os.execv(sys.executable, [sys.executable, servidor])  # nosec B606: sin shell


TIPOS = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}


class ManejadorInicio(BaseHTTPRequestHandler):
    server_version = "npm-guardian-setup"
    protocol_version = "HTTP/1.1"

    def log_message(self, formato, *args):
        pass

    def _cabeceras(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                         "script-src 'self'; connect-src 'self'; frame-ancestors 'none'")

    def _json(self, datos, codigo=200):
        cuerpo = json.dumps(datos, ensure_ascii=False).encode()
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        self._cabeceras()
        self.end_headers()
        self.wfile.write(cuerpo)

    def _estatico(self, ruta):
        if ruta in ("", "/"):
            ruta = "/index.html"
        destino = DIR_WEB / os.path.normpath(ruta).lstrip("/\\")
        try:
            seguro = os.path.commonpath((str(destino.resolve()), str(DIR_WEB.resolve()))) == str(DIR_WEB.resolve())
        except (OSError, ValueError):
            seguro = False
        if not seguro or not destino.is_file():
            return self._json({"error": "No existe", "code": "NOT_FOUND"}, 404)
        cuerpo = destino.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", TIPOS.get(destino.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-cache")
        self._cabeceras()
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_GET(self):
        ruta = self.path.split("?", 1)[0]
        if ruta == "/api/health":
            return self._json({"status": "setup-required"})
        if ruta == "/api/version":
            return self._json({"product": "NPM Guardian", "version": _version()})
        if ruta == "/api/bootstrap/status":
            return self._json({"required": True, "version": _version()})
        if ruta.startswith("/api/"):
            return self._json({"error": "Completa primero la configuracion del nodo",
                               "code": "SETUP_REQUIRED"}, 409)
        return self._estatico(ruta)

    def do_POST(self):
        ruta = self.path.split("?", 1)[0]
        if ruta != "/api/bootstrap":
            return self._json({"error": "No existe", "code": "NOT_FOUND"}, 404)
        try:
            if self.headers.get("Transfer-Encoding"):
                raise ErrorArranque("Transfer-Encoding no esta permitido")
            longitud = int(self.headers.get("Content-Length") or "0")
            if not 1 <= longitud <= 128 * 1024:
                raise ErrorArranque("el formulario esta vacio o es demasiado grande")
            entrada = json.loads(self.rfile.read(longitud).decode())
            with CANDADO_INICIO:
                codigo = guardar(entrada)
            self._json({"ok": True, "restarting": True, "enrollment_code": codigo})
            threading.Thread(target=self._reiniciar, daemon=True).start()
        except (ErrorArranque, ValueError, UnicodeError, json.JSONDecodeError) as error:
            return self._json({"error": str(error), "code": "INVALID_SETUP"}, 422)

    @staticmethod
    def _reiniciar():
        time.sleep(0.5)
        cargar_entorno(_leer_configuracion())
        _ejecutar_servidor()


def main():
    if RUTA_NODO.exists():
        cargar_entorno(_leer_configuracion())
        return _ejecutar_servidor()
    if _entorno_legacy_completo():
        return _ejecutar_servidor()
    DATOS.mkdir(parents=True, exist_ok=True)
    print(f"NPM Guardian · configuracion inicial pendiente · puerto={PUERTO}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PUERTO), ManejadorInicio).serve_forever()  # nosec B104


if __name__ == "__main__":
    main()
