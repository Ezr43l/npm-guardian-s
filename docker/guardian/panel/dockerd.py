"""Cliente Docker mínimo de NPM Guardian mediante el socket local.

La aplicación vive en un único contenedor. Sólo implementa las operaciones
cerradas que necesita sobre los nombres declarados en ``NPMG_NPM_CONTAINER``;
no instala un SDK Docker ni acepta órdenes arbitrarias desde el portal.
"""
import http.client
import json
import os
import socket
import urllib.parse

RUTA_SOCKET = os.environ.get(
    "NPMG_DOCKER_SOCKET", os.environ.get(
        "NPMHA_DOCKER_SOCKET", "/var/run/docker.sock")).strip()

# Lista blanca. Aunque alguien llegue al panel, no puede pedirle que pare
# cualquier cosa: si el nombre no esta aqui, no se toca.
NOMBRES_CONFIGURADOS = [
    n.strip() for n in (os.environ.get("NPMG_NPM_CONTAINER") or
                        os.environ.get("NPMHA_NPM_CONTENEDOR") or "NPM").split(",") if n.strip()
]
NOMBRES_PERMITIDOS = set(NOMBRES_CONFIGURADOS)


class ErrorDocker(Exception):
    """No se pudo hablar con el demonio, o dijo que no."""


class _ConexionUnix(http.client.HTTPConnection):
    def __init__(self, ruta_socket, tiempo):
        super().__init__("localhost", timeout=tiempo)
        self.ruta_socket = ruta_socket

    def connect(self):  # pragma: no cover - requiere un socket Docker Linux
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.ruta_socket)


def _conexion(tiempo):
    if not os.path.isabs(RUTA_SOCKET):
        raise ErrorDocker("NPMG_DOCKER_SOCKET debe ser una ruta absoluta")
    return _ConexionUnix(RUTA_SOCKET, tiempo)


def _llamar(metodo, ruta, tiempo=90, cuerpo=None):
    if cuerpo is None:
        datos = b""
    elif isinstance(cuerpo, bytes):
        datos = cuerpo
    else:
        datos = json.dumps(cuerpo, separators=(",", ":")).encode("utf-8")
    conexion = _conexion(tiempo)
    try:
        cabeceras = {"Connection": "close", "Content-Length": str(len(datos))}
        if datos:
            cabeceras["Content-Type"] = "application/json"
        conexion.request(metodo, ruta, body=datos, headers=cabeceras)
        respuesta = conexion.getresponse()
        return respuesta.status, respuesta.read()
    except (OSError, http.client.HTTPException) as e:
        raise ErrorDocker(
            f"no se llega al socket Docker en {RUTA_SOCKET} ({e.__class__.__name__})") from e
    finally:
        conexion.close()


def _desmontar_trozos(datos):
    salida, resto = b"", datos
    while True:
        linea, _, resto = resto.partition(b"\r\n")
        try:
            n = int(linea.strip() or b"0", 16)
        except ValueError:
            break
        if n == 0:
            break
        salida += resto[:n]
        resto = resto[n + 2:]
    return salida


def _comprobar_permitido(nombre):
    if nombre not in NOMBRES_PERMITIDOS:
        raise ErrorDocker(
            f"«{nombre}» no está en la lista de contenedores que este guardián puede tocar "
            f"({sorted(NOMBRES_PERMITIDOS)}).")


def estado(nombre):
    """¿Existe y está corriendo? Sin excepciones para el caso normal de «no está»."""
    _comprobar_permitido(nombre)
    codigo, cuerpo = _llamar("GET", f"/containers/{nombre}/json", tiempo=20)
    if codigo == 404:
        return {"existe": False, "corriendo": False}
    if codigo != 200:
        raise ErrorDocker(f"Docker devolvió {codigo} al preguntar por «{nombre}»")
    try:
        d = json.loads(cuerpo.decode())
    except ValueError:
        raise ErrorDocker(f"no se entiende la respuesta de Docker sobre «{nombre}»")
    return {
        "existe": True,
        "corriendo": bool(d.get("State", {}).get("Running")),
        "estado": d.get("State", {}).get("Status"),
        "imagen": d.get("Config", {}).get("Image"),
    }


def parar(nombre, espera=30):
    _comprobar_permitido(nombre)
    codigo, cuerpo = _llamar("POST", f"/containers/{nombre}/stop?t={espera}", tiempo=espera + 30)
    # 304 = ya estaba parado. No es un error: es el resultado que se buscaba.
    if codigo not in (204, 304):
        raise ErrorDocker(f"no se pudo parar «{nombre}»: HTTP {codigo} {cuerpo[:200]!r}")
    return codigo == 204


def arrancar(nombre):
    _comprobar_permitido(nombre)
    codigo, cuerpo = _llamar("POST", f"/containers/{nombre}/start", tiempo=60)
    if codigo not in (204, 304):
        raise ErrorDocker(f"no se pudo arrancar «{nombre}»: HTTP {codigo} {cuerpo[:200]!r}")
    return codigo == 204


def _salida_exec(datos):
    """Desmultiplexa stdout/stderr del protocolo raw-stream de Docker."""
    salida = bytearray()
    posicion = 0
    while posicion + 8 <= len(datos):
        cabecera = datos[posicion:posicion + 8]
        longitud = int.from_bytes(cabecera[4:8], "big")
        final = posicion + 8 + longitud
        if cabecera[0] not in (0, 1, 2, 3) or cabecera[1:4] != b"\x00\x00\x00" or final > len(datos):
            return datos.decode("utf-8", errors="replace")
        salida.extend(datos[posicion + 8:final])
        posicion = final
    if posicion != len(datos):
        return datos.decode("utf-8", errors="replace")
    return salida.decode("utf-8", errors="replace")


def _ejecutar(nombre, orden, tiempo=30):
    """Ejecuta una orden interna; no se expone al panel ni acepta entrada del usuario."""
    _comprobar_permitido(nombre)
    nombre_url = urllib.parse.quote(nombre, safe="")
    codigo, cuerpo = _llamar("POST", f"/containers/{nombre_url}/exec", cuerpo={
        "AttachStdout": True,
        "AttachStderr": True,
        "Cmd": orden,
    })
    if codigo != 201:
        raise ErrorDocker(f"Docker no pudo preparar la comprobacion en «{nombre}»: HTTP {codigo}")
    try:
        identificador = json.loads(cuerpo.decode())["Id"]
    except (ValueError, KeyError, UnicodeError) as e:
        raise ErrorDocker("Docker no devolvio un identificador de ejecucion valido") from e

    codigo, cuerpo = _llamar("POST", f"/exec/{identificador}/start", tiempo=tiempo, cuerpo={
        "Detach": False,
        "Tty": False,
    })
    if codigo != 200:
        raise ErrorDocker(f"Docker no pudo ejecutar la comprobacion en «{nombre}»: HTTP {codigo}")
    salida = _salida_exec(cuerpo).strip()

    codigo, inspeccion = _llamar("GET", f"/exec/{identificador}/json", tiempo=20)
    if codigo != 200:
        raise ErrorDocker(f"Docker no pudo consultar el resultado en «{nombre}»: HTTP {codigo}")
    try:
        resultado = json.loads(inspeccion.decode())
        salida_codigo = resultado.get("ExitCode")
    except (ValueError, UnicodeError) as e:
        raise ErrorDocker("Docker devolvio un resultado de ejecucion no valido") from e
    if salida_codigo is None:
        raise ErrorDocker("la comprobacion de Nginx no llego a terminar")
    return {"exit_code": int(salida_codigo), "output": salida}


def contenedor_principal():
    """Nombre determinista del NPM local cuando se admiten alias de migracion."""
    if not NOMBRES_CONFIGURADOS:
        raise ErrorDocker("no hay ningun contenedor NPM permitido")
    return NOMBRES_CONFIGURADOS[0]


def recargar_nginx(nombre=None):
    """Valida y recarga Nginx dentro del NPM permitido, sin reiniciar el contenedor."""
    objetivo = nombre or contenedor_principal()
    prueba = _ejecutar(objetivo, ["/usr/sbin/nginx", "-t"], tiempo=30)
    if prueba["exit_code"] != 0:
        detalle = prueba["output"][-500:] or "sin detalle"
        raise ErrorDocker(f"la configuracion de Nginx no es valida: {detalle}")
    recarga = _ejecutar(objetivo, ["/usr/sbin/nginx", "-s", "reload"], tiempo=30)
    if recarga["exit_code"] != 0:
        detalle = recarga["output"][-500:] or "sin detalle"
        raise ErrorDocker(f"Nginx rechazo la recarga: {detalle}")
    return {"ok": True, "config_tested": True, "reloaded": True}


def disponible():
    """Para poder decir en el panel si la replica es posible en este nodo."""
    try:
        codigo, _ = _llamar("GET", "/_ping", tiempo=10)
        return codigo == 200
    except ErrorDocker:
        return False
