"""Hablar con NPM por su API, que es la UNICA forma correcta de pedirle cosas.

El guardian lee su base de datos en solo lectura para saber que hay, pero para
CAMBIAR algo usa la API: NPM tiene que regenerar la configuracion de nginx y
recargarla, y eso solo lo sabe hacer el. Escribir por debajo dejaria a NPM
sirviendo una cosa distinta de la que cree tener.

La renovacion se pide siempre al NPM del nodo que sostiene la direccion
flotante. Los demas no se tocan: recibiran el resultado cuando se replique su
estado.
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import configuracion

CADUCIDAD_MARGEN = 60  # segundos de margen antes de dar el token por vencido


class ErrorNPM(Exception):
    """Algo fue mal hablando con NPM."""

    def __init__(self, mensaje, codigo="npm_error", resultado_indeterminado=False):
        super().__init__(mensaje)
        self.codigo = codigo
        self.resultado_indeterminado = bool(resultado_indeterminado)


def credenciales():
    return configuracion.secretos_npm()


def _verdadero(nombre):
    return (os.environ.get(nombre, "0").strip().lower() in
            ("1", "true", "yes", "si", "sí", "on"))


def esquema_api():
    esquema = os.environ.get("NPMG_NPM_API_SCHEME", "https").strip().lower()
    if esquema not in ("http", "https"):
        raise ErrorNPM("NPMG_NPM_API_SCHEME debe ser http o https", "configuration")
    if esquema == "http" and not _verdadero("NPMG_ALLOW_INSECURE_NPM_API"):
        raise ErrorNPM(
            "La API de NPM usa HTTP sin autorización explícita; configura HTTPS o "
            "NPMG_ALLOW_INSECURE_NPM_API=1", "configuration")
    return esquema


def _contexto(url):
    if not str(url).lower().startswith("https://"):
        return None
    ca = configuracion.fichero_ca("NPMG_NPM_CA_FILE")
    return ssl.create_default_context(cafile=ca)


def _abrir(peticion, timeout):
    url = peticion.full_url if hasattr(peticion, "full_url") else str(peticion)
    partes = urllib.parse.urlsplit(url)
    if (partes.scheme not in ("http", "https") or not partes.hostname or
            partes.username or partes.password or partes.fragment or
            not partes.path.startswith("/api/")):
        raise ErrorNPM("la URL de NPM no cumple el contrato HTTP(S)", "configuration")
    if partes.scheme != esquema_api():
        raise ErrorNPM("la URL de NPM no usa el esquema configurado", "configuration")
    # La URL se limita al esquema configurado y a rutas /api/ HTTP(S).
    return urllib.request.urlopen(  # nosec B310
        peticion, timeout=timeout, context=_contexto(url))


def _base_del_activo(nodo_activo, puerto=None):
    tabla = _tabla_nodos()
    destino = tabla.get(nodo_activo) or (nodo_activo if _parece_ip(nodo_activo) else None)
    if not destino:
        destino = os.environ.get("NPMG_NODE_ADDRESS") or os.environ.get("NPMHA_MI_IP") or ""
    if not destino:
        raise ErrorNPM("No se conoce la direccion del NPM activo", "unavailable")
    puerto = puerto or int(configuracion.leer()["settings"]["npm_api"].get("port") or 443)
    return f"{esquema_api()}://{destino}:{puerto}"


def autenticar_usuario(nodo_activo, usuario, clave):
    """Delega la identidad humana en NPM sin conservar su contraseña.

    El token sólo vive durante esta llamada. Además de validar las credenciales,
    se consulta ``/api/users/me`` para fijar la cuenta de Guardian al identificador
    estable de NPM y exigir el rol administrador.
    """
    usuario = str(usuario or "").strip()
    clave = str(clave or "")
    if not usuario or not clave or len(usuario) > 256 or len(clave) > 256:
        raise ErrorNPM("NPM no reconoce esas credenciales", "invalid_credentials")
    base = _base_del_activo(nodo_activo)
    cuerpo = json.dumps({"identity": usuario, "secret": clave}).encode()
    peticion = urllib.request.Request(f"{base}/api/tokens", data=cuerpo, method="POST")
    peticion.add_header("Content-Type", "application/json")
    try:
        with _abrir(peticion, timeout=20) as respuesta:
            token = json.loads(respuesta.read().decode()).get("token")
    except urllib.error.HTTPError as error:
        if error.code in (400, 401, 403):
            raise ErrorNPM("NPM no reconoce esas credenciales", "invalid_credentials") from None
        raise ErrorNPM(f"NPM no puede validar el acceso (HTTP {error.code})", "unavailable") from None
    except (TimeoutError, urllib.error.URLError):
        raise ErrorNPM("No se puede contactar con el NPM activo", "unavailable") from None
    except (ValueError, TypeError):
        raise ErrorNPM("NPM devolvio una respuesta de acceso no valida", "invalid_response") from None
    if not token:
        raise ErrorNPM("NPM no devolvio una identidad valida", "invalid_response")

    peticion = urllib.request.Request(f"{base}/api/users/me")
    peticion.add_header("Authorization", f"Bearer {token}")
    try:
        with _abrir(peticion, timeout=20) as respuesta:
            perfil = json.loads(respuesta.read().decode())
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise ErrorNPM("NPM no permite consultar esa identidad", "invalid_credentials") from None
        raise ErrorNPM(f"NPM no puede completar el acceso (HTTP {error.code})", "unavailable") from None
    except (TimeoutError, urllib.error.URLError):
        raise ErrorNPM("Se perdio la conexion con el NPM activo", "unavailable") from None
    except (ValueError, TypeError):
        raise ErrorNPM("NPM devolvio un perfil no valido", "invalid_response") from None

    if perfil.get("is_disabled"):
        raise ErrorNPM("La cuenta esta desactivada en NPM", "invalid_credentials")
    if "admin" not in (perfil.get("roles") or []):
        raise ErrorNPM("La cuenta de NPM no tiene rol de administrador", "admin_required")
    if perfil.get("id") is None or not perfil.get("email"):
        raise ErrorNPM("NPM no devolvio un identificador de usuario", "invalid_response")
    return {
        "id": str(perfil["id"]),
        "username": str(perfil["email"]).strip(),
        "display_name": str(perfil.get("name") or perfil.get("nickname") or perfil["email"]).strip(),
        "_token": token,
    }


def validar_token_usuario(nodo_activo, token, npm_user_id):
    """Revalida identidad y rol en NPM antes de una mutación sensible."""
    if not token:
        raise ErrorNPM("Vuelve a iniciar sesión con NPM para continuar",
                       "reauth_required")
    peticion = urllib.request.Request(f"{_base_del_activo(nodo_activo)}/api/users/me")
    peticion.add_header("Authorization", f"Bearer {token}")
    try:
        with _abrir(peticion, timeout=10) as respuesta:
            perfil = json.loads(respuesta.read().decode())
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise ErrorNPM("La sesión de NPM ya no es válida", "reauth_required") from None
        raise ErrorNPM(f"NPM no puede revalidar el acceso (HTTP {error.code})",
                       "unavailable") from None
    except (TimeoutError, urllib.error.URLError):
        raise ErrorNPM("No se puede revalidar el acceso contra NPM", "unavailable") from None
    except (ValueError, TypeError, UnicodeError):
        raise ErrorNPM("NPM devolvió un perfil no válido", "invalid_response") from None
    if (perfil.get("is_disabled") or "admin" not in (perfil.get("roles") or []) or
            str(perfil.get("id")) != str(npm_user_id)):
        raise ErrorNPM("La cuenta ya no es administradora activa de NPM",
                       "reauth_required")
    return True


def autenticacion_disponible(nodo_activo):
    """Distingue una caida real de NPM de unas credenciales incorrectas."""
    try:
        with _abrir(f"{_base_del_activo(nodo_activo)}/api/", timeout=5):
            return True
    except urllib.error.HTTPError as error:
        # Un 4xx explícito demuestra que contestó la aplicación/ruta. Un 5xx
        # puede ser sólo el proxy avisando de que NPM aún no levantó y no debe
        # bloquear equivocadamente el acceso de emergencia.
        return error.code in (400, 401, 403, 404, 405, 409, 422, 429)
    except Exception:  # noqa: BLE001 - sólo clasifica disponibilidad
        return False


def api_responde(nodo, timeout=5):
    """Salud HTTP usando exactamente URL, CA y verificación del cliente real."""
    try:
        with _abrir(f"{_base_del_activo(nodo)}/api/", timeout=timeout):
            return True
    except urllib.error.HTTPError as error:
        # Nunca se compromete una réplica por un 500/502/503 del proxy. Se
        # admiten sólo respuestas cliente que prueban que el endpoint de NPM
        # está atendiendo, aunque esa versión exija autenticación en la raíz.
        return error.code in (400, 401, 403, 404, 405, 409, 422, 429)
    except Exception:  # noqa: BLE001 - devuelve únicamente una señal de salud
        return False


class Cliente:
    """Un cliente por servidor de NPM. Guarda el token mientras sirva."""

    def __init__(self, base):
        self.base = base.rstrip("/")
        self._token = None
        self._vence = 0

    # ── autenticacion ───────────────────────────────────────────────────
    def _pedir_token(self):
        usuario, clave = credenciales()
        if not usuario or not clave:
            raise ErrorNPM(
                "Faltan el usuario y la clave de NPM. Configuralos en NPM Guardian."
            )
        cuerpo = json.dumps({"identity": usuario, "secret": clave}).encode()
        pet = urllib.request.Request(f"{self.base}/api/tokens", data=cuerpo, method="POST")
        pet.add_header("Content-Type", "application/json")
        try:
            with _abrir(pet, timeout=20) as r:
                datos = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            detalle = ""
            try:
                detalle = json.loads(e.read().decode()).get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                detalle = ""
            if e.code in (401, 403):
                raise ErrorNPM(f"NPM rechaza el usuario o la clave ({e.code}). {detalle}")
            raise ErrorNPM(f"NPM devolvio {e.code} al pedir el token. {detalle}")
        except Exception as e:  # noqa: BLE001
            raise ErrorNPM(f"no se pudo hablar con NPM en {self.base}: {type(e).__name__}")

        self._token = datos.get("token")
        if not self._token:
            raise ErrorNPM("NPM no devolvio ningun token")
        # El token trae su caducidad; se renueva antes de que venza para no
        # fallar a mitad de una renovacion.
        self._vence = time.time() + 3600
        return self._token

    def token(self):
        if not self._token or time.time() > self._vence - CADUCIDAD_MARGEN:
            return self._pedir_token()
        return self._token

    # ── llamadas ────────────────────────────────────────────────────────
    def _llamar(self, ruta, metodo="GET", cuerpo=None, tiempo=180, validar_envio=None):
        datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
        pet = urllib.request.Request(f"{self.base}{ruta}", data=datos, method=metodo)
        token = self.token()
        # Pedir el token puede tardar. La autoridad se comprueba después y en
        # el último instante posible, justo antes de enviar una mutación.
        if validar_envio:
            validar_envio()
        pet.add_header("Authorization", f"Bearer {token}")
        if datos:
            pet.add_header("Content-Type", "application/json")
        try:
            with _abrir(pet, timeout=tiempo) as r:
                texto = r.read().decode()
                return json.loads(texto) if texto.strip() else {}
        except urllib.error.HTTPError as e:
            detalle = ""
            try:
                detalle = json.loads(e.read().decode()).get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                detalle = ""
            indeterminado = metodo not in ("GET", "HEAD", "OPTIONS")
            raise ErrorNPM(f"{metodo} {ruta} → HTTP {e.code}. {detalle}",
                           "indeterminate" if indeterminado else "npm_error",
                           resultado_indeterminado=indeterminado)
        except (TimeoutError, urllib.error.URLError) as e:
            motivo = getattr(e, "reason", e)
            if isinstance(motivo, TimeoutError) or "timed out" in str(motivo).lower():
                raise ErrorNPM(f"{metodo} {ruta} supero el tiempo de espera", "timeout",
                               resultado_indeterminado=(metodo not in ("GET", "HEAD", "OPTIONS")))
            indeterminado = metodo not in ("GET", "HEAD", "OPTIONS")
            raise ErrorNPM(f"{metodo} {ruta} → {type(e).__name__}",
                           "indeterminate" if indeterminado else "connection",
                           resultado_indeterminado=indeterminado)
        except Exception as e:  # noqa: BLE001
            indeterminado = metodo not in ("GET", "HEAD", "OPTIONS")
            raise ErrorNPM(f"{metodo} {ruta} → {type(e).__name__}",
                           "indeterminate" if indeterminado else "npm_error",
                           resultado_indeterminado=indeterminado)

    def version(self):
        pet = urllib.request.Request(f"{self.base}/api/")
        with _abrir(pet, timeout=10) as r:
            return json.loads(r.read().decode())

    def certificados(self):
        return self._llamar("/api/nginx/certificates")

    def renovar(self, id_certificado, validar_envio=None):
        """Pide a NPM que renueve ESE certificado.

        Puede tardar: el reto DNS-01 espera a que el registro se propague. Por
        eso el tiempo de espera es largo — cortar antes dejaria la renovacion a
        medias sin saber si funciono.
        """
        espera = int(configuracion.leer()["settings"]["npm_api"].get("timeout_seconds") or 720)
        return self._llamar(f"/api/nginx/certificates/{id_certificado}/renew", "POST",
                            cuerpo={}, tiempo=espera, validar_envio=validar_envio)


def _tabla_nodos():
    """nombre -> IP, de NPMG_NODES. Lo pasa el despliegue."""
    salida = {}
    for trozo in (os.environ.get("NPMG_NODES") or os.environ.get("NPMHA_NODOS") or "").split(","):
        if ":" in trozo:
            n, ip = trozo.strip().split(":", 1)
            if n and ip:
                salida[n] = ip
    return salida


def cliente_del_activo(nodo_activo, puerto=None):
    """El cliente que apunta al NPM del nodo que manda.

    Hace falta la IP, no el nombre: este contenedor corre en red puente, asi
    que 127.0.0.1 es el propio contenedor y el nombre del nodo no tiene por
    que resolver. La tabla la pasa el despliegue en NPMG_NODES."""
    return Cliente(_base_del_activo(nodo_activo, puerto))


def _parece_ip(v):
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v or ""))
