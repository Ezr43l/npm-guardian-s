"""Identidad delegada en NPM, sesiones firmadas y TOTP de NPM Guardian.

NPM comprueba el usuario y la contraseña en cada entrada. Guardian sólo conserva
el identificador estable de esa cuenta, su segundo factor y sus propias sesiones;
la contraseña humana nunca se persiste aquí.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode

import configuracion


COOKIE = "npm_guardian_session"
USUARIO = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{2,63}")
COMUNES = {"123456789012", "administrador", "npm-guardian", "changeme1234", "password1234"}


class ErrorAcceso(ValueError):
    def __init__(self, mensaje, codigo="INVALID_CREDENTIALS", http=401):
        super().__init__(mensaje)
        self.codigo = codigo
        self.http = http


def normalizar_usuario(valor):
    valor = str(valor or "").strip()
    if not USUARIO.fullmatch(valor):
        raise ErrorAcceso(
            "El usuario debe tener entre 3 y 64 caracteres y usar letras, numeros, punto, arroba, guion o guion bajo",
            "INVALID_PROFILE", 422)
    return valor


def validar_clave(clave, usuario=""):
    if len(clave or "") < 12:
        raise ErrorAcceso("La contraseña debe tener al menos 12 caracteres", "WEAK_PASSWORD", 422)
    if len(clave) > 256:
        raise ErrorAcceso("La contraseña no puede superar 256 caracteres", "WEAK_PASSWORD", 422)
    compacta = clave.strip().casefold()
    if compacta in COMUNES or (usuario and compacta == usuario.casefold()):
        raise ErrorAcceso("La contraseña elegida es demasiado predecible", "WEAK_PASSWORD", 422)


def _decodificar(valor):
    return base64.urlsafe_b64decode((valor + "=" * (-len(valor) % 4)).encode("ascii"))


def hash_clave(clave):
    sal = secrets.token_bytes(16)
    n, r, p = 2**15, 8, 1
    derivada = hashlib.scrypt(clave.encode(), salt=sal, n=n, r=r, p=p,
                              dklen=32, maxmem=64 * 1024 * 1024)
    return "$".join(("scrypt", str(n), str(r), str(p),
                     base64.urlsafe_b64encode(sal).decode().rstrip("="),
                     base64.urlsafe_b64encode(derivada).decode().rstrip("=")))


def comprobar_clave(clave, guardada):
    try:
        algoritmo, n, r, p, sal, esperada = guardada.split("$", 5)
        if algoritmo != "scrypt":
            return False
        esperada_b = _decodificar(esperada)
        real = hashlib.scrypt(clave.encode(), salt=_decodificar(sal), n=int(n),
                              r=int(r), p=int(p), dklen=len(esperada_b),
                              maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(real, esperada_b)
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class Identidad:
    usuario: str
    csrf: str
    vence: int
    version_sesion: int
    nombre: str
    npm_token: str = field(default_factory=str)


class Sesiones:
    def __init__(self):
        self.secreto = configuracion.SECRETO_SESION.encode()
        minutos = int(__import__("os").environ.get("NPMG_SESSION_MINUTES", "15"))
        self.duracion = max(5, min(60, minutos)) * 60

    @property
    def disponible(self):
        try:
            return bool(self.secreto) and configuracion.validar_secretos()
        except configuracion.ErrorConfiguracion:
            return False

    def crear(self, cuenta, npm_token=None):
        if not self.disponible:
            raise ErrorAcceso("Falta NPMG_SESSION_SECRET", "AUTH_NOT_CONFIGURED", 503)
        ahora = int(time.time())
        datos = {
            "sub": cuenta["username"], "name": cuenta.get("display_name") or cuenta["username"],
            "sv": int(cuenta.get("session_version") or 0), "csrf": secrets.token_urlsafe(24),
            "iat": ahora, "exp": ahora + self.duracion, "nonce": secrets.token_hex(12),
            "nt": configuracion.cifrar(str(npm_token)) if npm_token else str(),
        }
        cuerpo = base64.urlsafe_b64encode(
            json.dumps(datos, separators=(",", ":"), ensure_ascii=False).encode()).decode().rstrip("=")
        firma = base64.urlsafe_b64encode(
            hmac.new(self.secreto, cuerpo.encode("ascii"), hashlib.sha256).digest()).decode().rstrip("=")
        return f"{cuerpo}.{firma}", Identidad(
            datos["sub"], datos["csrf"], datos["exp"], datos["sv"], datos["name"],
            npm_token)

    def leer(self, token):
        if not token or not self.disponible or "." not in token:
            return None
        cuerpo, firma = token.split(".", 1)
        esperada = base64.urlsafe_b64encode(
            hmac.new(self.secreto, cuerpo.encode("ascii"), hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(firma, esperada):
            return None
        try:
            d = json.loads(_decodificar(cuerpo).decode())
            token_npm = configuracion.descifrar(d.get("nt") or "")
            identidad = Identidad(str(d["sub"]), str(d["csrf"]), int(d["exp"]),
                                  int(d.get("sv") or 0), str(d.get("name") or d["sub"]),
                                  token_npm)
        except (ValueError, KeyError, TypeError, UnicodeError):
            return None
        if identidad.vence <= int(time.time()):
            return None
        cuenta = configuracion.leer().get("account")
        if (not cuenta or cuenta.get("username") != identidad.usuario or
                int(cuenta.get("session_version") or 0) != identidad.version_sesion):
            return None
        return identidad


sesiones = Sesiones()


def _totp(secreto, contador, digitos=6):
    clave = base64.b32decode((secreto + "=" * (-len(secreto) % 8)).encode(), casefold=True)
    resumen = hmac.new(clave, struct.pack(">Q", contador), hashlib.sha1).digest()
    offset = resumen[-1] & 0x0F
    valor = struct.unpack(">I", resumen[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(valor % (10 ** digitos)).zfill(digitos)


def comprobar_totp(secreto, codigo, instante=None, ventana=1):
    codigo = re.sub(r"\s+", "", str(codigo or ""))
    if not re.fullmatch(r"\d{6}", codigo):
        return False
    contador = int(instante if instante is not None else time.time()) // 30
    return any(hmac.compare_digest(codigo, _totp(secreto, contador + desfase))
               for desfase in range(-ventana, ventana + 1))


def generar_secreto_totp():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def uri_totp(usuario, secreto):
    emisor = "NPM Guardian"
    etiqueta = quote(f"{emisor}:{usuario}", safe="")
    return "otpauth://totp/" + etiqueta + "?" + urlencode({
        "secret": secreto, "issuer": emisor, "algorithm": "SHA1", "digits": 6, "period": 30,
    })


def qr_totp(uri):
    """QR local; nunca se manda el secreto a un servicio externo."""
    try:
        import io
        import qrcode
        from qrcode.image.svg import SvgPathFillImage
        imagen = qrcode.make(uri, image_factory=SvgPathFillImage, box_size=7, border=4)
        salida = io.BytesIO()
        imagen.save(salida)
        return "data:image/svg+xml;base64," + base64.b64encode(salida.getvalue()).decode()
    except ImportError:
        return None


def _codigo_recuperacion():
    crudo = base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")
    return "-".join(crudo[i:i + 4] for i in range(0, 16, 4))


def _hash_recuperacion(codigo):
    normal = re.sub(r"[^A-Za-z0-9]", "", str(codigo or "")).upper()
    clave = hashlib.sha256(("recovery:" + configuracion.SECRETO_SESION).encode()).digest()
    return hmac.new(clave, normal.encode(), hashlib.sha256).hexdigest()


def _segundo_factor(cuenta, codigo):
    totp = cuenta.get("totp") or {}
    if not totp.get("enabled"):
        return None
    try:
        secreto = configuracion.descifrar(totp.get("secret"))
    except configuracion.ErrorConfiguracion:
        return False
    if comprobar_totp(secreto, codigo):
        return "totp"
    candidato = _hash_recuperacion(codigo)
    for i, esperado in enumerate(totp.get("recovery_code_hashes") or []):
        if hmac.compare_digest(candidato, esperado):
            return ("recovery", i)
    return False


_fallos = {}


def _limitado(origen):
    ahora = time.time()
    marcas = [t for t in _fallos.get(origen, []) if ahora - t < 300]
    _fallos[origen] = marcas
    return len(marcas) >= 8


def _fallar(origen):
    _fallos.setdefault(origen, []).append(time.time())


def asegurar_intentos(origen):
    if _limitado(origen):
        raise ErrorAcceso("Demasiados intentos; espera cinco minutos", "LOGIN_RATE_LIMIT", 429)


def registrar_fallo(origen):
    _fallar(origen)


def limpiar_fallos(origen):
    _fallos.pop(origen, None)


def _cuenta_npm(perfil_npm):
    """Crea o vincula la única cuenta administradora a una identidad de NPM."""
    usuario = normalizar_usuario(perfil_npm.get("username"))
    npm_id = str(perfil_npm.get("id") or "").strip()
    if not npm_id:
        raise ErrorAcceso("NPM no devolvio un identificador de usuario",
                          "NPM_IDENTITY_INVALID", 502)
    def vincular(datos):
        cuenta = datos.get("account")
        cambiado = False
        if not cuenta:
            cuenta = {
                "id": str(uuid.uuid4()), "username": usuario,
                "display_name": perfil_npm.get("display_name") or usuario,
                "auth_provider": "npm", "npm_user_id": npm_id,
                "session_version": 1, "created_at": int(time.time()),
                "totp": {"enabled": False, "secret": str(), "pending_secret": str(),
                         "recovery_code_hashes": []},
            }
            datos["account"] = cuenta
            cambiado = True
        else:
            guardado_id = str(cuenta.get("npm_user_id") or "")
            mismo_usuario = cuenta.get("username", "").casefold() == usuario.casefold()
            if guardado_id and guardado_id != npm_id:
                raise ErrorAcceso("Esta cuenta de NPM no administra Guardian",
                                  "NPM_ACCOUNT_NOT_ALLOWED", 403)
            if not guardado_id and not mismo_usuario:
                raise ErrorAcceso("Esta cuenta de NPM no administra Guardian",
                                  "NPM_ACCOUNT_NOT_ALLOWED", 403)
            anterior = cuenta.get("username", "")
            if (not guardado_id or cuenta.get("auth_provider") != "npm" or
                    "password_hash" in cuenta or anterior != usuario):
                cuenta["auth_provider"] = "npm"
                cuenta["npm_user_id"] = npm_id
                cuenta["username"] = usuario
                cuenta.pop("password_hash", None)
                if cuenta.get("display_name") in (None, "", anterior):
                    cuenta["display_name"] = perfil_npm.get("display_name") or usuario
                cuenta["session_version"] = int(cuenta.get("session_version") or 0) + 1
                cambiado = True
        return cambiado, None

    guardados, _, cambiado = configuracion.mutar_condicional(vincular)
    return guardados["account"], cambiado


def _validar_y_consumir_factor(codigo):
    """Valida el segundo factor y consume recovery codes atómicamente."""
    def consumir(datos):
        cuenta = datos.get("account") or {}
        verificacion = _segundo_factor(cuenta, codigo)
        if (cuenta.get("totp") or {}).get("enabled") and not codigo:
            raise ErrorAcceso("Introduce el codigo 2FA o uno de recuperacion",
                              "TWO_FACTOR_REQUIRED", 401)
        if verificacion is False:
            raise ErrorAcceso("El segundo factor no es valido",
                              "INVALID_SECOND_FACTOR", 401)
        if isinstance(verificacion, tuple) and verificacion[0] == "recovery":
            cuenta["totp"]["recovery_code_hashes"].pop(verificacion[1])
            return True, verificacion
        return False, verificacion

    guardados, verificacion, consumido = configuracion.mutar_condicional(consumir)
    return guardados.get("account") or {}, verificacion, consumido


def confirmar_identidad_npm(perfil_npm):
    """Reautentica una operación sensible contra la misma cuenta de NPM."""
    cuenta = configuracion.leer().get("account") or {}
    if (str(cuenta.get("npm_user_id") or "") != str(perfil_npm.get("id") or "") or
            cuenta.get("username", "").casefold() !=
            str(perfil_npm.get("username") or "").strip().casefold()):
        raise ErrorAcceso("La cuenta de NPM no coincide con la de Guardian",
                          "NPM_ACCOUNT_NOT_ALLOWED", 403)
    return cuenta


def iniciar_npm(perfil_npm, codigo="", origen="?"):
    if not sesiones.disponible:
        raise ErrorAcceso("Falta NPMG_SESSION_SECRET", "AUTH_NOT_CONFIGURED", 503)
    asegurar_intentos(origen)
    cuenta, cambiado = _cuenta_npm(perfil_npm)

    try:
        cuenta, verificacion, consumido = _validar_y_consumir_factor(codigo)
    except ErrorAcceso:
        _fallar(origen)
        raise
    cambiado = cambiado or consumido
    limpiar_fallos(origen)
    token, identidad = sesiones.crear(cuenta, perfil_npm.get("_token") or "")
    return token, identidad, cambiado


def iniciar_emergencia(usuario, codigo_recuperacion, origen="?"):
    """Permite entrar sin NPM usando un código de recuperación de un solo uso."""
    if not sesiones.disponible:
        raise ErrorAcceso("Falta NPMG_SESSION_SECRET", "AUTH_NOT_CONFIGURED", 503)
    asegurar_intentos(origen)
    def consumir(datos):
        cuenta = datos.get("account") or {}
        totp = cuenta.get("totp") or {}
        if (not cuenta or cuenta.get("username", "").casefold() !=
                str(usuario or "").strip().casefold()):
            raise ErrorAcceso("Usuario o codigo de recuperacion no validos")
        if not totp.get("enabled") or not totp.get("recovery_code_hashes"):
            raise ErrorAcceso(
                "El acceso de emergencia requiere 2FA y codigos de recuperacion",
                "EMERGENCY_ACCESS_NOT_CONFIGURED", 409)
        verificacion = _segundo_factor(cuenta, codigo_recuperacion)
        if not isinstance(verificacion, tuple) or verificacion[0] != "recovery":
            raise ErrorAcceso("Usuario o codigo de recuperacion no validos")
        cuenta["totp"]["recovery_code_hashes"].pop(verificacion[1])
        return True, None
    try:
        datos, _, _ = configuracion.mutar_condicional(consumir)
    except ErrorAcceso:
        _fallar(origen)
        raise
    cuenta = datos["account"]
    limpiar_fallos(origen)
    token, identidad = sesiones.crear(cuenta)
    return token, identidad, True


def perfil(cuenta=None):
    cuenta = cuenta or configuracion.leer().get("account")
    if not cuenta:
        return None
    totp = cuenta.get("totp") or {}
    return {
        "username": cuenta.get("username"),
        "display_name": cuenta.get("display_name"),
        "two_factor_enabled": bool(totp.get("enabled")),
        "two_factor_pending": bool(totp.get("pending_secret")),
        "recovery_codes_remaining": len(totp.get("recovery_code_hashes") or []),
        "auth_provider": cuenta.get("auth_provider") or "legacy-local",
        "password_managed_by": "npm" if cuenta.get("auth_provider") == "npm" else "guardian",
        "emergency_access_enabled": bool(totp.get("enabled") and
                                         totp.get("recovery_code_hashes")),
    }


def sesion_publica(identidad):
    p = perfil()
    return {**p, "csrf_token": identidad.csrf, "expires_at": identidad.vence}


def _confirmar_segundo_factor(cuenta, codigo=None):
    if (cuenta.get("totp") or {}).get("enabled"):
        if not codigo:
            raise ErrorAcceso("Esta operacion requiere el segundo factor", "TWO_FACTOR_REQUIRED", 401)
        verificacion = _segundo_factor(cuenta, codigo)
        if not verificacion:
            raise ErrorAcceso("El segundo factor no es valido", "INVALID_SECOND_FACTOR", 401)
        if isinstance(verificacion, tuple):
            cuenta["totp"]["recovery_code_hashes"].pop(verificacion[1])


def actualizar_perfil(nombre):
    nombre = " ".join(str(nombre or "").split())
    if not nombre or len(nombre) > 120:
        raise ErrorAcceso("El nombre debe tener entre 1 y 120 caracteres", "INVALID_PROFILE", 422)
    def mutar(datos):
        datos["account"]["display_name"] = nombre
    return perfil(configuracion.actualizar(mutar)["account"])


def preparar_2fa():
    secreto = generar_secreto_totp()
    cifrado = configuracion.cifrar(secreto)
    def preparar(datos):
        cuenta = datos.get("account") or {}
        if (cuenta.get("totp") or {}).get("enabled"):
            raise ErrorAcceso("2FA ya esta activo", "TWO_FACTOR_ALREADY_ENABLED", 409)
        cuenta.setdefault("totp", {})["pending_secret"] = cifrado
        return True, cuenta["username"]
    _, usuario, _ = configuracion.mutar_condicional(preparar)
    uri = uri_totp(usuario, secreto)
    return {"secret": secreto, "otpauth_uri": uri, "qr_data_url": qr_totp(uri),
            "issuer": "NPM Guardian"}


def cancelar_2fa():
    def cancelar(datos):
        pendiente = datos["account"].setdefault("totp", {}).get("pending_secret")
        datos["account"]["totp"]["pending_secret"] = str()
        return bool(pendiente), None
    configuracion.mutar_condicional(cancelar)


def activar_2fa(codigo):
    codigos = [_codigo_recuperacion() for _ in range(10)]
    hashes = [_hash_recuperacion(c) for c in codigos]
    def activar(datos):
        cuenta = datos.get("account") or {}
        pendiente = (cuenta.get("totp") or {}).get("pending_secret")
        if not pendiente:
            raise ErrorAcceso(
                "Inicia primero la configuracion 2FA", "TWO_FACTOR_SETUP_MISSING", 409)
        secreto = configuracion.descifrar(pendiente)
        if not comprobar_totp(secreto, codigo):
            raise ErrorAcceso(
                "El codigo no coincide; comprueba la hora del dispositivo",
                "INVALID_SECOND_FACTOR", 401)
        cuenta["totp"] = {
            "enabled": True, "secret": pendiente, "pending_secret": str(),
            "recovery_code_hashes": hashes,
        }
        cuenta["session_version"] = int(cuenta.get("session_version") or 0) + 1
        return True, None
    guardada, _, _ = configuracion.mutar_condicional(activar)
    guardada = guardada["account"]
    return guardada, codigos


def desactivar_2fa(codigo):
    def desactivar(datos):
        cuenta = datos.get("account") or {}
        if not (cuenta.get("totp") or {}).get("enabled"):
            raise ErrorAcceso("2FA no esta activo", "TWO_FACTOR_NOT_ENABLED", 409)
        _confirmar_segundo_factor(cuenta, codigo)
        cuenta["totp"] = {"enabled": False, "secret": str(), "pending_secret": str(),
                          "recovery_code_hashes": []}
        cuenta["session_version"] = int(cuenta.get("session_version") or 0) + 1
        return True, None
    guardada, _, _ = configuracion.mutar_condicional(desactivar)
    return guardada["account"]


def regenerar_recuperacion(codigo):
    codigos = [_codigo_recuperacion() for _ in range(10)]
    hashes = [_hash_recuperacion(c) for c in codigos]
    def regenerar(datos):
        cuenta = datos.get("account") or {}
        _confirmar_segundo_factor(cuenta, codigo)
        cuenta["totp"]["recovery_code_hashes"] = hashes
        return True, None
    configuracion.mutar_condicional(regenerar)
    return codigos
