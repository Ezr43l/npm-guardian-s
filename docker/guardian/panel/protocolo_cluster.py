"""Canal autenticado y cifrado entre instancias de NPM Guardian.

Los pares pueden estar en una red HTTP privada, pero por ella viajan bases de
datos y claves TLS. El secreto compartido nunca cruza la red: deriva una clave
de firma para las peticiones y otra AES-GCM para cifrar cuerpos y respuestas.
Las escrituras llevan origen, destino, instante y nonce; el receptor persiste
los nonces consumidos para impedir que una captura válida se pueda repetir.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

import configuracion

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


VERSION_PROTOCOLO = 1
MAX_DESFASE = 5 * 60
VENTANA_REPLAY = 24 * 3600
_CANDADO_REPLAY = threading.Lock()


class ErrorProtocolo(ValueError):
    """La petición no demuestra que venga de un par legítimo e íntegro."""


def disponible():
    return bool(configuracion.TOKEN_CLUSTER)


def _claves():
    token = configuracion.TOKEN_CLUSTER.encode()
    if len(token) < 24:
        raise ErrorProtocolo("falta un NPMG_CLUSTER_TOKEN suficientemente largo")
    material = HKDF(
        algorithm=hashes.SHA256(), length=64,
        salt=b"npm-guardian/cluster/v1",
        info=b"request-signing-and-payload-encryption",
    ).derive(token)
    return material[:32], material[32:]


def _b64(datos):
    return base64.urlsafe_b64encode(datos).decode().rstrip("=")


def _desb64(texto):
    texto = str(texto or "")
    return base64.b64decode(texto + "=" * (-len(texto) % 4), altchars=b"-_",
                            validate=True)


def _canonica_peticion(metodo, ruta, origen, destino, instante, nonce, cuerpo):
    huella = hashlib.sha256(cuerpo).hexdigest()
    return "\n".join((metodo.upper(), ruta, origen, destino, str(instante), nonce,
                       huella)).encode()


def firmar(metodo, ruta, origen, destino, cuerpo=b"", ahora=None):
    """Cabeceras de una petición sin enviar el secreto compartido."""
    _, clave_firma = _claves()
    instante = int(ahora if ahora is not None else time.time())
    nonce = _b64(secrets.token_bytes(18))
    canonica = _canonica_peticion(
        metodo, ruta, str(origen), str(destino), instante, nonce, cuerpo)
    firma = hmac.new(clave_firma, canonica, hashlib.sha256).hexdigest()
    return {
        "X-NPMG-Protocol": str(VERSION_PROTOCOLO),
        "X-NPMG-Source": str(origen),
        "X-NPMG-Target": str(destino),
        "X-NPMG-Timestamp": str(instante),
        "X-NPMG-Nonce": nonce,
        "X-NPMG-Signature": firma,
    }


def verificar(metodo, ruta, cabeceras, destino, cuerpo=b"", origenes=None, ahora=None):
    """Valida firma, reloj, destino y pertenencia al clúster."""
    if str(cabeceras.get("X-NPMG-Protocol") or "") != str(VERSION_PROTOCOLO):
        raise ErrorProtocolo("versión de protocolo interno no válida")
    origen = str(cabeceras.get("X-NPMG-Source") or "")
    recibido_destino = str(cabeceras.get("X-NPMG-Target") or "")
    nonce = str(cabeceras.get("X-NPMG-Nonce") or "")
    firma = str(cabeceras.get("X-NPMG-Signature") or "")
    if not origen or recibido_destino != str(destino):
        raise ErrorProtocolo("origen o destino interno no válido")
    permitidos = {str(v).casefold() for v in (origenes or [])}
    if not permitidos or origen.casefold() not in permitidos:
        raise ErrorProtocolo("el origen no pertenece a los pares configurados")
    if not nonce or len(nonce) > 128:
        raise ErrorProtocolo("nonce interno no válido")
    try:
        instante = int(cabeceras.get("X-NPMG-Timestamp") or "")
    except (TypeError, ValueError) as error:
        raise ErrorProtocolo("instante interno no válido") from error
    actual = int(ahora if ahora is not None else time.time())
    if abs(actual - instante) > MAX_DESFASE:
        raise ErrorProtocolo("la petición interna está fuera de la ventana temporal")
    _, clave_firma = _claves()
    esperada = hmac.new(
        clave_firma,
        _canonica_peticion(metodo, ruta, origen, recibido_destino, instante, nonce, cuerpo),
        hashlib.sha256,
    ).hexdigest()
    if not firma or not hmac.compare_digest(firma, esperada):
        raise ErrorProtocolo("firma interna no válida")
    return {"source": origen, "target": recibido_destino,
            "timestamp": instante, "nonce": nonce}


def _aad(meta):
    return json.dumps(meta, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def cifrar(datos, tipo, origen, destino, ahora=None, contexto=""):
    """Cifra bytes y liga el resultado a su uso, origen y receptor."""
    clave_cifrado, _ = _claves()
    nonce_crudo = secrets.token_bytes(12)
    meta = {
        "v": VERSION_PROTOCOLO,
        "type": str(tipo),
        "source": str(origen),
        "target": str(destino),
        "timestamp": int(ahora if ahora is not None else time.time()),
        "nonce": _b64(nonce_crudo),
        "context": str(contexto or ""),
    }
    cifrado = AESGCM(clave_cifrado).encrypt(nonce_crudo, datos, _aad(meta))
    return json.dumps({**meta, "ciphertext": _b64(cifrado)},
                      separators=(",", ":"), ensure_ascii=False).encode()


def descifrar(cuerpo, tipo, origen, destino, ahora=None, contexto=""):
    """Abre un sobre sólo si fue creado para esta operación y este par."""
    try:
        sobre = json.loads(cuerpo.decode())
        meta = {k: sobre[k] for k in
                ("v", "type", "source", "target", "timestamp", "nonce", "context")}
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise ErrorProtocolo("sobre interno no válido") from error
    if (meta["v"] != VERSION_PROTOCOLO or meta["type"] != str(tipo) or
            str(meta["source"]).casefold() != str(origen).casefold() or
            str(meta["target"]).casefold() != str(destino).casefold() or
            str(meta["context"]) != str(contexto or "")):
        raise ErrorProtocolo("el sobre no corresponde a esta operación")
    actual = int(ahora if ahora is not None else time.time())
    try:
        instante = int(meta["timestamp"])
    except (TypeError, ValueError) as error:
        raise ErrorProtocolo("instante del sobre no válido") from error
    if abs(actual - instante) > MAX_DESFASE:
        raise ErrorProtocolo("el sobre está fuera de la ventana temporal")
    try:
        nonce = _desb64(meta["nonce"])
        cifrado = _desb64(sobre.get("ciphertext"))
        if len(nonce) != 12:
            raise ValueError("nonce")
        clave_cifrado, _ = _claves()
        return AESGCM(clave_cifrado).decrypt(nonce, cifrado, _aad(meta))
    except Exception as error:  # InvalidTag no revela por qué falló
        raise ErrorProtocolo("el sobre interno fue alterado o no es auténtico") from error


def _ruta_replay():
    datos = os.environ.get("NPMG_DATA_DIR", os.environ.get("NPMHA_DATOS", "/datos"))
    return os.path.join(datos, "cluster-replay.json")


def consumir_nonce(nonce, instante=None, ahora=None):
    """Registra un nonce de escritura de forma atómica; False significa replay."""
    actual = int(ahora if ahora is not None else time.time())
    marca = int(instante if instante is not None else actual)
    ruta = _ruta_replay()
    with _CANDADO_REPLAY:
        try:
            with open(ruta, encoding="utf-8") as fichero:
                usados = json.load(fichero)
            if (not isinstance(usados, dict) or
                    not all(isinstance(k, str) and isinstance(v, (int, float))
                            for k, v in usados.items())):
                raise ErrorProtocolo(
                    "el registro anti-replay está corrupto; se bloquean las escrituras")
        except FileNotFoundError:
            usados = {}
        except (OSError, ValueError, TypeError, UnicodeError) as error:
            raise ErrorProtocolo(
                "no se puede validar el registro anti-replay; se bloquean las escrituras") from error
        usados = {k: int(v) for k, v in usados.items()
                  if isinstance(v, (int, float)) and actual - int(v) < VENTANA_REPLAY}
        if nonce in usados:
            return False
        usados[nonce] = marca
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        temporal = ruta + ".tmp"
        descriptor = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as fichero:
                json.dump(usados, fichero, separators=(",", ":"))
                fichero.flush()
                os.fsync(fichero.fileno())
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        os.replace(temporal, ruta)
        carpeta = os.path.dirname(ruta) or "."
        descriptor_carpeta = os.open(carpeta, os.O_RDONLY)
        try:
            os.fsync(descriptor_carpeta)
        finally:
            os.close(descriptor_carpeta)
        return True
