"""Réplica coherente, verificable y recuperable del estado completo de NPM.

El emisor crea un snapshot SQLite con la API de backup, copia el estado de
Nginx/Certbot, genera un manifiesto SHA-256 y lo empaqueta. El receptor valida
todo antes de parar NPM y conserva los caminos anteriores para poder deshacer
la sustitución si el servicio no vuelve sano.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import time
import uuid

import dockerd


RUTA_DATOS = os.environ.get("NPMG_NPM_DATA", os.environ.get("NPMHA_NPM_DATOS", "/npm"))
RUTA_LE = os.environ.get("NPMG_NPM_LETSENCRYPT", os.environ.get(
    "NPMHA_NPM_LETSENCRYPT", "/npm-letsencrypt"))
CONTENEDOR = (os.environ.get("NPMG_NPM_CONTAINER") or
              os.environ.get("NPMHA_NPM_CONTENEDOR") or "NPM").split(",")[0].strip()

DE_DATOS = ["database.sqlite", "keys.json", "nginx", "custom_ssl", "access"]
DE_LE = ["live", "archive", "renewal", "renewal-hooks", "accounts", "credentials"]
PARTES = {"data": DE_DATOS, "letsencrypt": DE_LE}

MAX_TAMANO = 64 * 1024 * 1024
MAX_DESEMPAQUETADO = 512 * 1024 * 1024
MAX_MIEMBROS = 20000
MAX_MANIFIESTO = 4 * 1024 * 1024

RUTA_RESPALDOS = os.environ.get("NPMG_DATA_DIR", os.environ.get("NPMHA_DATOS", "/datos"))
RUTA_JOURNAL = os.path.join(RUTA_RESPALDOS, "replica-transaction.json")
PREFIJO_RESPALDO = "antes-de-replicar-"
RESPALDOS_QUE_SE_GUARDAN = 3


class ErrorReplica(Exception):
    """El estado no puede aplicarse sin arriesgar el nodo."""


class RolCambiado(ErrorReplica):
    """El receptor pasivo fue promovido mientras aplicaba un paquete válido."""


class ErrorRollback(ErrorReplica):
    """El swap empezó y su estado original no pudo restaurarse con certeza."""


class SwapRevertido(ErrorReplica):
    """El swap falló, pero sus renames ya se revirtieron de forma durable."""


def _sospechoso(nombre):
    n = nombre.lower()
    return "-copia-" in n or n.endswith(".bak") or ".bak-" in n or n.endswith("~")


def _ignorar(_base, nombres):
    return {nombre for nombre in nombres if _sospechoso(nombre)}


def _copiar(origen, destino):
    if os.path.islink(origen):
        os.symlink(os.readlink(origen), destino)
    elif os.path.isdir(origen):
        shutil.copytree(origen, destino, symlinks=True, ignore=_ignorar)
    else:
        shutil.copy2(origen, destino)


def _snapshot_sqlite(origen, destino):
    if not os.path.isfile(origen):
        raise ErrorReplica(f"no existe la base de datos de NPM: {origen}")
    fuente = sqlite3.connect(f"file:{origen}?mode=ro", uri=True, timeout=30)
    salida = sqlite3.connect(destino)
    try:
        fuente.backup(salida)
        resultado = salida.execute("pragma quick_check").fetchone()
        if not resultado or resultado[0] != "ok":
            raise ErrorReplica("el snapshot SQLite no supera PRAGMA quick_check")
    except sqlite3.Error as error:
        raise ErrorReplica(f"no se pudo crear un snapshot coherente de SQLite: {error}") from error
    finally:
        salida.close()
        fuente.close()
    os.chmod(destino, 0o600)


def _sha256(ruta):
    huella = hashlib.sha256()
    with open(ruta, "rb") as fichero:
        while True:
            bloque = fichero.read(1024 * 1024)
            if not bloque:
                break
            huella.update(bloque)
    return huella.hexdigest()


def _registro(ruta, raiz):
    relativo = os.path.relpath(ruta, raiz).replace(os.sep, "/")
    if os.path.islink(ruta):
        return relativo, {"type": "symlink", "target": os.readlink(ruta)}
    return relativo, {"type": "file", "size": os.path.getsize(ruta),
                      "sha256": _sha256(ruta)}


def _inventariar_directorio(raiz):
    ficheros = {}
    for base, carpetas, nombres in os.walk(raiz, followlinks=False):
        carpetas[:] = [nombre for nombre in carpetas if not _sospechoso(nombre)]
        nombres = [nombre for nombre in nombres if not _sospechoso(nombre)]
        for nombre in list(carpetas):
            ruta = os.path.join(base, nombre)
            if os.path.islink(ruta):
                clave, valor = _registro(ruta, raiz)
                ficheros[clave] = valor
                carpetas.remove(nombre)
        for nombre in nombres:
            ruta = os.path.join(base, nombre)
            clave, valor = _registro(ruta, raiz)
            ficheros[clave] = valor
    return ficheros


def inventario_artefactos():
    """Huella del estado en disco que debe viajar junto a SQLite."""
    registros = {}
    ultima = 0.0
    for base, partes, prefijo in ((RUTA_DATOS, DE_DATOS, "data"),
                                  (RUTA_LE, DE_LE, "letsencrypt")):
        for parte in partes:
            if prefijo == "data" and parte == "database.sqlite":
                continue
            raiz = os.path.join(base, parte)
            if not os.path.lexists(raiz):
                continue
            if os.path.isdir(raiz) and not os.path.islink(raiz):
                for ruta, valor in _inventariar_directorio(raiz).items():
                    clave = f"{prefijo}/{parte}/{ruta}"
                    registros[clave] = valor
                    try:
                        ultima = max(ultima, os.lstat(os.path.join(raiz, ruta)).st_mtime)
                    except OSError:
                        pass
            else:
                _, valor = _registro(raiz, os.path.dirname(raiz))
                registros[f"{prefijo}/{parte}"] = valor
                try:
                    ultima = max(ultima, os.lstat(raiz).st_mtime)
                except OSError:
                    pass
    canonico = json.dumps(registros, sort_keys=True, separators=(",", ":")).encode()
    return {"huella": hashlib.sha256(canonico).hexdigest()[:16],
            "ficheros": len(registros),
            "modificado": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ultima))
            if ultima else ""}


def _crear_staging_una_vez():
    raiz = tempfile.mkdtemp(
        prefix="npm-guardian-package-", dir=tempfile.gettempdir())
    try:
        for prefijo in PARTES:
            os.makedirs(os.path.join(raiz, prefijo), exist_ok=True)
        _snapshot_sqlite(
            os.path.join(RUTA_DATOS, "database.sqlite"),
            os.path.join(raiz, "data", "database.sqlite"))
        for base, partes, prefijo in ((RUTA_DATOS, DE_DATOS, "data"),
                                      (RUTA_LE, DE_LE, "letsencrypt")):
            for parte in partes:
                if prefijo == "data" and parte == "database.sqlite":
                    continue
                origen = os.path.join(base, parte)
                if os.path.lexists(origen):
                    _copiar(origen, os.path.join(raiz, prefijo, parte))
        manifiesto = {"version": 1, "parts": PARTES,
                      "files": _inventariar_directorio(raiz)}
        ruta_manifiesto = os.path.join(raiz, "manifest.json")
        with open(ruta_manifiesto, "w", encoding="utf-8") as fichero:
            json.dump(manifiesto, fichero, sort_keys=True, separators=(",", ":"))
        os.chmod(ruta_manifiesto, 0o600)
        return raiz
    except Exception:
        shutil.rmtree(raiz, ignore_errors=True)
        raise


def _crear_staging():
    """Obtiene DB y filesystem del mismo intervalo estable, con reintentos."""
    ultimo_error = None
    for _intento in range(3):
        artefactos_antes = inventario_artefactos()["huella"]
        raiz = _crear_staging_una_vez()
        descriptor, segundo = tempfile.mkstemp(
            prefix="npm-guardian-db-check-", suffix=".sqlite",
            dir=tempfile.gettempdir())
        os.close(descriptor)
        os.unlink(segundo)  # sqlite crea el fichero con su propio formato
        try:
            artefactos_despues = inventario_artefactos()["huella"]
            _snapshot_sqlite(os.path.join(RUTA_DATOS, "database.sqlite"), segundo)
            db_paquete = os.path.join(raiz, "data", "database.sqlite")
            if (artefactos_antes == artefactos_despues and
                    _sha256(db_paquete) == _sha256(segundo)):
                return raiz
            ultimo_error = "NPM cambió mientras se preparaba el snapshot"
        finally:
            try:
                os.unlink(segundo)
            except OSError:
                pass
        shutil.rmtree(raiz, ignore_errors=True)
    raise ErrorReplica((ultimo_error or "snapshot inestable") +
                       "; se aborta sin enviar una mezcla de estados")


def empaquetar():
    """Crea un snapshot autocontenido sin leer SQLite como fichero vivo."""
    raiz = _crear_staging()
    try:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(os.path.join(raiz, "manifest.json"), arcname="manifest.json")
            for prefijo in PARTES:
                tar.add(os.path.join(raiz, prefijo), arcname=prefijo)
        datos = buf.getvalue()
    finally:
        shutil.rmtree(raiz, ignore_errors=True)
    if len(datos) > MAX_TAMANO:
        raise ErrorReplica(
            f"el paquete son {len(datos) // (1024 * 1024)} MB, más de los "
            f"{MAX_TAMANO // (1024 * 1024)} MB permitidos")
    return datos


def respaldos():
    try:
        nombres = [n for n in os.listdir(RUTA_RESPALDOS)
                   if n.startswith(PREFIJO_RESPALDO) and n.endswith(".tar.gz")]
    except OSError:
        return []
    return [os.path.join(RUTA_RESPALDOS, n) for n in sorted(nombres, reverse=True)]


def _respaldos_a_borrar():
    return respaldos()[RESPALDOS_QUE_SE_GUARDAN:]


def _nombre_seguro(nombre):
    normal = nombre.replace("\\", "/")
    while normal.startswith("./"):
        normal = normal[2:]
    if not normal or normal.startswith("/") or ".." in normal.split("/"):
        raise ErrorReplica(f"el paquete trae una ruta que se sale: «{nombre}»")
    if not (normal == "manifest.json" or normal == "data" or
            normal.startswith("data/") or normal == "letsencrypt" or
            normal.startswith("letsencrypt/")):
        raise ErrorReplica(f"el paquete trae algo que no es estado de NPM: «{nombre}»")
    return normal


def _validar_paquete(tar):
    miembros = tar.getmembers()
    if len(miembros) > MAX_MIEMBROS:
        raise ErrorReplica("el paquete contiene demasiados elementos")
    expandido = 0
    manifiestos = []
    hay_bd = False
    for miembro in miembros:
        nombre = _nombre_seguro(miembro.name)
        if miembro.isreg():
            expandido += miembro.size
        elif not (miembro.isdir() or miembro.issym()):
            raise ErrorReplica(f"tipo de elemento no permitido en «{miembro.name}»")
        if expandido > MAX_DESEMPAQUETADO:
            raise ErrorReplica("el paquete expandido supera el límite de seguridad")
        if nombre == "manifest.json":
            if not miembro.isreg() or miembro.size > MAX_MANIFIESTO:
                raise ErrorReplica("el manifiesto no es válido")
            manifiestos.append(miembro)
        if nombre == "data/database.sqlite" and miembro.isreg():
            hay_bd = True
        if miembro.issym():
            destino = miembro.linkname.replace("\\", "/")
            if destino.startswith("/"):
                raise ErrorReplica(f"«{miembro.name}» enlaza fuera del paquete")
            resuelto = os.path.normpath(os.path.join(os.path.dirname(nombre), destino))
            if (resuelto.startswith("..") or os.path.isabs(resuelto) or
                    not (resuelto.startswith("data/") or
                         resuelto.startswith("letsencrypt/"))):
                raise ErrorReplica(f"«{miembro.name}» enlaza fuera del paquete")
    if len(manifiestos) != 1:
        raise ErrorReplica("el paquete debe traer un único manifiesto")
    if not hay_bd:
        raise ErrorReplica("el paquete no trae una base SQLite válida")
    return miembros


def _validar_extraido(raiz):
    try:
        with open(os.path.join(raiz, "manifest.json"), encoding="utf-8") as fichero:
            manifiesto = json.load(fichero)
    except (OSError, ValueError) as error:
        raise ErrorReplica("no se puede leer el manifiesto del paquete") from error
    if manifiesto.get("version") != 1 or manifiesto.get("parts") != PARTES:
        raise ErrorReplica("el manifiesto usa un contrato de réplica incompatible")
    esperados = manifiesto.get("files")
    if not isinstance(esperados, dict):
        raise ErrorReplica("el manifiesto no contiene inventario de ficheros")
    actuales = _inventariar_directorio(raiz)
    actuales.pop("manifest.json", None)
    if set(actuales) != set(esperados):
        raise ErrorReplica("el contenido no coincide con el manifiesto")
    for nombre, esperado in esperados.items():
        if actuales.get(nombre) != esperado:
            raise ErrorReplica(f"la huella no coincide en «{nombre}»")
    db = os.path.join(raiz, "data", "database.sqlite")
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
        resultado = con.execute("pragma quick_check").fetchone()
        con.close()
    except sqlite3.Error as error:
        raise ErrorReplica(f"la base recibida no se puede abrir: {error}") from error
    if not resultado or resultado[0] != "ok":
        raise ErrorReplica("la base recibida no supera PRAGMA quick_check")


def _extraer_validado(datos):
    raiz = tempfile.mkdtemp(
        prefix="npm-guardian-receive-", dir=tempfile.gettempdir())
    try:
        with tarfile.open(fileobj=io.BytesIO(datos), mode="r:gz") as tar:
            miembros = _validar_paquete(tar)
            tar.extractall(path=raiz, members=miembros, filter="data")
        _validar_extraido(raiz)
        return raiz
    except Exception:
        shutil.rmtree(raiz, ignore_errors=True)
        raise


def _guardar_respaldo(datos):
    os.makedirs(RUTA_RESPALDOS, mode=0o700, exist_ok=True)
    sello = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time_ns() % 1000000):06d}"
    ruta = os.path.join(RUTA_RESPALDOS, f"{PREFIJO_RESPALDO}{sello}.tar.gz")
    descriptor = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as fichero:
            fichero.write(datos)
            fichero.flush()
            os.fsync(fichero.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(ruta)
        except OSError:
            pass
        raise
    _fsync_directorio(RUTA_RESPALDOS)
    return ruta


def _quitar(ruta):
    if os.path.islink(ruta) or os.path.isfile(ruta):
        os.unlink(ruta)
    elif os.path.isdir(ruta):
        shutil.rmtree(ruta)


def _fsync_directorio(ruta):
    descriptor = os.open(ruta, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_arbol(ruta):
    """Hace durable el staging antes de publicar sus nombres con rename."""
    if os.path.islink(ruta):
        _fsync_directorio(os.path.dirname(ruta))
        return
    if os.path.isfile(ruta):
        descriptor = os.open(ruta, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directorio(os.path.dirname(ruta))
        return
    for base, carpetas, ficheros in os.walk(ruta, topdown=False,
                                            followlinks=False):
        for nombre in ficheros:
            fichero = os.path.join(base, nombre)
            if os.path.islink(fichero):
                continue
            descriptor = os.open(fichero, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for nombre in carpetas:
            carpeta = os.path.join(base, nombre)
            if not os.path.islink(carpeta):
                _fsync_directorio(carpeta)
        _fsync_directorio(base)


def _escribir_journal(estado, cambios, was_running=True,
                      keep_new_on_recovery=False):
    os.makedirs(RUTA_RESPALDOS, mode=0o700, exist_ok=True)
    documento = {
        "version": 1,
        "state": estado,
        "was_running": bool(was_running),
        "keep_new_on_recovery": bool(keep_new_on_recovery),
        "changes": [{clave: cambio.get(clave) for clave in
                     ("label", "dest", "new", "old", "had_old")}
                    for cambio in cambios],
    }
    contenido = (json.dumps(documento, ensure_ascii=False, sort_keys=True) + "\n").encode()
    descriptor, temporal = tempfile.mkstemp(
        prefix=".replica-transaction-", suffix=".json", dir=RUTA_RESPALDOS)
    try:
        with os.fdopen(descriptor, "wb") as fichero:
            fichero.write(contenido)
            fichero.flush()
            os.fsync(fichero.fileno())
        os.chmod(temporal, 0o600)
        os.replace(temporal, RUTA_JOURNAL)
        _fsync_directorio(RUTA_RESPALDOS)
    finally:
        try:
            if os.path.exists(temporal):
                os.unlink(temporal)
        except OSError:
            pass


def _borrar_journal():
    try:
        os.unlink(RUTA_JOURNAL)
        _fsync_directorio(RUTA_RESPALDOS)
    except FileNotFoundError:
        pass


def _validar_cambios_journal(documento):
    if isinstance(documento, dict) and "keep_new_on_recovery" not in documento:
        # Compatibilidad con un journal escrito por una versión de desarrollo
        # anterior: su comportamiento siempre era restaurar lo antiguo.
        documento["keep_new_on_recovery"] = False
    if (not isinstance(documento, dict) or documento.get("version") != 1 or
            documento.get("state") not in ("prepared", "swapping", "swapped", "committed") or
            type(documento.get("was_running")) is not bool or
            type(documento.get("keep_new_on_recovery")) is not bool or
            not isinstance(documento.get("changes"), list)):
        raise ErrorReplica("el journal de réplica no es válido")
    cambios = documento["changes"]
    bases = (os.path.abspath(RUTA_DATOS), os.path.abspath(RUTA_LE))
    for cambio in cambios:
        if (not isinstance(cambio, dict) or
                set(cambio) != {"label", "dest", "new", "old", "had_old"} or
                type(cambio.get("had_old")) is not bool):
            raise ErrorReplica("el journal contiene un cambio no válido")
        for clave in ("dest", "new", "old"):
            ruta = cambio.get(clave)
            if ruta is None and clave == "new":
                continue
            absoluta = os.path.abspath(str(ruta or ""))
            if not any(os.path.commonpath((absoluta, base)) == base for base in bases):
                raise ErrorReplica("el journal contiene una ruta fuera de NPM")
    return cambios


def _recuperar_cambios(cambios):
    errores = []
    directorios = set()
    for cambio in reversed(cambios):
        try:
            existe_old = os.path.lexists(cambio["old"])
            existe_new = bool(cambio.get("new") and os.path.lexists(cambio["new"]))
            existe_dest = os.path.lexists(cambio["dest"])
            if cambio["had_old"]:
                # Si .old existe, este paso llegó a mover el original y debe
                # deshacerse. Si no, el paso no había empezado.
                if existe_old:
                    if existe_dest:
                        _quitar(cambio["dest"])
                    os.replace(cambio["old"], cambio["dest"])
            elif not existe_new and existe_dest:
                # El destino no existía antes y el staging ya se movió allí.
                _quitar(cambio["dest"])
            if cambio.get("new") and os.path.lexists(cambio["new"]):
                _quitar(cambio["new"])
            directorios.add(os.path.dirname(cambio["dest"]))
        except Exception as error:  # noqa: BLE001
            errores.append(f"{cambio.get('label')}: {type(error).__name__}")
    for directorio in sorted(directorios):
        try:
            _fsync_directorio(directorio)
        except OSError as error:
            errores.append(
                f"fsync {directorio}: {type(error).__name__}")
    if errores:
        raise ErrorReplica("no se pudo recuperar la transacción: " + ", ".join(errores))


def _completar_cambios(cambios):
    """Termina hacia delante un swap interrumpido tras promover al receptor."""
    errores = []
    directorios = set()
    for cambio in cambios:
        try:
            destino = cambio["dest"]
            nuevo = cambio.get("new")
            anterior = cambio["old"]
            existe_destino = os.path.lexists(destino)
            existe_nuevo = bool(nuevo and os.path.lexists(nuevo))
            existe_anterior = os.path.lexists(anterior)
            if nuevo is not None:
                if existe_nuevo:
                    if cambio["had_old"] and not existe_anterior:
                        if not existe_destino:
                            raise ErrorReplica("falta el estado original")
                        os.replace(destino, anterior)
                    elif not cambio["had_old"] and existe_destino:
                        raise ErrorReplica("apareció un destino que no existía")
                    elif cambio["had_old"] and existe_anterior and existe_destino:
                        raise ErrorReplica("hay dos destinos durante el forward recovery")
                    os.replace(nuevo, destino)
                elif not existe_destino:
                    raise ErrorReplica("faltan tanto staging como destino")
            elif cambio["had_old"]:
                # WAL/SHM ausentes en el paquete: publicarlos significa
                # retirarlos, conservando el anterior para un posible rollback.
                if not existe_anterior:
                    if not existe_destino:
                        raise ErrorReplica("falta el fichero que debía retirarse")
                    os.replace(destino, anterior)
                elif existe_destino:
                    raise ErrorReplica("el fichero retirado existe en dos rutas")
            elif existe_destino:
                raise ErrorReplica("apareció un fichero excluido del paquete")
            directorios.add(os.path.dirname(destino))
        except Exception as error:  # noqa: BLE001
            errores.append(f"{cambio.get('label')}: {type(error).__name__}")
    for directorio in sorted(directorios):
        try:
            _fsync_directorio(directorio)
        except OSError as error:
            errores.append(f"fsync {directorio}: {type(error).__name__}")
    if errores:
        raise ErrorReplica(
            "no se pudo completar la transacción promovida: " + ", ".join(errores))


def _estado_contenedor_confirmado():
    """Consulta Docker sin convertir una respuesta perdida en una suposición."""
    try:
        estado = dockerd.estado(CONTENEDOR)
    except dockerd.ErrorDocker as error:
        raise ErrorReplica(
            "no se puede confirmar el estado real de NPM; se conserva el journal") \
            from error
    if not estado.get("existe"):
        raise ErrorReplica(f"ya no existe el contenedor «{CONTENEDOR}»")
    return estado


def _asegurar_contenedor(corriendo):
    """Converge y vuelve a consultar tras una orden Docker potencialmente ambigua."""
    estado = _estado_contenedor_confirmado()
    if bool(estado.get("corriendo")) == bool(corriendo):
        return estado
    error_orden = None
    try:
        if corriendo:
            dockerd.arrancar(CONTENEDOR)
        else:
            dockerd.parar(CONTENEDOR)
    except dockerd.ErrorDocker as error:
        # La respuesta puede haberse perdido después de que Docker aplicara la
        # orden. Sólo el GET posterior decide si se alcanzó el estado buscado.
        error_orden = error
    try:
        final = _estado_contenedor_confirmado()
    except ErrorReplica as error_estado:
        detalle = f" ({type(error_orden).__name__})" if error_orden else ""
        raise ErrorReplica(
            "Docker no permite confirmar la " +
            ("puesta en marcha" if corriendo else "parada") + detalle +
            "; se conserva el journal") from error_estado
    if bool(final.get("corriendo")) != bool(corriendo):
        detalle = f": {error_orden}" if error_orden else ""
        raise ErrorReplica(
            ("NPM no quedó en marcha" if corriendo else "NPM no quedó detenido") +
            detalle + "; se conserva el journal")
    return final


def recuperar_transaccion():
    """Completa limpieza o restaura el estado anterior tras un corte abrupto."""
    if not os.path.exists(RUTA_JOURNAL):
        return {"ok": True, "recovered": False}
    try:
        with open(RUTA_JOURNAL, "r", encoding="utf-8") as fichero:
            documento = json.load(fichero)
    except (OSError, ValueError, UnicodeError) as error:
        raise ErrorReplica("no se puede leer el journal de réplica; se bloquea el arranque") from error
    cambios = _validar_cambios_journal(documento)
    if documento["state"] == "committed":
        _limpiar_transaccion(cambios)
        _borrar_journal()
        return {"ok": True, "recovered": True, "action": "commit-cleaned"}

    if (documento["state"] in ("swapping", "swapped") and
            documento.get("keep_new_on_recovery")):
        # El receptor llegó a convertirse en activo durante el swap. La decisión
        # durable es terminar primero el paquete validado, no resucitar a ciegas
        # el estado anterior sobre el portador de la VIP.
        _asegurar_contenedor(False)
        try:
            _completar_cambios(cambios)
        except Exception:  # noqa: BLE001
            # El forward puede haber publicado sólo una parte del staging. La
            # decisión contraria debe quedar durable antes de tocar esos paths:
            # si Guardian vuelve a caer, el siguiente arranque continuará el
            # rollback y nunca reintentará el forward sobre un estado parcial.
            _escribir_journal(
                "swapped", cambios, documento["was_running"],
                keep_new_on_recovery=False)
            _asegurar_contenedor(False)
            try:
                _recuperar_cambios(cambios)
                _asegurar_contenedor(documento["was_running"])
                if documento["was_running"] and not _esperar_salud():
                    raise ErrorReplica(
                        "el estado anterior no recuperó salud después de "
                        "fallar el forward; se conserva el journal")
            except Exception as error_rollback:  # noqa: BLE001
                raise ErrorReplica(
                    "falló la recuperación hacia delante y tampoco se pudo "
                    "confirmar el estado anterior; se conserva el journal") \
                    from error_rollback
            _borrar_journal()
            return {"ok": True, "recovered": True,
                    "action": "promoted-swap-rolled-back"}
        _escribir_journal(
            "swapped", cambios, documento["was_running"],
            keep_new_on_recovery=True)
        _asegurar_contenedor(documento["was_running"])
        sano = (not documento["was_running"] or _esperar_salud())
        if sano:
            _escribir_journal(
                "committed", cambios, documento["was_running"],
                keep_new_on_recovery=True)
            _limpiar_transaccion(cambios)
            _borrar_journal()
            return {"ok": True, "recovered": True,
                    "action": "promoted-swap-completed"}

        # El estado nuevo no es servible. Se persiste primero la decisión de
        # rollback para que otro corte nunca vuelva a intentar comprometerlo.
        _escribir_journal(
            "swapped", cambios, documento["was_running"],
            keep_new_on_recovery=False)
        _asegurar_contenedor(False)
        _recuperar_cambios(cambios)
        _asegurar_contenedor(documento["was_running"])
        if documento["was_running"] and not _esperar_salud():
            raise ErrorReplica(
                "ni el estado promovido ni el anterior recuperaron salud; "
                "se conserva el journal")
        _borrar_journal()
        return {"ok": True, "recovered": True,
                "action": "promoted-swap-rolled-back"}

    if documento["state"] == "prepared":
        # Todavía no se publicó ningún staging. Puede que el corte ocurriera
        # justo después de parar NPM, así que se limpia y se recupera su estado
        # de ejecución sin tocar los destinos originales.
        _limpiar_transaccion(cambios)
        _asegurar_contenedor(documento["was_running"])
        if documento["was_running"]:
            if not _esperar_salud():
                raise ErrorReplica("NPM no recuperó salud tras una preparación interrumpida")
        # Si arranque o salud fallan, el journal permanece y el siguiente
        # arranque repite esta recuperación idempotente.
        _borrar_journal()
        return {"ok": True, "recovered": True, "action": "prepared-cleaned"}

    _asegurar_contenedor(False)
    _recuperar_cambios(cambios)
    _asegurar_contenedor(documento["was_running"])
    if documento["was_running"] and not _esperar_salud():
        raise ErrorReplica(
            "se restauró la transacción, pero NPM no recuperó salud; "
            "se conserva el journal")
    _borrar_journal()
    return {"ok": True, "recovered": True, "action": "rolled-back"}


def _preparar_cambios(raiz):
    identificador = uuid.uuid4().hex
    cambios = []
    for prefijo, base in (("data", RUTA_DATOS), ("letsencrypt", RUTA_LE)):
        os.makedirs(base, exist_ok=True)
        for parte in PARTES[prefijo]:
            origen = os.path.join(raiz, prefijo, parte)
            destino = os.path.join(base, parte)
            nuevo = os.path.join(base, f".npmg-new-{identificador}-{parte}")
            anterior = os.path.join(base, f".npmg-old-{identificador}-{parte}")
            if os.path.lexists(nuevo) or os.path.lexists(anterior):
                raise ErrorReplica("hay restos de una transacción de réplica")
            if os.path.lexists(origen):
                _copiar(origen, nuevo)
                _fsync_arbol(nuevo)
            else:
                nuevo = None
            cambios.append({"label": f"{prefijo}/{parte}", "dest": destino,
                             "new": nuevo, "old": anterior,
                             "had_old": os.path.lexists(destino)})
    for sufijo in ("-wal", "-shm"):
        destino = os.path.join(RUTA_DATOS, "database.sqlite" + sufijo)
        cambios.append({"label": "data/database.sqlite" + sufijo,
                         "dest": destino, "new": None,
                         "old": os.path.join(
                             RUTA_DATOS, f".npmg-old-{identificador}-database.sqlite{sufijo}"),
                         "had_old": os.path.lexists(destino)})
    return cambios


def _restaurar(cambios):
    errores = []
    directorios = set()
    for cambio in reversed(cambios):
        try:
            if os.path.lexists(cambio["dest"]):
                _quitar(cambio["dest"])
            if cambio.get("had_old") and os.path.lexists(cambio["old"]):
                os.replace(cambio["old"], cambio["dest"])
            directorios.add(os.path.dirname(cambio["dest"]))
        except Exception as error:  # noqa: BLE001
            errores.append(f"{cambio['label']}: {type(error).__name__}")
    # El journal sólo puede desaparecer después de que los renames del
    # rollback sean duraderos. Si fsync falla, se conserva el journal y NPM no
    # se considera recuperado: tras un corte no se arriesga una mezcla new/old.
    for directorio in sorted(directorios):
        try:
            _fsync_directorio(directorio)
        except OSError as error:
            errores.append(
                f"fsync {directorio}: {type(error).__name__}")
    if errores:
        raise ErrorReplica("el rollback no pudo restaurar: " + ", ".join(errores))


def _intercambiar(cambios, comprobar_pasivo=None, was_running=True,
                  conservar_nuevo=None):
    tocados = []
    conservar = lambda: bool(conservar_nuevo and conservar_nuevo())
    try:
        # Desde el primer rename recovery debe poder completar hacia delante.
        # Persistirlo siempre cierra la ventana entre publicar el primer path y
        # detectar una promoción/cambio de rol. Al terminar el swap se rebaja
        # de nuevo a la política indicada por conservar_nuevo.
        _escribir_journal(
            "swapping", cambios, was_running,
            keep_new_on_recovery=True)
        for cambio in cambios:
            if comprobar_pasivo:
                comprobar_pasivo()
            if cambio["had_old"]:
                os.replace(cambio["dest"], cambio["old"])
            tocados.append(cambio)
            if cambio["new"] is not None:
                os.replace(cambio["new"], cambio["dest"])
            _fsync_directorio(os.path.dirname(cambio["dest"]))
        _escribir_journal(
            "swapped", cambios, was_running,
            keep_new_on_recovery=conservar())
        return tocados
    except Exception as error:
        try:
            # Desde este punto la decisión durable es volver al estado anterior,
            # incluso si se había observado una promoción. Debe constar antes
            # del primer rename inverso.
            _escribir_journal(
                "swapping", cambios, was_running,
                keep_new_on_recovery=False)
            _restaurar(tocados)
        except Exception as rollback_error:  # noqa: BLE001
            # El journal y los .old son ahora la única evidencia recuperable.
            # No se limpian ni se intenta servir un NPM potencialmente parcial.
            raise ErrorRollback(
                f"falló el swap ({error}) y también su rollback ({rollback_error})") \
                from rollback_error
        # El estado anterior ya está restaurado y durable, pero el llamador
        # aún debe recuperar runtime+salud. El journal conserva was_running
        # hasta entonces.
        raise SwapRevertido(
            f"falló la sustitución atómica del estado: {error}") from error


def _limpiar_transaccion(cambios):
    for cambio in cambios:
        for clave in ("new", "old"):
            ruta = cambio.get(clave)
            if ruta and os.path.lexists(ruta):
                _quitar(ruta)


def _db_local_valida():
    ruta = os.path.join(RUTA_DATOS, "database.sqlite")
    try:
        con = sqlite3.connect(f"file:{ruta}?mode=ro", uri=True, timeout=5)
        resultado = con.execute("pragma quick_check").fetchone()
        con.close()
        return bool(resultado and resultado[0] == "ok")
    except sqlite3.Error:
        return False


def _npm_responde():
    direccion = (os.environ.get("NPMG_NODE_ADDRESS") or "").strip()
    nodo = (os.environ.get("NPMG_NODE_NAME") or
            os.environ.get("NPMHA_NODO") or direccion).strip()
    if not nodo:
        return True
    import npm_api
    return npm_api.api_responde(nodo, timeout=3)


def _esperar_salud(segundos=60):
    limite = time.monotonic() + segundos
    while time.monotonic() < limite:
        try:
            estado = dockerd.estado(CONTENEDOR)
            if estado.get("corriendo") and _db_local_valida() and _npm_responde():
                return True
        except dockerd.ErrorDocker:
            pass
        time.sleep(2)
    return False


def aplicar(datos, soy_el_activo, comprobar_pasivo=None, comprobar_activo=None):
    """Valida, respalda, aplica y comprueba; revierte ante cualquier fallo.

    La recepción ordinaria sigue siendo exclusivamente pasiva. La única
    excepción es una recuperación cercada del activo: debe aportar una función
    que confirme durante toda la operación que continúa poseyendo la VIP.
    """
    if soy_el_activo and comprobar_activo is None:
        raise ErrorReplica("un nodo activo no acepta una réplica sin cercado de rol")
    if soy_el_activo and comprobar_pasivo is not None:
        raise ErrorReplica("una réplica activa no puede usar el cercado pasivo")
    if not soy_el_activo and comprobar_activo is not None:
        raise ErrorReplica("una réplica pasiva no puede usar el cercado activo")
    comprobar_rol = comprobar_activo if soy_el_activo else comprobar_pasivo
    if len(datos) > MAX_TAMANO:
        raise ErrorReplica("el paquete comprimido supera el límite")
    if comprobar_rol:
        comprobar_rol()

    raiz = _extraer_validado(datos)
    cambios = []
    npm_parado = False
    aplicados = []
    pasos = []
    rol_cambiado_durante_swap = False
    swap_iniciado = False
    estado_previo = None
    fase_journal = "prepared"

    def comprobar_durante_swap():
        nonlocal rol_cambiado_durante_swap
        if not comprobar_rol or rol_cambiado_durante_swap:
            return
        try:
            comprobar_rol()
        except ErrorReplica:
            # Ya se inició la sustitución. Terminar el paquete validado deja un
            # NPM coherente; deshacerlo sólo por un cambio de topología podría
            # restaurar datos viejos precisamente durante una conmutación.
            rol_cambiado_durante_swap = True
            # La decisión sobrevive a una caída de Guardian. Recovery podrá
            # terminar hacia delante el paquete validado y comprobar su salud.
            _escribir_journal(
                fase_journal, cambios,
                bool(estado_previo and estado_previo.get("corriendo")),
                keep_new_on_recovery=True)
            pasos.append("cambio de rol detectado; se completa el estado validado")
    try:
        estado_previo = dockerd.estado(CONTENEDOR)
        if not estado_previo.get("existe"):
            raise ErrorReplica(f"aquí no hay ningún contenedor «{CONTENEDOR}»")
        if not estado_previo.get("corriendo"):
            raise ErrorReplica(f"el contenedor «{CONTENEDOR}» no está en marcha")
        cambios = _preparar_cambios(raiz)
        if comprobar_rol:
            comprobar_rol()

        # El journal durable precede a la parada. Así el arranque siempre sabe
        # que debe devolver NPM a su estado original aunque Guardian muera en la
        # ventana de backup previa al primer rename.
        _escribir_journal("prepared", cambios,
                          bool(estado_previo.get("corriendo")))

        _asegurar_contenedor(False)
        npm_parado = True
        pasos.append("NPM parado")

        respaldo = _guardar_respaldo(empaquetar())
        pasos.append(f"estado anterior guardado en {respaldo}")

        fase_journal = "swapping"
        _escribir_journal(
            fase_journal, cambios, bool(estado_previo.get("corriendo")),
            keep_new_on_recovery=rol_cambiado_durante_swap)
        comprobar_durante_swap()
        swap_iniciado = True
        aplicados = _intercambiar(
            cambios, comprobar_pasivo=comprobar_durante_swap,
            was_running=bool(estado_previo.get("corriendo")),
            conservar_nuevo=lambda: rol_cambiado_durante_swap)
        fase_journal = "swapped"
        pasos.extend(c["label"] for c in aplicados if c.get("new") is not None)

        comprobar_durante_swap()

        _asegurar_contenedor(True)
        npm_parado = False
        pasos.append("NPM arrancado")
        if not _esperar_salud():
            raise ErrorReplica("NPM no recuperó salud después de aplicar la réplica")
        comprobar_durante_swap()
        pasos.append("NPM sano")
        _escribir_journal(
            "committed", cambios, bool(estado_previo.get("corriendo")),
            keep_new_on_recovery=rol_cambiado_durante_swap)
        # Desde aquí la transacción está comprometida y sana. La limpieza de
        # restos/backup no puede convertir un éxito en rollback: algunos .old
        # podrían haberse retirado ya y restaurar sería destructivo.
        aplicados = []
        try:
            _limpiar_transaccion(cambios)
            _borrar_journal()
        except OSError as error:
            pasos.append(f"aviso al limpiar la transacción: {type(error).__name__}")
        for viejo in _respaldos_a_borrar():
            try:
                os.unlink(viejo)
            except OSError as error:
                pasos.append(
                    f"aviso al rotar {os.path.basename(viejo)}: {type(error).__name__}")
        return {"ok": True, "pasos": pasos, "bytes": len(datos),
                "backup": os.path.basename(respaldo),
                "promoted_during_apply": (
                    rol_cambiado_durante_swap and not soy_el_activo),
                "role_changed_during_apply": rol_cambiado_durante_swap}
    except Exception as error:
        if isinstance(error, ErrorRollback):
            # Fail closed: NPM queda detenido y el journal conserva todas las
            # rutas necesarias para que el siguiente arranque reintente la
            # recuperación. Arrancarlo parcial o borrar .old sería destructivo.
            npm_parado = False
            raise
        if aplicados:
            try:
                _escribir_journal(
                    fase_journal, cambios,
                    bool(estado_previo and estado_previo.get("corriendo")),
                    keep_new_on_recovery=False)
                # El flag local no basta: stop/start pueden haberse aplicado y
                # perder su respuesta. Se consulta y se garantiza la parada
                # antes de tocar un solo fichero del rollback.
                _asegurar_contenedor(False)
                npm_parado = True
                _restaurar(aplicados)
                pasos.append("estado anterior restaurado")
                if estado_previo and estado_previo.get("corriendo"):
                    _asegurar_contenedor(True)
                    npm_parado = False
                    if not _esperar_salud():
                        raise ErrorReplica(
                            "el estado anterior fue restaurado, pero NPM no recuperó salud")
                # Datos anteriores, estado de ejecución y salud ya están
                # confirmados. Sólo ahora deja de hacer falta el journal.
                _borrar_journal()
            except Exception as rollback_error:  # noqa: BLE001
                # Cualquier ambigüedad conserva journal/.old y evita una nueva
                # escritura hasta que recuperar_transaccion pueda resolverla.
                npm_parado = False
                raise ErrorRollback(
                    f"{error}; además falló el rollback: {rollback_error}") from rollback_error
        elif estado_previo and estado_previo.get("corriendo"):
            try:
                # No llegó a publicarse ningún staging (o _intercambiar ya lo
                # revirtió). Arrancar es idempotente y también resuelve una
                # respuesta perdida del stop inicial.
                _asegurar_contenedor(True)
                npm_parado = False
                if not _esperar_salud():
                    raise ErrorReplica("NPM no recuperó salud tras abortar la réplica")
            except (dockerd.ErrorDocker, ErrorReplica) as start_error:
                raise ErrorReplica(
                    f"{error}; NPM tampoco pudo volver a arrancar: {start_error}") from start_error
        if ((not swap_iniciado or isinstance(error, SwapRevertido)) and
                not aplicados and cambios and
                os.path.exists(RUTA_JOURNAL)):
            try:
                _limpiar_transaccion(cambios)
                _borrar_journal()
            except OSError as cleanup_error:
                raise ErrorReplica(
                    f"{error}; no se pudo limpiar la preparación: {cleanup_error}") \
                    from cleanup_error
        if isinstance(error, ErrorReplica):
            raise
        raise ErrorReplica(f"no se pudo aplicar la réplica: {type(error).__name__}: {error}") from error
    finally:
        shutil.rmtree(raiz, ignore_errors=True)
        if cambios and not os.path.exists(RUTA_JOURNAL):
            try:
                _limpiar_transaccion(cambios)
            except OSError:
                pass
