"""Comprueba TLS y recupera sólo claves que coincidan con el certificado actual."""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class ErrorTLS(ValueError):
    pass


def _publica(clave):
    return clave.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def _nombres(certificado):
    try:
        return frozenset(certificado.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return frozenset(a.value for a in certificado.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME))


def _leer(ruta):
    with Path(ruta).open("rb") as fichero:
        contenido = fichero.read(64 * 1024 + 1)
    if len(contenido) > 64 * 1024:
        raise ErrorTLS("el archivo TLS supera el límite permitido")
    return contenido


def _ruta(raiz, ruta):
    raiz = Path(raiz).resolve()
    salida = Path(ruta).resolve()
    if not salida.is_relative_to(raiz):
        raise ErrorTLS("la ruta TLS sale del almacenamiento de certificados")
    return salida


def _ids(datos):
    db = Path(datos) / "database.sqlite"
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as con:
        tablas = {fila[0] for fila in con.execute(
            "select name from sqlite_master where type='table'")}
        if "certificate" not in tablas:
            return []  # Los snapshots sin certificados no necesitan TLS.
        return [int(fila[0]) for fila in con.execute(
            "select id from certificate where is_deleted=0 and provider='letsencrypt'")]


def pendientes(datos, letsencrypt):
    salida = []
    for cid in _ids(datos):
        live = Path(letsencrypt) / "live" / f"npm-{cid}"
        try:
            certificado = _leer(_ruta(letsencrypt, live / "fullchain.pem"))
            objeto = x509.load_pem_x509_certificate(certificado)
            publica = _publica(objeto.public_key())
            destino = _ruta(letsencrypt, live / "privkey.pem")
            archivo = (Path(letsencrypt) / "archive" / f"npm-{cid}").resolve()
            if destino.parent not in (archivo, live.resolve()):
                raise ErrorTLS("la clave TLS no pertenece al certificado solicitado")
        except (OSError, ValueError) as error:
            raise ErrorTLS(f"no se puede validar el certificado NPM {cid}") from error
        try:
            clave = _leer(destino)
            coincide = _publica(serialization.load_pem_private_key(
                clave, password=None).public_key()) == publica
        except (OSError, ValueError, TypeError):
            coincide = False
        if not coincide:
            salida.append({"id": cid, "publica": publica, "destino": destino,
                           "certificado": hashlib.sha256(certificado).digest(),
                           "live": live, "objeto": objeto})
    return salida


def validar(datos, letsencrypt):
    fallos = pendientes(datos, letsencrypt)
    if fallos:
        ids = ", ".join(str(p["id"]) for p in fallos)
        raise ErrorTLS(f"certificado y clave privada no coinciden en NPM: {ids}")


def claves(letsencrypt, ids):
    """Claves de archivo; el receptor exige igualdad con su certificado actual."""
    for cid in ids:
        archivo = Path(letsencrypt) / "archive" / f"npm-{int(cid)}"
        for ruta in sorted(archivo.glob("privkey*.pem")):
            try:
                key = _leer(_ruta(letsencrypt, ruta))
                suffix = ruta.name[len("privkey"):]
                fullchain = archivo / ("fullchain" + suffix)
                if fullchain.exists():
                    yield int(cid), {"key": key, "fullchain": _leer(_ruta(letsencrypt, fullchain))}
                else:
                    yield int(cid), key
            except (OSError, ValueError):
                continue


def recuperar(datos, letsencrypt, respaldos, obtener_claves=None, comprobar=None):
    fallos = pendientes(datos, letsencrypt)
    if not fallos:
        return {"ok": True, "certificados_recuperados": []}
    buscadas = {p["id"]: p for p in fallos}
    encontradas = {}
    mas_recientes = {}

    def recoger(candidatas):
        for cid, candidato in candidatas:
            if cid not in buscadas or cid in encontradas:
                continue
            contenido = candidato["key"] if isinstance(candidato, dict) else candidato
            try:
                publica = _publica(serialization.load_pem_private_key(
                    contenido, password=None).public_key())
            except (ValueError, TypeError):
                continue
            if publica == buscadas[cid]["publica"]:
                encontradas[cid] = contenido
                if len(encontradas) == len(buscadas):
                    break
            elif isinstance(candidato, dict):
                try:
                    cadena = x509.load_pem_x509_certificates(candidato["fullchain"])
                    cert = cadena[0]
                    actual = buscadas[cid]["objeto"]
                    ahora = datetime.datetime.now(datetime.timezone.utc)
                    anterior = mas_recientes.get(cid)
                    if (_publica(cert.public_key()) == publica and
                            _nombres(cert) == _nombres(actual) and
                            actual.not_valid_before_utc < cert.not_valid_before_utc <= ahora and
                            cert.not_valid_after_utc > ahora and
                            (not anterior or cert.not_valid_before_utc > anterior["objeto"].not_valid_before_utc)):
                        mas_recientes[cid] = {**candidato, "objeto": cert, "cadena": cadena}
                except (ValueError, TypeError, IndexError):
                    continue

    recoger(claves(letsencrypt, buscadas))
    if len(encontradas) != len(buscadas) and obtener_claves:
        recoger(obtener_claves(set(buscadas) - set(encontradas)))
    if set(encontradas) | set(mas_recientes) != set(buscadas):
        faltan = ", ".join(str(cid) for cid in buscadas if cid not in encontradas and cid not in mas_recientes)
        raise ErrorTLS(f"no se encontró la clave del certificado actual NPM {faltan}; "
                       "no se retrocede a un certificado anterior")

    carpeta = Path(respaldos) / "tls-recovery"
    carpeta.mkdir(mode=0o700, parents=True, exist_ok=True)
    recuperados = []
    actualizados = []
    for cid, pendiente in buscadas.items():
        if comprobar:
            comprobar()
        live = pendiente["live"]
        actual = _leer(_ruta(letsencrypt, live / "fullchain.pem"))
        if hashlib.sha256(actual).digest() != pendiente["certificado"]:
            raise ErrorTLS("el certificado cambió durante la recuperación; se reintentará")
        destino = _ruta(letsencrypt, live / "privkey.pem")
        if destino != pendiente["destino"]:
            raise ErrorTLS("la clave cambió de ruta durante la recuperación")
        anterior = destino.read_bytes() if destino.exists() else b""
        nombre = f"npm-{cid}-{hashlib.sha256(anterior).hexdigest()}.key"
        copia = carpeta / nombre
        if not copia.exists():
            fd = os.open(copia, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fichero:
                fichero.write(anterior)
                fichero.flush()
                os.fsync(fichero.fileno())
        if copia.read_bytes() != anterior:
            raise ErrorTLS("no se pudo verificar la copia previa de la clave")
        if (_leer(_ruta(letsencrypt, live / "fullchain.pem")) != actual or
                (destino.read_bytes() if destino.exists() else b"") != anterior):
            raise ErrorTLS("TLS cambió durante la recuperación; se reintentará")
        nuevo = mas_recientes.get(cid) if cid not in encontradas else None
        cambios = [(destino, encontradas[cid] if nuevo is None else nuevo["key"])]
        if nuevo:
            for nombre, contenido in (
                    ("cert.pem", nuevo["objeto"].public_bytes(serialization.Encoding.PEM)),
                    ("chain.pem", b"".join(c.public_bytes(serialization.Encoding.PEM) for c in nuevo["cadena"][1:])),
                    ("fullchain.pem", nuevo["fullchain"])):
                ruta = _ruta(letsencrypt, live / nombre)
                if ruta.parent != destino.parent:
                    raise ErrorTLS("los archivos de la pareja TLS no pertenecen al mismo certificado")
                previo = ruta.read_bytes() if ruta.exists() else b""
                copia_cert = carpeta / f"npm-{cid}-{nombre}-{hashlib.sha256(previo).hexdigest()}.backup"
                if not copia_cert.exists():
                    fd = os.open(copia_cert, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as fichero:
                        fichero.write(previo)
                        fichero.flush()
                        os.fsync(fichero.fileno())
                if copia_cert.read_bytes() != previo:
                    raise ErrorTLS("la copia previa del certificado no se pudo verificar")
                cambios.append((ruta, contenido))
        if comprobar:
            comprobar()
        for ruta, contenido in cambios:
            fd, temporal = tempfile.mkstemp(prefix=".npmg-tls-", dir=ruta.parent)
            try:
                with os.fdopen(fd, "wb") as fichero:
                    fichero.write(contenido)
                    fichero.flush()
                    os.fsync(fichero.fileno())
                os.replace(temporal, ruta)
            finally:
                if os.path.exists(temporal):
                    os.unlink(temporal)
        fd_carpeta = os.open(destino.parent, os.O_RDONLY)
        try:
            os.fsync(fd_carpeta)
        finally:
            os.close(fd_carpeta)
        if nuevo:
            with sqlite3.connect(Path(datos) / "database.sqlite") as con:
                columnas = {r[1] for r in con.execute("pragma table_info(certificate)")}
                if "expires_on" in columnas:
                    con.execute("update certificate set expires_on=? where id=?",
                                (nuevo["objeto"].not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"), cid))
            actualizados.append(cid)
        recuperados.append(cid)
    validar(datos, letsencrypt)
    return {"ok": True, "certificados_recuperados": recuperados,
            "certificados_mas_recientes": actualizados}
