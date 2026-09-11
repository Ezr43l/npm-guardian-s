"""Lo que se puede saber de NPM sin tocarlo: su inventario de certificados y de
dominios, leido de su base de datos en SOLO LECTURA.

Se abre con `mode=ro` a proposito. Este contenedor no escribe jamas en la base
de datos de NPM: cuando haya que cambiar algo se hara por su API, que es la que
sabe regenerar la configuracion de nginx y recargarla. Escribir por debajo
dejaria a NPM sirviendo una cosa distinta de la que dice tener.
"""
import json
import os
import re
import sqlite3
import socket
import ssl
from datetime import datetime, timezone

import configuracion

RUTA_DB = os.environ.get("NPMG_NPM_DB", os.environ.get("NPMHA_DB", "/npm/database.sqlite"))
RUTA_LE = os.environ.get("NPMG_NPM_LETSENCRYPT", os.environ.get(
    "NPMHA_NPM_LETSENCRYPT", "/npm-letsencrypt"))
TABLAS_HOST_TLS = {"proxy_host", "redirection_host", "dead_host"}
CONSULTAS_HOST_TLS = {
    "proxy_host": (
        'select domain_names from "proxy_host" '
        "where is_deleted=0 and enabled=1 and certificate_id=?"),
    "redirection_host": (
        'select domain_names from "redirection_host" '
        "where is_deleted=0 and enabled=1 and certificate_id=?"),
    "dead_host": (
        'select domain_names from "dead_host" '
        "where is_deleted=0 and enabled=1 and certificate_id=?"),
}


class SinBaseDeDatos(Exception):
    """No se puede leer la base de datos de NPM."""


def _identificador_host_tls(tabla):
    if tabla not in TABLAS_HOST_TLS or not re.fullmatch(r"[a-z_]+", tabla):
        raise SinBaseDeDatos("identificador de tabla de hosts no permitido")
    return f'"{tabla}"'


def _abrir():
    if not os.path.exists(RUTA_DB):
        raise SinBaseDeDatos(f"No existe {RUTA_DB}. ¿Está montado el appdata de NPM?")
    try:
        return sqlite3.connect(f"file:{RUTA_DB}?mode=ro", uri=True, timeout=10)
    except sqlite3.Error as e:
        raise SinBaseDeDatos(f"No se pudo abrir {RUTA_DB}: {e}")


def _dias_hasta(fecha):
    if not fecha:
        return None
    for formato in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            d = datetime.strptime(fecha[:19] if formato[2] == "%" else fecha, formato)
            return (d.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        except ValueError:
            continue
    return None


def certificados():
    """Los certificados vivos, con lo que falta para que caduquen."""
    con = _abrir()
    salida = []
    for cid, nombre, proveedor, caduca, meta, domain_names in con.execute(
        "select id, nice_name, provider, expires_on, meta, domain_names "
        "from certificate where is_deleted=0 order by expires_on"
    ):
        m = {}
        try:
            m = json.loads(meta or "{}")
        except ValueError:
            pass
        try:
            dominios_cert = json.loads(domain_names or "[]")
        except (ValueError, TypeError):
            dominios_cert = []
        dominios_cert = sorted({
            str(d).strip().rstrip(".").casefold() for d in dominios_cert
            if str(d).strip()
        })
        salida.append({
            "id": cid,
            "nombre": nombre,
            "proveedor": proveedor,
            "caduca": (caduca or "")[:19],
            "dias": _dias_hasta(caduca),
            "reto_dns": bool(m.get("dns_challenge")),
            "proveedor_dns": m.get("dns_provider"),
            "dominios": dominios_cert,
        })
    con.close()
    return salida


def estado_certificado(id_certificado):
    """Marca del registro y del PEM para probar que una emisión cambió de verdad."""
    con = _abrir()
    try:
        fila = con.execute(
            "select expires_on, modified_on, is_deleted from certificate where id=?",
            (int(id_certificado),),
        ).fetchone()
    finally:
        con.close()
    if not fila or fila[2]:
        return None
    ruta_pem = os.path.join(
        RUTA_LE, "live", f"npm-{int(id_certificado)}", "fullchain.pem")
    huella = None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        with open(ruta_pem, "rb") as fichero:
            huella = x509.load_pem_x509_certificate(
                fichero.read()).fingerprint(hashes.SHA256()).hex()
    except (OSError, ValueError):
        pass
    return {"caduca": (fila[0] or "")[:19], "modificado": (fila[1] or "")[:19],
            "fingerprint": huella}


def credenciales_en_npm():
    """La huella de las credenciales que NPM usaria de verdad al renovar.

    NO se devuelve la clave, solo un resumen: sirve para avisar si la que hay en
    Guardian y la que usa NPM han dejado de coincidir. Un detector
    que comprueba una copia informa de la copia, no de la realidad.
    """
    import hashlib
    con = _abrir()
    juegos = {}
    for (meta,) in con.execute(
        "select meta from certificate where is_deleted=0 and meta like '%dns_provider%'"
    ):
        try:
            cred = (json.loads(meta or "{}") or {}).get("dns_provider_credentials") or ""
        except ValueError:
            continue
        usuario = _campo(cred, "dns_namecheap_username")
        clave = _campo(cred, "dns_namecheap_api_key")
        if not clave:
            continue
        juegos.setdefault((usuario, hashlib.sha256(clave.encode()).hexdigest()[:12]), 0)
        juegos[(usuario, hashlib.sha256(clave.encode()).hexdigest()[:12])] += 1
    con.close()
    return [{"usuario": u, "huella": h, "certificados": n} for (u, h), n in juegos.items()]


def credencial_dns_certificado(id_certificado):
    """Huella del juego DNS usado por un certificado concreto."""
    con = _abrir()
    try:
        fila = con.execute(
            "select meta from certificate where id=? and is_deleted=0",
            (int(id_certificado),),
        ).fetchone()
    finally:
        con.close()
    if not fila:
        return None
    try:
        cred = (json.loads(fila[0] or "{}") or {}).get(
            "dns_provider_credentials") or ""
    except ValueError:
        return None
    usuario = _campo(cred, "dns_namecheap_username")
    clave = _campo(cred, "dns_namecheap_api_key")
    if not clave:
        return None
    import hashlib
    return {"usuario": usuario,
            "huella": hashlib.sha256(clave.encode()).hexdigest()[:12]}


def _campo(cred, nombre):
    m = re.search(nombre + r"\s*=\s*([^\s\\]+)", cred or "")
    return m.group(1).strip() if m else None


def dominios():
    """Los proxy hosts y a donde envian, para saber que hay detras de cada uno."""
    con = _abrir()
    salida = []
    for hid, nombres, esquema, destino, puerto, cert, activo in con.execute(
        "select id, domain_names, forward_scheme, forward_host, forward_port, "
        "certificate_id, enabled from proxy_host where is_deleted=0 order by id"
    ):
        try:
            lista = json.loads(nombres or "[]")
        except ValueError:
            lista = [nombres]
        salida.append({
            "id": hid,
            "dominios": lista,
            "destino": f"{esquema}://{destino}:{puerto}",
            "servidor_destino": destino,
            "certificado": cert or None,
            "activo": bool(activo),
        })
    con.close()
    return salida


def resumen():
    certs = certificados()
    doms = dominios()
    proximos = [c for c in certs if c["dias"] is not None and c["dias"] <= 30]
    return {
        "certificados": len(certs),
        "dominios": len(doms),
        "caducan_en_30_dias": len(proximos),
        "proximo": certs[0] if certs else None,
    }


def salud_base():
    """Comprueba integridad SQLite, no sólo que el fichero se pueda abrir."""
    con = _abrir()
    try:
        resultado = con.execute("pragma quick_check").fetchone()
    except sqlite3.Error as error:
        raise SinBaseDeDatos(f"PRAGMA quick_check fallo: {error}") from error
    finally:
        con.close()
    if not resultado or resultado[0] != "ok":
        raise SinBaseDeDatos("la base de NPM no supera PRAGMA quick_check")
    return True


def comprobar_certificado_servido(id_certificado, nodo_activo):
    """Compara el fingerprint DER exacto guardado con cada consumidor TLS."""
    con = _abrir()
    dominios_cert = []
    try:
        tablas = {fila[0] for fila in con.execute(
            "select name from sqlite_master where type='table'")}
        # Proxy, redirecciones y hosts 404 pueden terminar TLS y presentar el
        # certificado. Streams de NPM son passthrough TCP/UDP y no tienen SNI
        # verificable desde este inventario.
        for tabla in sorted(TABLAS_HOST_TLS):
            if tabla not in tablas:
                continue
            identificador = _identificador_host_tls(tabla)
            # El identificador procede de la allowlist cerrada anterior.
            columnas = {fila[1] for fila in con.execute(
                f"pragma table_info({identificador})")}
            if not {"domain_names", "is_deleted", "enabled", "certificate_id"} <= columnas:
                continue
            for (nombres,) in con.execute(
                    CONSULTAS_HOST_TLS[tabla],
                    (id_certificado,)):
                try:
                    dominios_cert.extend(json.loads(nombres or "[]"))
                except ValueError:
                    pass
        fila = con.execute("select expires_on from certificate where id=?", (id_certificado,)).fetchone()
    finally:
        con.close()
    if not fila:
        return {"ok": False, "verificable": False, "motivo": "el certificado ya no existe"}
    if not dominios_cert:
        return {"ok": False, "verificable": False, "servido": False,
                "motivo": "certificado emitido, pero ningún host TLS activo lo sirve"}

    ruta_pem = os.path.join(RUTA_LE, "live", f"npm-{int(id_certificado)}", "fullchain.pem")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        with open(ruta_pem, "rb") as fichero:
            guardado = x509.load_pem_x509_certificate(fichero.read())
        huella_guardada = guardado.fingerprint(hashes.SHA256()).hex()
        vence_guardado = guardado.not_valid_after_utc
    except Exception as error:  # noqa: BLE001
        return {"ok": False, "verificable": False, "servido": False,
                "motivo": f"no se pudo leer el PEM guardado ({type(error).__name__})"}

    tabla = {}
    for trozo in (os.environ.get("NPMG_NODES") or os.environ.get("NPMHA_NODOS") or "").split(","):
        if ":" in trozo:
            nombre, ip = trozo.strip().split(":", 1)
            tabla[nombre] = ip
    destino = tabla.get(nodo_activo) or nodo_activo
    puerto = int(configuracion.leer()["settings"]["npm_api"].get("https_port") or 443)
    resultados = []
    contexto = ssl.create_default_context()
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE
    for dominio in dict.fromkeys(str(d).replace("*.", "") for d in dominios_cert):
        try:
            with socket.create_connection((destino, puerto), timeout=10) as crudo:
                with contexto.wrap_socket(crudo, server_hostname=dominio) as seguro:
                    der = seguro.getpeercert(binary_form=True)
            servido = x509.load_der_x509_certificate(der)
            huella_servida = servido.fingerprint(hashes.SHA256()).hex()
            resultados.append({
                "dominio": dominio,
                "ok": huella_servida == huella_guardada,
                "caduca_servido": servido.not_valid_after_utc.isoformat(timespec="seconds"),
                "fingerprint": huella_servida[:16],
            })
        except Exception as error:  # noqa: BLE001
            resultados.append({"dominio": dominio, "ok": False,
                               "error": type(error).__name__})
    coincide = bool(resultados and all(r.get("ok") for r in resultados))
    return {
        "ok": coincide, "verificable": True, "servido": coincide,
        "dominio": resultados[0]["dominio"], "dominios": resultados,
        "destino": f"{destino}:{puerto}",
        "fingerprint_guardado": huella_guardada[:16],
        "caduca_servido": resultados[0].get("caduca_servido"),
        "caduca_guardado": vence_guardado.isoformat(timespec="seconds"),
        "motivo": ("nginx entrega exactamente el certificado guardado en todos los hosts"
                   if coincide else
                   "al menos un host no entrega el certificado exacto guardado por NPM"),
    }
