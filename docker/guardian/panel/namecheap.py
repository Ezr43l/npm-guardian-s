"""¿Aceptaria Namecheap una renovacion AHORA MISMO?

Namecheap exige que la IP publica desde la que se llama a su API este en una
lista blanca, y NO ofrece ningun comando para actualizarla — comprobado contra
la propia API: todos los candidatos plausibles responden «Command is Invalid»
mientras dos comandos reales responden OK en la misma tanda. Asi que cuando el
operador cambia la IP, las renovaciones dejan de funcionar EN SILENCIO.

Este modulo hace la pregunta binaria que importa, con una llamada de solo
lectura: ¿renovaria hoy si tuviera que hacerlo?
"""
import hashlib
import os
import re
import urllib.parse
import urllib.request

import configuracion

# La IP no autorizada tiene su propio codigo. El veredicto se decide por EL, y
# no por «hubo algun error»: confundir cualquier fallo con un problema de lista
# blanca es exactamente el tipo de indicador que miente. Paso en la primera
# version de esta comprobacion, que daba «rechaza tu IP» ante un parametro mal
# puesto por quien la escribio.
IP_NO_AUTORIZADA = "1011150"

API = "https://api.namecheap.com/xml.response"
SERVICIOS_IP = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)
HOSTS_HTTPS_PERMITIDOS = {
    "api.ipify.org", "ifconfig.me", "icanhazip.com", "api.namecheap.com",
}


def _abrir_https(url, timeout):
    """Abre unicamente los endpoints HTTPS fijos usados por este modulo."""
    partes = urllib.parse.urlsplit(str(url))
    if (partes.scheme != "https" or partes.hostname not in HOSTS_HTTPS_PERMITIDOS or
            partes.username or partes.password or partes.fragment or
            partes.port not in (None, 443)):
        raise ValueError("endpoint HTTPS no permitido")
    # Esquema, host, credenciales, fragmento y puerto se validan arriba.
    return urllib.request.urlopen(url, timeout=timeout)  # nosec B310


def credenciales():
    """De la configuracion cifrada; el entorno se admite para migraciones."""
    return configuracion.secretos_namecheap()


def huella(clave):
    return hashlib.sha256((clave or "").encode()).hexdigest()[:12] if clave else None


def ip_publica():
    """Se prueban varios servicios: si uno esta caido, la comprobacion no debe
    convertirse en un falso «no se puede renovar»."""
    ultimo = None
    for url in SERVICIOS_IP:
        try:
            ip = _abrir_https(url, timeout=10).read().decode().strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip, None
        except Exception as e:  # noqa: BLE001
            ultimo = f"{type(e).__name__}"
    return None, f"no se pudo averiguar la IP publica ({ultimo})"


def comprobar():
    """Devuelve el veredicto, listo para enseñar y para decidir si avisar."""
    if not configuracion.leer()["settings"]["namecheap"].get("enabled"):
        return {
            "estado": "desactivado",
            "mensaje": "La automatizacion de Namecheap esta desactivada. La alta disponibilidad y la sincronizacion siguen funcionando.",
        }
    usuario, clave = credenciales()
    if not usuario or not clave:
        return {
            "estado": "sin_credenciales",
            "mensaje": "Faltan el usuario o la clave de Namecheap. Configuralos en el panel.",
        }

    ip, err = ip_publica()
    if not ip:
        return {"estado": "indeterminado", "mensaje": err}

    q = urllib.parse.urlencode({
        "ApiUser": usuario, "ApiKey": clave, "UserName": usuario,
        "Command": "namecheap.domains.getList", "ClientIp": ip, "PageSize": "10",
    })
    try:
        r = _abrir_https(f"{API}?{q}", timeout=30).read().decode()
    except Exception as e:  # noqa: BLE001
        # No se llego a hablar con Namecheap. NO es «la IP esta mal»: es que no
        # sabemos. Decirlo asi evita un aviso falso cada vez que hay un corte.
        return {"estado": "indeterminado", "ip": ip,
                "mensaje": f"no se pudo llamar a Namecheap: {type(e).__name__}"}

    errores = re.findall(r'<Error Number="(\d+)">([^<]*)', r)
    codigos = [n for n, _ in errores]
    estado_api = re.search(r'ApiResponse[^>]*Status="([^"]+)"', r)
    dominios = re.findall(r'<Domain[^>]*Name="([^"]+)"', r)

    if IP_NO_AUTORIZADA in codigos:
        return {
            "estado": "ip_rechazada", "ip": ip,
            "mensaje": f"Namecheap no acepta la IP {ip}. Hasta que no se anada a su lista "
                       f"blanca no se puede renovar ningun certificado.",
        }
    if estado_api and estado_api.group(1) == "OK":
        return {"estado": "ok", "ip": ip, "dominios_visibles": len(dominios),
                "mensaje": f"Namecheap acepta la IP {ip}. Una renovacion funcionaria."}
    detalle = "; ".join(f"{n}: {t}" for n, t in errores[:3]) or "sin detalle"
    return {"estado": "otro_error", "ip": ip,
            "mensaje": f"Namecheap respondio con un error que NO es de lista blanca: {detalle}"}
