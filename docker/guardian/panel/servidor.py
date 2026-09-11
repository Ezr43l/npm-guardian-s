"""NPM Guardian: panel, API, vigilancia y replica.

Mira, avisa, renueva y replica:

  · lee el inventario de NPM (su base de datos, en solo lectura),
  · comprueba cada hora si Namecheap aceptaría una renovación,
  · vigila las caducidades y avisa por el centro de notificaciones de Unraid,
  · renueva por la API de NPM antes de que lo haga NPM por su cuenta,
  · y lleva el resultado a los nodos pasivos configurados.

TODO ESO LO HACE UN SOLO NODO: el que sostiene la dirección flotante. Los otros
dos miran y callan. Cuando NO SE SABE quién la sostiene —el panel de direcciones
no contesta— tampoco actúa nadie: «no lo sé» no es «mando yo», y tratarlo como
tal haría que varios nodos renovaran y avisaran a la vez.

Corre en todos los nodos. El activo sirve el portal autenticado; los pasivos
sirven una vista publica minima. Las llamadas internas usan un token distinto
de las sesiones humanas.
"""
import json
import hashlib
import hmac
import ipaddress
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import arranque
import avisos
import configuracion
import coordinacion
import dockerd
import inventario
import namecheap
import planificador
import protocolo_cluster
import replica
import npm
import npm_api
import seguridad
import vigilante

PUERTO = int(os.environ.get("NPMG_PORT", os.environ.get("NPMHA_PUERTO", "6061")))
PUERTO_PUBLICO = int(os.environ.get("NPMG_PUBLIC_PORT", str(PUERTO)))
DIR_WEB = os.environ.get("NPMG_WEB", os.environ.get(
    "NPMHA_WEB", os.path.join(os.path.dirname(__file__), "web")))
NODO = os.environ.get("NPMG_NODE_NAME", os.environ.get("NPMHA_NODO", "sin-nombre"))


def _pares():
    salida = []
    crudo = os.environ.get("NPMG_PEERS", os.environ.get("NPMHA_PARES", ""))
    for i, trozo in enumerate(crudo.split(",")):
        trozo = trozo.strip()
        if not trozo:
            continue
        if "=" in trozo:
            nombre, base = trozo.split("=", 1)
        else:
            nombre, base = f"peer-{i + 1}", trozo
        salida.append({"nombre": nombre.strip(), "url": base.strip().rstrip("/")})
    return salida


PARES = _pares()


def _nodos_declarados():
    """Membresía autoritativa declarada en NPMG_NODES, normalizada por nombre."""
    crudo = (os.environ.get("NPMG_NODES") or
             os.environ.get("NPMHA_NODOS") or "")
    nodos = {}
    for trozo in crudo.split(","):
        trozo = trozo.strip()
        if not trozo:
            continue
        if ":" not in trozo:
            raise configuracion.ErrorConfiguracion(
                "cada entrada de NPMG_NODES debe ser nombre:dirección")
        nombre, direccion = trozo.split(":", 1)
        nombre = nombre.strip()
        direccion = direccion.strip()
        clave = nombre.casefold()
        if not nombre or not direccion:
            raise configuracion.ErrorConfiguracion(
                "NPMG_NODES contiene un nombre o dirección vacío")
        if clave in nodos:
            raise configuracion.ErrorConfiguracion(
                f"NPMG_NODES repite el miembro «{nombre}»")
        nodos[clave] = nombre
    return nodos


def _miembros_locales():
    nombres = [str(NODO or "").strip()] + [
        str(par.get("nombre") or "").strip() for par in PARES]
    if any(not nombre for nombre in nombres):
        raise configuracion.ErrorConfiguracion(
            "NPMG_NODE_NAME y todos los nombres de NPMG_PEERS son obligatorios")
    normalizados = [nombre.casefold() for nombre in nombres]
    if len(set(normalizados)) != len(normalizados):
        raise configuracion.ErrorConfiguracion(
            "NPMG_PEERS repite un miembro o incluye el nodo local")
    return {nombre.casefold(): nombre for nombre in nombres}


def _huella_topologia():
    """Huella estable de nombres; las direcciones pueden ser distintas por nodo."""
    declarados = _nodos_declarados()
    # El fallback sólo mantiene importables las primitivas y las pruebas
    # aisladas. ``main`` exige siempre la declaración autoritativa completa.
    miembros = declarados or _miembros_locales()
    canonico = json.dumps(sorted(miembros), separators=(",", ":")).encode()
    return hashlib.sha256(canonico).hexdigest()


def _validar_topologia():
    declarados = _nodos_declarados()
    if not declarados:
        raise configuracion.ErrorConfiguracion(
            "NPMG_NODES debe declarar todos los miembros del clúster")
    locales = _miembros_locales()
    if set(declarados) != set(locales):
        faltan = sorted(set(declarados) - set(locales))
        sobran = sorted(set(locales) - set(declarados))
        detalle = []
        if faltan:
            detalle.append("faltan en NPMG_PEERS: " + ", ".join(faltan))
        if sobran:
            detalle.append("no constan en NPMG_NODES: " + ", ".join(sobran))
        raise configuracion.ErrorConfiguracion(
            "la membresía NPMG_NODES no coincide con NODO+PARES; " + "; ".join(detalle))
    for par in PARES:
        url = urllib.parse.urlparse(str(par.get("url") or ""))
        if url.scheme.lower() not in ("http", "https") or not url.hostname:
            raise configuracion.ErrorConfiguracion(
                f"la URL interna de «{par.get('nombre')}» debe ser http(s) y tener host")
        if url.username or url.password or url.query or url.fragment:
            raise configuracion.ErrorConfiguracion(
                f"la URL interna de «{par.get('nombre')}» no admite credenciales, query ni fragmento")
    return {"members": sorted(declarados), "fingerprint": _huella_topologia()}

# El panel de direcciones flotantes dice quién sostiene la dirección de NPM, y
# por tanto quién manda. Se le pregunta a él en vez de inventar otra elección.
PANEL_IP = os.environ.get("NPMG_KEEPALIVED_URL", os.environ.get(
    "NPMHA_PANEL_FLOTANTE", "http://host.docker.internal:6060")).rstrip("/")
SERVICIO_FLOTANTE = os.environ.get("NPMG_KEEPALIVED_SERVICE", os.environ.get(
    "NPMHA_SERVICIO", "npm"))
TOKEN_KEEPALIVED = configuracion._secreto_entorno(
    "NPMG_KEEPALIVED_API_TOKEN", "NPMHA_KEEPALIVED_API_TOKEN")
MODO_INDEPENDIENTE = (os.environ.get("NPMG_STANDALONE", "0").lower() in
                      ("1", "true", "yes", "si", "sí"))


def _verdadero(nombre):
    return (os.environ.get(nombre, "0").strip().lower() in
            ("1", "true", "yes", "si", "sí", "on"))


PERMITIR_PORTAL_INSEGURO = _verdadero("NPMG_ALLOW_INSECURE_PORTAL")
PERMITIR_KEEPALIVED_INSEGURO = _verdadero("NPMG_ALLOW_INSECURE_KEEPALIVED_API")


def _redes_proxy():
    redes = []
    for valor in (os.environ.get("NPMG_TRUSTED_PROXY_IPS") or "").split(","):
        if valor.strip():
            redes.append(ipaddress.ip_network(valor.strip(), strict=False))
    return redes


REDES_PROXY = _redes_proxy()


def _version_embebida():
    ruta = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "APP_VERSION"))
    try:
        with open(ruta, encoding="utf-8") as fichero:
            return fichero.read().strip() or "desarrollo"
    except OSError:
        return "desarrollo"


# La version forma parte de la imagen y procede exclusivamente del VERSION raiz.
# No se acepta una variable de entorno: una imagen no puede anunciar una version
# distinta de la que contiene.
VERSION = _version_embebida()
TIEMPO_PAR = 4


def _reiniciar_desde_configuracion():
    time.sleep(0.75)
    inicio = os.path.join(os.path.dirname(__file__), "arranque.py")
    os.execv(sys.executable, [sys.executable, inicio])  # nosec B606: sin shell

TIPOS = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
}


def _peticion_interna(url, destino, datos=None, metodo=None):
    metodo = metodo or ("POST" if datos is not None else "GET")
    ruta = urllib.parse.urlparse(url).path
    pet = urllib.request.Request(url, data=datos, method=metodo)
    cabeceras = protocolo_cluster.firmar(
        metodo, ruta, NODO, destino, datos or b"")
    for nombre, valor in cabeceras.items():
        pet.add_header(nombre, valor)
    return pet, cabeceras["X-NPMG-Nonce"]


def _abrir_http(recurso, timeout, context=None):
    """Bloquea esquemas URL locales o de fichero antes de delegar en urllib."""
    url = recurso.full_url if hasattr(recurso, "full_url") else str(recurso)
    partes = urllib.parse.urlsplit(url)
    if (partes.scheme not in ("http", "https") or not partes.hostname or
            partes.username or partes.password or partes.fragment):
        raise RuntimeError("el endpoint remoto debe ser una URL HTTP(S) sin credenciales")
    # Esquema y autoridad se validan inmediatamente arriba.
    return urllib.request.urlopen(  # nosec B310
        recurso, timeout=timeout, context=context)


def _pedir(url, tiempo=TIEMPO_PAR):
    esquema = urllib.parse.urlparse(url).scheme.lower()
    if esquema == "http" and not PERMITIR_KEEPALIVED_INSEGURO:
        raise RuntimeError(
            "la API de Keepalived usa HTTP sin NPMG_ALLOW_INSECURE_KEEPALIVED_API=1")
    contexto = None
    if esquema == "https":
        ca = configuracion.fichero_ca("NPMG_KEEPALIVED_CA_FILE")
        contexto = ssl.create_default_context(cafile=ca)
    peticion = urllib.request.Request(url)
    if TOKEN_KEEPALIVED:
        peticion.add_header("Authorization", f"Bearer {TOKEN_KEEPALIVED}")
    with _abrir_http(peticion, timeout=tiempo, context=contexto) as r:
        return json.loads(r.read().decode() or "{}")


def _pedir_interno(par, ruta, tiempo=TIEMPO_PAR):
    url = f"{par['url']}{ruta}"
    pet, nonce = _peticion_interna(url, par["nombre"])
    with _abrir_http(pet, timeout=tiempo) as respuesta:
        cifrado = respuesta.read()
    claro = protocolo_cluster.descifrar(
        cifrado, f"response:{ruta}", par["nombre"], NODO, contexto=nonce)
    return json.loads(claro.decode() or "{}")


def _descifrar_escritura_interna(cuerpo, tipo, identidad):
    """Abre v1 con fence de topología o, durante rolling upgrade, el legado."""
    try:
        claro = protocolo_cluster.descifrar(
            cuerpo, tipo, identidad["source"], NODO,
            contexto=_huella_topologia())
        return claro, True
    except protocolo_cluster.ErrorProtocolo as error_topologia:
        try:
            claro = protocolo_cluster.descifrar(
                cuerpo, tipo, identidad["source"], NODO, contexto="")
            return claro, False
        except protocolo_cluster.ErrorProtocolo:
            raise error_topologia


def quien_manda():
    """Qué nodo sostiene la dirección flotante de NPM, y si soy yo.

    `soy_yo` tiene TRES valores y los tres importan:

        True   la sostengo yo. Es el único caso en el que se actúa.
        False  la sostiene otro, y consta.
        None   NO SE SABE — no se llega al panel de direcciones, o la dirección
               todavía no está en marcha.

    `None` no es `False`. Quien lo trate como «no soy yo» acabará aceptando una
    réplica en el nodo que está sirviendo tráfico; quien lo trate como «soy yo»
    acabará con varios nodos renovando a la vez. Aquí no se inventa un
    veredicto: se dice que no se sabe, y quien llama decide qué hacer sabiéndolo.
    """
    if MODO_INDEPENDIENTE:
        return {"activo": NODO, "soy_yo": True, "ip": None,
                "origen": "modo independiente declarado"}
    try:
        cuadro = _pedir(f"{PANEL_IP}/api/direcciones")
    except Exception as e:  # noqa: BLE001
        return {"activo": None, "soy_yo": None, "origen": f"no se llega al panel de direcciones ({type(e).__name__})"}

    for d in cuadro.get("direcciones", []):
        if d.get("servicio") != SERVICIO_FLOTANTE:
            continue
        if d.get("estado") != "en_uso":
            return {"activo": None, "soy_yo": None, "ip": d.get("ip"),
                    "origen": f"la dirección {d.get('ip')} está «{d.get('estado')}», todavía no en marcha"}
        activo = d.get("portador")
        return {"activo": activo, "soy_yo": activo == NODO, "ip": d.get("ip"),
                "origen": "dirección flotante"}
    return {"activo": None, "soy_yo": None,
            "origen": f"«{SERVICIO_FLOTANTE}» no está declarado en el reparto de direcciones"}


def vista_local():
    """Lo que este nodo puede contar por sí mismo."""
    v = {"nodo": NODO, "version": VERSION, "npm_accesible": False}
    try:
        v["resumen"] = npm.resumen()
        v["npm_accesible"] = True
    except npm.SinBaseDeDatos as e:
        v["error"] = str(e)
    # Sin socket de Docker este nodo puede mandar su estado, pero no recibirlo:
    # recibir exige parar NPM. Se dice, en vez de descubrirlo el día que haga falta.
    v["puede_recibir_replica"] = dockerd.disponible()
    v["security_key_ids"] = configuracion.identificadores_secretos()
    v["topology_fingerprint"] = _huella_topologia()
    v["configuration_revision"] = configuracion.exportar()["revision"]
    v["ledger_revision"] = vigilante.exportar_estado_cluster()["revision"]
    return v


def credenciales_desincronizadas():
    """¿La clave de la plantilla y la que usa NPM son la misma?

    Mandan las de la plantilla, por decisión: una sola copia que mantiene una
    persona. Pero si NPM usa otra distinta, el guardián estaría comprobando algo
    que NPM no va a usar — y eso hay que decirlo, no callarlo.
    """
    if not configuracion.leer()["settings"]["namecheap"].get("enabled"):
        return {"comparable": False, "disabled": True,
                "motivo": "la integracion con Namecheap esta desactivada"}
    _, clave = namecheap.credenciales()
    if not clave:
        return {"comparable": False, "motivo": "no hay clave en la plantilla"}
    try:
        en_npm = npm.credenciales_en_npm()
    except npm.SinBaseDeDatos as e:
        return {"comparable": False, "motivo": str(e)}
    if not en_npm:
        return {"comparable": False, "motivo": "NPM no tiene credenciales de DNS guardadas"}
    mia = namecheap.huella(clave)
    huellas = {c["huella"] for c in en_npm}
    return {
        "comparable": True,
        "coinciden": mia in huellas,
        "juegos_en_npm": len(huellas),
        "aviso": None if mia in huellas else
                 "La clave de la plantilla NO es la que usa NPM. El guardián estaría "
                 "comprobando una clave que NPM no va a usar al renovar.",
    }


def cuadro():
    """El estado completo: lo de aquí más lo que cuenten los pares."""
    yo = vista_local()
    yo["alcanzable"] = True
    nodos = {NODO: yo}

    def traer(par):
        try:
            v = _pedir_interno(par, "/api/internal/local")
            v["alcanzable"] = True
            return v
        except Exception as e:  # noqa: BLE001
            return {"nodo": par["nombre"], "alcanzable": False, "error": type(e).__name__}

    if PARES:
        with ThreadPoolExecutor(max_workers=len(PARES)) as ex:
            for v in ex.map(traer, PARES):
                nodos[v.get("nodo", "?")] = v

    salida = {"yo": NODO, "version": VERSION, "mando": quien_manda(), "nodos": nodos,
              "vigilancia": vigilante.ultimo(),
              "credenciales": credenciales_desincronizadas()}
    ids_locales = configuracion.identificadores_secretos()
    incompatibles = []
    for nombre, estado in nodos.items():
        if estado.get("alcanzable") and estado.get("security_key_ids") != ids_locales:
            estado["security_compatible"] = False
            incompatibles.append(nombre)
        elif estado.get("alcanzable"):
            estado["security_compatible"] = True
    salida["cluster_security"] = {
        "ok": not incompatibles,
        "incompatible_nodes": sorted(incompatibles),
    }
    try:
        salida["certificados"] = npm.certificados()
        salida["dominios"] = npm.dominios()
        salida["credenciales_en_npm"] = npm.credenciales_en_npm()
    except npm.SinBaseDeDatos as e:
        salida["error"] = str(e)
    return salida


def sincronia():
    """El inventario de todos los nodos, comparado elemento a elemento.

    Sólo mira. No cambia nada en ningún nodo: enseña quién tiene qué de cada
    cosa y quién ganaría. Lo que se haga con eso se decide aparte, y se enseña
    antes de hacerlo.
    """
    caidos = {}
    incompatibles = {}
    try:
        invs = {NODO: inventario.inventario()}
    except inventario.ErrorInventario as e:
        invs = {}
        caidos[NODO] = str(e)
        incompatibles[NODO] = {
            "code": "INCOMPATIBLE_LOCAL_SCHEMA", "error": str(e)}
    except npm.SinBaseDeDatos as e:
        # Sin base de datos aquí no se puede comparar, pero eso no debe tumbar
        # la respuesta entera: se dice y se sigue con lo que cuenten los demás.
        invs = {}
        caidos[NODO] = str(e)

    def traer(par):
        try:
            return par, _pedir_interno(par, "/api/internal/inventario", 8)
        except urllib.error.HTTPError as error:
            detalle = ""
            codigo = None
            try:
                cuerpo = json.loads(error.read().decode())
                detalle = cuerpo.get("error", "")
                codigo = cuerpo.get("code")
            except Exception:  # noqa: BLE001
                detalle, codigo = "", None
            return par, {"error": detalle or f"HTTP {error.code}",
                         "codigo": codigo or f"HTTP_{error.code}",
                         "bloquea_replica": True}
        except protocolo_cluster.ErrorProtocolo as error:
            return par, {"error": str(error), "codigo": "INVALID_CLUSTER_RESPONSE",
                         "bloquea_replica": True}
        except Exception as e:  # noqa: BLE001
            return par, {"error": type(e).__name__}

    if PARES:
        with ThreadPoolExecutor(max_workers=len(PARES)) as ex:
            for par, v in ex.map(traer, PARES):
                if v.get("error"):
                    caidos[par["nombre"]] = v["error"]
                    if v.get("bloquea_replica"):
                        incompatibles[par["nombre"]] = {
                            "code": v.get("codigo"), "error": v.get("error")}
                else:
                    invs[v.get("nodo") or par["nombre"]] = v

    r = inventario.comparar(invs)
    r["nodos_consultados"] = sorted(invs)
    r["nodos_sin_respuesta"] = caidos
    r["nodos_incompatibles"] = incompatibles
    # Comparar contra un nodo que no contesta no dice nada útil: lo que le falte
    # puede ser que no lo tenga, o que no se le haya podido preguntar. Se dice,
    # en vez de dar por bueno un veredicto a medias.
    r["comparacion_completa"] = not caidos
    return r


# Un cerrojo por operación que escribe. El panel deshabilita el botón mientras
# dura, pero eso es cortesía del navegador: dos pestañas, un refresco a destiempo
# o un `curl` se lo saltan. Dos réplicas a la vez sobre el mismo nodo pararían y
# arrancarían NPM cruzándose, y las dos escribirían los mismos ficheros.
_candado_replica = threading.Lock()
_candado_recibir = threading.Lock()
_candado_config_salida = threading.RLock()
_candado_config_recepcion = threading.Lock()
_candado_reconciliacion_guardian = threading.Lock()


def _quorum_cluster():
    """Mayoría del clúster configurado, contando siempre este nodo."""
    total = 1 + len(PARES)
    return total // 2 + 1


def _resumen_quorum(resultados):
    confirmados = 1 + sum(1 for valor in resultados.values() if valor.get("ok"))
    quorum = _quorum_cluster()
    return {
        "ok": confirmados >= quorum,
        "complete": all(valor.get("ok") for valor in resultados.values()),
        "acknowledged": confirmados,
        "cluster_size": 1 + len(PARES),
        "quorum": quorum,
    }


def _huella_sincronia(inventario_nodo=None):
    """Huella semántica: ignora fechas que NPM reescribe sin cambiar datos."""
    inventario_nodo = inventario_nodo or inventario.inventario()
    elementos = inventario_nodo.get("elementos") or {}
    if not isinstance(elementos, dict) or any(
            not isinstance(valor, dict) or not valor.get("huella")
            for valor in elementos.values()):
        raise inventario.ErrorInventario(
            "el inventario no contiene huellas semánticas completas")
    canonico = json.dumps(
        {clave: valor["huella"] for clave, valor in sorted(elementos.items())},
        ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonico).hexdigest()


def _huella_logica(inventario_nodo=None):
    """Huella del estado autoritativo de SQLite, sin artefactos derivados."""
    inventario_nodo = inventario_nodo or inventario.inventario()
    elementos = inventario_nodo.get("elementos") or {}
    logicos = {
        clave: valor["huella"]
        for clave, valor in sorted(elementos.items())
        if clave != "artefactos:estado"
    }
    if not logicos or any(not isinstance(valor, str) or not valor for valor in logicos.values()):
        raise inventario.ErrorInventario(
            "el inventario lógico no contiene huellas completas")
    canonico = json.dumps(
        logicos, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode()
    return hashlib.sha256(canonico).hexdigest()


def _par_por_nombre(nombre):
    buscado = str(nombre or "").casefold()
    return next((par for par in PARES
                 if str(par.get("nombre") or "").casefold() == buscado), None)


def _pedir_snapshot(par):
    """Obtiene del pasivo elegido un snapshot cifrado y estable."""
    ruta = "/api/internal/export"
    peticion, nonce = _peticion_interna(
        f"{par['url']}{ruta}", par["nombre"])
    limite_sobre = (replica.MAX_TAMANO + 4096) * 2
    with _abrir_http(peticion, timeout=300) as respuesta:
        cifrado = respuesta.read(limite_sobre + 1)
    if len(cifrado) > limite_sobre:
        raise replica.ErrorReplica("la respuesta de recuperación supera el límite")
    claro = protocolo_cluster.descifrar(
        cifrado, f"response:{ruta}", par["nombre"], NODO, contexto=nonce)
    huella_cruda, separador, paquete = claro.partition(b"\n")
    try:
        huella = huella_cruda.decode("ascii")
    except UnicodeDecodeError as error:
        raise replica.ErrorReplica("la recuperación no acredita su estado lógico") from error
    if (separador != b"\n" or len(huella) != 64 or
            any(caracter not in "0123456789abcdef" for caracter in huella) or
            not paquete or len(paquete) > replica.MAX_TAMANO):
        raise replica.ErrorReplica("la respuesta de recuperación no es válida")
    return paquete, huella


def _recuperar_activo_desde(par):
    """Converge el activo desde el único nodo con cambios lógicos más nuevos."""
    def comprobar_activo():
        mando = quien_manda()
        if (mando.get("soy_yo") is not True or
                str(mando.get("activo") or "").casefold() != NODO.casefold()):
            raise replica.RolCambiado(
                "este nodo dejó de ser el activo durante la recuperación")

    comprobar_activo()
    paquete, huella_fuente = _pedir_snapshot(par)
    comprobar_activo()
    resultado = replica.aplicar(
        paquete, soy_el_activo=True, comprobar_activo=comprobar_activo)
    huella_local = _huella_logica()
    if not hmac.compare_digest(huella_local, huella_fuente):
        raise replica.ErrorReplica(
            "el estado aplicado no coincide con la fuente lógica elegida")
    return resultado


def _confirmar_sincronia_pares():
    """Heartbeat autenticado que no para NPM cuando el inventario ya coincide."""
    cuerpo = json.dumps({
        "schema": 1, "inventory_hash": _huella_sincronia(),
    }, separators=(",", ":")).encode()
    resultados = {}
    for par in PARES:
        try:
            mando = quien_manda()
            if (mando.get("soy_yo") is not True or
                    str(mando.get("activo") or "").casefold() != NODO.casefold()):
                raise replica.ErrorReplica(
                    "este nodo dejó de ser el activo antes del heartbeat")
            ruta = "/api/internal/sync-confirm"
            sobre = protocolo_cluster.cifrar(
                cuerpo, "sync-confirm", NODO, par["nombre"],
                contexto=_huella_topologia())
            pet, nonce = _peticion_interna(
                f"{par['url']}{ruta}", par["nombre"], sobre, "POST")
            pet.add_header("Content-Type", "application/json")
            with _abrir_http(pet, timeout=15) as respuesta:
                cifrado = respuesta.read()
            claro = protocolo_cluster.descifrar(
                cifrado, f"response:{ruta}", par["nombre"], NODO,
                contexto=nonce)
            respuesta = json.loads(claro.decode() or "{}")
            if (respuesta.get("topology_verified") is not True or
                    respuesta.get("topology_fingerprint") != _huella_topologia()):
                raise protocolo_cluster.ErrorProtocolo(
                    "el par no confirmó la membresía del clúster")
            resultados[par["nombre"]] = {"ok": True, **respuesta}
        except Exception as error:  # noqa: BLE001
            resultados[par["nombre"]] = {
                "ok": False, "error": type(error).__name__}
    return {**_resumen_quorum(resultados), "resultados": resultados}


def _empujar_a(par, datos):
    """Mandar el paquete a un par y esperar a que lo aplique."""
    mando = quien_manda()
    if (mando.get("soy_yo") is not True or
            str(mando.get("activo") or "").casefold() != NODO.casefold()):
        raise replica.ErrorReplica("este nodo ha dejado de ser el activo antes de enviar")
    ruta = "/api/internal/receive"
    sobre = protocolo_cluster.cifrar(
        datos, "replica", NODO, par["nombre"],
        contexto=_huella_topologia())
    pet, nonce = _peticion_interna(
        f"{par['url']}{ruta}", par["nombre"], datos=sobre, metodo="POST")
    pet.add_header("Content-Type", "application/json")
    # Generoso a propósito: al otro lado hay que parar NPM, copiar y arrancarlo.
    # Cortar a mitad dejaría un nodo con el estado a medias y sin saberlo.
    with _abrir_http(pet, timeout=300) as r:
        cifrado = r.read()
    claro = protocolo_cluster.descifrar(
        cifrado, f"response:{ruta}", par["nombre"], NODO, contexto=nonce)
    respuesta = json.loads(claro.decode() or "{}")
    if (respuesta.get("topology_verified") is not True or
            respuesta.get("topology_fingerprint") != _huella_topologia()):
        raise protocolo_cluster.ErrorProtocolo(
            "el receptor no confirmó la membresía del clúster")
    return respuesta


def sincronizar(forzar=False):
    """Una réplica cada vez. Lo que hace de verdad está en `_sincronizar`."""
    if not _candado_replica.acquire(blocking=False):
        return {"ok": False, "hecho": False,
                "motivo": "ya hay una réplica en marcha desde este servidor; espera a que acabe"}
    if not coordinacion.escritura_npm.acquire(blocking=False):
        _candado_replica.release()
        return {"ok": False, "hecho": False,
                "motivo": "NPM está procesando otra operación; vuelve a intentarlo"}
    try:
        return _sincronizar(forzar)
    finally:
        coordinacion.escritura_npm.release()
        _candado_replica.release()


def _sincronizar(forzar=False):
    """Llevar el estado de este nodo a todos los pasivos.

    Sólo lo hace el nodo que sostiene la dirección flotante. Si mandaran los
    pares, los pasivos estarían pisando con estado viejo lo que el activo acaba
    de hacer — que es precisamente lo que no puede pasar.

    Sin `forzar`, además se exige que este nodo gane TODO lo que difiere. Si un
    par tiene algo más nuevo, empujar lo perdería, y eso no se hace solo: se
    enseña en pantalla y lo decide una persona.
    """
    m = quien_manda()
    if m.get("soy_yo") is not True:
        return {"ok": False, "hecho": False,
                "motivo": f"aquí no se manda (manda «{m.get('activo') or 'nadie todavía'}»); "
                          f"la réplica sale siempre del nodo que sostiene la dirección"}

    estado_sinc = sincronia()

    if estado_sinc.get("nodos_incompatibles"):
        return {"ok": False, "hecho": False,
                "motivo": "hay nodos que responden pero no aceptan el contrato de "
                          "inventario; no se sobrescriben: " +
                          ", ".join(sorted(estado_sinc["nodos_incompatibles"])),
                "sincronia": estado_sinc}

    # «Los que contestaron coinciden» NO es «están todos al día». Un nodo mudo
    # se quedaba sin recibir y esto decía que no hacía falta hacer nada — justo
    # después de renovar, que es cuando más falta hace que le llegue.
    #
    # Si falta alguno por contestar se empuja igualmente: mandar a los que sí
    # están no rompe nada, y el que no contesta se marca como fallo para que
    # conste que no lo recibió.
    completa = estado_sinc.get("comparacion_completa", True)
    if estado_sinc.get("en_sincronia") and completa and not forzar:
        confirmacion = _confirmar_sincronia_pares()
        return {**confirmacion, "hecho": False,
                "motivo": ("todos los nodos ya tienen lo mismo" if
                           confirmacion.get("complete") else
                           "el inventario coincide, pero no todos confirmaron el heartbeat"),
                "sincronia": estado_sinc}

    if estado_sinc.get("conflictos") and not forzar:
        return {"ok": False, "hecho": False,
                "motivo": "hay cambios distintos con la misma marca temporal; "
                          "la réplica automática no puede elegir un ganador",
                "sincronia": estado_sinc}

    ganadores = set(estado_sinc.get("nodos_con_algo_ganador") or [])
    ganadores_logicos = set(
        estado_sinc.get("nodos_con_cambio_logico") or [])
    recuperado_de = None
    resultado_recuperacion = None

    # Los artefactos Nginx/Certbot viajan con el snapshot, pero no compiten con
    # una modificación lógica de NPM: Nginx reescribe ficheros al arrancar y su
    # mtime no expresa autoridad. Si todos los cambios lógicos más recientes
    # proceden de un único pasivo, el activo lo recupera automáticamente y
    # vuelve a distribuir un snapshot coherente. Así se cierra también la
    # ventana en la que hubo un failover antes del siguiente cron.
    otros_logicos = ganadores_logicos - {NODO}
    if not forzar and otros_logicos:
        if (estado_sinc.get("comparacion_completa") and
                not estado_sinc.get("conflictos") and
                len(ganadores_logicos) == 1):
            recuperado_de = next(iter(otros_logicos))
            par_fuente = _par_por_nombre(recuperado_de)
            if par_fuente is None:
                return {"ok": False, "hecho": False,
                        "motivo": f"el nodo fuente «{recuperado_de}» no pertenece a los pares",
                        "sincronia": estado_sinc}
            try:
                resultado_recuperacion = _recuperar_activo_desde(par_fuente)
            except (replica.ErrorReplica, urllib.error.URLError,
                    urllib.error.HTTPError, protocolo_cluster.ErrorProtocolo) as error:
                return {"ok": False, "hecho": False,
                        "motivo": f"no se pudo recuperar automáticamente desde "
                                  f"«{recuperado_de}»: {type(error).__name__}",
                        "sincronia": estado_sinc}
        else:
            return {"ok": False, "hecho": False,
                    "motivo": f"hay cambios lógicos repartidos entre "
                              f"{sorted(otros_logicos)}; no existe una fuente única segura",
                    "sincronia": estado_sinc}
    elif not forzar and not ganadores_logicos and ganadores - {NODO}:
        # Una diferencia exclusivamente de ficheros no permite inferir si se
        # trata de estado derivado o de material TLS no representado en SQLite.
        return {"ok": False, "hecho": False,
                "motivo": f"hay artefactos más nuevos en {sorted(ganadores - {NODO})}, "
                          "sin un cambio lógico que permita elegir la fuente",
                "sincronia": estado_sinc}

    try:
        paquete = replica.empaquetar()
    except replica.ErrorReplica as e:
        return {"ok": False, "hecho": False, "motivo": str(e)}

    resultados = {}
    if PARES and not protocolo_cluster.disponible():
        return {"ok": False, "hecho": False,
                "motivo": "falta NPMG_CLUSTER_TOKEN; la replica sin autenticar esta bloqueada"}

    for par in PARES:
        if (recuperado_de and
                str(par.get("nombre") or "").casefold() == recuperado_de.casefold()):
            resultados[par["nombre"]] = {
                "ok": True, "source_preserved": True,
            }
            continue
        try:
            resultados[par["nombre"]] = {"ok": True, **_empujar_a(par, paquete)}
        except urllib.error.HTTPError as e:
            detalle = ""
            try:
                detalle = json.loads(e.read().decode()).get("error", "")
            except Exception:  # noqa: BLE001
                detalle = ""
            resultados[par["nombre"]] = {"ok": False, "error": f"HTTP {e.code}. {detalle}"}
        except Exception as e:  # noqa: BLE001
            resultados[par["nombre"]] = {"ok": False, "error": type(e).__name__}

    bien = [b for b, r in resultados.items() if r.get("ok")]
    mal = [b for b, r in resultados.items() if not r.get("ok")]
    if mal:
        avisos.avisar(
            "NPM · réplica", "No se pudo replicar a algún servidor",
            f"Llegó a {len(bien)} de {len(resultados)}.", "warning",
            "Los que no la recibieron siguen con su estado anterior — no se ha roto nada, "
            "pero no están al día.\n\n"
            + "\n".join(f"{b}: {resultados[b].get('error')}" for b in mal))

    return {**_resumen_quorum(resultados), "hecho": bool(bien), "desde": NODO,
            "bytes": len(paquete), "resultados": resultados,
            "recuperado_de": recuperado_de,
            "recuperacion": resultado_recuperacion}


def _bandera(ruta, nombre):
    """¿Viene la bandera `nombre` en la consulta, y activada?

    Antes esto era `nombre in consulta`, un simple «¿aparece el texto?». Con eso,
    `?forzar=false` activaba el forzado — la palabra estaba ahí—. Y forzar la
    sincronización pisa el estado más nuevo de otro servidor, así que era la
    peor bandera posible para tener un «sí» accidental.
    """
    consulta = urllib.parse.parse_qs(urllib.parse.urlparse(ruta).query, keep_blank_values=True)
    if nombre not in consulta:
        return False
    valor = (consulta[nombre][0] or "").strip().lower()
    # Sin valor («?forzar») es sí; con valor, sólo lo que de verdad dice que sí.
    return valor in ("", "1", "si", "sí", "true", "yes")


def _replicar_configuracion_sin_candado():
    """Lleva ajustes, cuenta/2FA y ledger de renovación a los pasivos."""
    if not PARES:
        return {**_resumen_quorum({}), "resultados": {}}
    if not protocolo_cluster.disponible():
        return {"ok": False, "error": "falta NPMG_CLUSTER_TOKEN", "resultados": {}}
    cuerpo = json.dumps({
        "schema": 3,
        "topology_fingerprint": _huella_topologia(),
        "security_key_ids": configuracion.identificadores_secretos(),
        "configuration": configuracion.exportar(),
        "renewal_state": vigilante.exportar_estado_cluster(),
    }, ensure_ascii=False).encode()
    resultados = {}
    for par in PARES:
        try:
            mando = quien_manda()
            if (mando.get("soy_yo") is not True or
                    str(mando.get("activo") or "").casefold() != NODO.casefold()):
                raise protocolo_cluster.ErrorProtocolo(
                    "este nodo ha dejado de ser el activo antes de enviar")
            ruta = "/api/internal/config"
            sobre = protocolo_cluster.cifrar(
                cuerpo, "config", NODO, par["nombre"],
                contexto=_huella_topologia())
            pet, nonce = _peticion_interna(
                f"{par['url']}{ruta}", par["nombre"], sobre, "POST")
            pet.add_header("Content-Type", "application/json")
            with _abrir_http(pet, timeout=15) as r:
                cifrado = r.read()
            claro = protocolo_cluster.descifrar(
                cifrado, f"response:{ruta}", par["nombre"], NODO,
                contexto=nonce)
            respuesta = json.loads(claro.decode() or "{}")
            if (respuesta.get("topology_verified") is not True or
                    respuesta.get("topology_fingerprint") != _huella_topologia()):
                raise protocolo_cluster.ErrorProtocolo(
                    "el par no confirmó la membresía del clúster")
            resultados[par["nombre"]] = {"ok": True, **respuesta}
        except Exception as e:  # noqa: BLE001
            resultados[par["nombre"]] = {"ok": False, "error": type(e).__name__}
    return {**_resumen_quorum(resultados), "resultados": resultados}


def _replicar_configuracion():
    """Serializa paquetes para que dos cambios no lleguen fuera de orden."""
    with _candado_config_salida:
        return _replicar_configuracion_sin_candado()


def _confirmar_mutacion_config(anterior):
    """Replica una mutación ya hecha o la revierte con revisión superior.

    Debe llamarse bajo ``_candado_config_salida``. Así un secreto TOTP o unos
    códigos de recuperación no pueden quedar guardados sin que el usuario llegue
    a recibir su única copia en claro.
    """
    replicacion = _replicar_configuracion_sin_candado()
    if replicacion.get("ok"):
        return replicacion
    restaurada = configuracion.revertir_no_confirmada(anterior)
    replica_restauracion = _replicar_configuracion_sin_candado()
    replicacion["rollback"] = {
        "ok": True,
        "quorum": bool(replica_restauracion.get("ok")),
        "revision": restaurada.get("revision"),
        "replication": replica_restauracion,
    }
    return replicacion


def _reconciliar_guardian_desde_pares(exigir_quorum=False):
    """Antes de escribir como nuevo activo, adopta la revisión más reciente.

    Esto convierte una conmutación con un nodo rezagado en un cierre seguro:
    mientras no pueda consultar a los demás no consume códigos, cambia 2FA ni
    inicia renovaciones; cuando vuelven, recupera el estado monotónico mayor.
    """
    if not PARES:
        return {"ok": True, "consultados": [], "fallos": {}}
    if not _candado_reconciliacion_guardian.acquire(blocking=False):
        return {"ok": False, "error": "ya hay una reconciliación de Guardian en curso"}
    _candado_config_salida.acquire()
    try:
        mando = quien_manda()
        if mando.get("soy_yo") is not True:
            return {"ok": False, "error": "sólo el nodo activo puede reconciliar Guardian"}
        estados = [{
            "node": NODO,
            "configuration": configuracion.exportar(),
            "renewal_state": vigilante.exportar_estado_cluster(),
        }]
        fallos = {}
        for par in PARES:
            try:
                recibido = _pedir_interno(par, "/api/internal/state", 8)
                if recibido.get("topology_fingerprint") != _huella_topologia():
                    raise configuracion.ErrorConfiguracion(
                        "el par no acredita la misma membresía de clúster")
                if recibido.get("security_key_ids") != configuracion.identificadores_secretos():
                    raise configuracion.ErrorConfiguracion(
                        "los identificadores de secretos no coinciden")
                configuracion.validar_replica(recibido.get("configuration"))
                vigilante.validar_estado_cluster(recibido.get("renewal_state"))
                estados.append({"node": par["nombre"], **recibido})
            except Exception as error:  # noqa: BLE001
                fallos[par["nombre"]] = type(error).__name__
        quorum = _quorum_cluster()
        if exigir_quorum and len(estados) < quorum:
            return {"ok": False, "error": "no se alcanzó el quórum del clúster",
                    "consultados": [e["node"] for e in estados], "fallos": fallos,
                    "acknowledged": len(estados), "cluster_size": 1 + len(PARES),
                    "quorum": quorum}

        def elegir_configuracion_confirmada():
            """Elige contenido lógico respaldado por mayoría, nunca sólo max-rev."""
            grupos = {}
            revisiones = []
            for estado in estados:
                candidato = estado["configuration"]
                logico = {clave: valor for clave, valor in candidato.items()
                          if clave not in ("revision", "updated_at")}
                canonico_logico = json.dumps(
                    logico, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":")).encode()
                canonico_exacto = json.dumps(
                    candidato, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":")).encode()
                huella = hashlib.sha256(canonico_logico).hexdigest()
                grupo = grupos.setdefault(huella, {
                    "canonical": canonico_logico,
                    "documents": [],
                    "nodes": set(),
                })
                if grupo["canonical"] != canonico_logico:
                    raise configuracion.ErrorConfiguracion(
                        "colisión al comparar la configuración del clúster")
                grupo["documents"].append((candidato, canonico_exacto))
                grupo["nodes"].add(str(estado["node"]).casefold())
                revisiones.append(int(candidato["revision"]))
            mayorias = [grupo for grupo in grupos.values()
                        if len(grupo["nodes"]) >= quorum]
            if len(mayorias) != 1:
                raise configuracion.ErrorConfiguracion(
                    "ningún contenido de configuración está respaldado "
                    "por el quórum del clúster")
            elegida = mayorias[0]
            # Revision y updated_at son metadatos de causalidad, no votos. Dentro
            # del contenido ganador se elige siempre el mismo representante.
            documento, _canonico = max(
                elegida["documents"],
                key=lambda par: (
                    int(par[0]["revision"]), str(par[0]["updated_at"]),
                    hashlib.sha256(par[1]).hexdigest()))
            return (documento, int(documento["revision"]),
                    len(elegida["nodes"]), max(revisiones))

        (elegida_config, revision_mayoria, apoyo_config,
         revision_maxima_observada) = elegir_configuracion_confirmada()
        resultado_config = configuracion.imponer_confirmada(
            elegida_config, revision_minima=revision_maxima_observada)
        # La promoción inicial también es una escritura: sólo se hace después
        # de demostrar la mayoría exacta de revisión 1 y deberá alcanzar quorum
        # igual que cualquier rebase. Hacerla antes del majority-read rompería
        # artificialmente el empate entre dos nodos recién instalados.
        bootstrap = configuracion.promover_bootstrap_activo()
        bootstrap_cambiado = bool(bootstrap.get("changed"))
        if bootstrap_cambiado:
            resultado_config = {
                "ok": True, "revision": int(bootstrap["revision"]),
                "idempotent": False, "rebased": False,
                "bootstrap": True,
            }
        revision_config = int(resultado_config["revision"])
        elegido_ledger = vigilante.fusionar_estados_cluster(
            [estado["renewal_state"] for estado in estados])
        revision_ledger = int(elegido_ledger["revision"])
        ledger_cambiado = False
        if revision_ledger > int(vigilante.exportar_estado_cluster()["revision"]):
            vigilante.aplicar_estado_cluster(elegido_ledger)
            ledger_cambiado = True
        replica_convergencia = None
        if not resultado_config.get("idempotent") or ledger_cambiado:
            replica_convergencia = _replicar_configuracion_sin_candado()
            # Un rebase crea la revisión que cercará al huérfano. Hasta que esa
            # revisión no alcance mayoría, esta reconciliación no puede autorizar
            # login ni otra mutación sensible.
            if ((resultado_config.get("rebased") or bootstrap_cambiado) and
                    not replica_convergencia.get("ok")):
                return {
                    "ok": False,
                    "error": "la configuración confirmada no pudo volver a fijarse en un quórum",
                    "consultados": [e["node"] for e in estados], "fallos": fallos,
                    "acknowledged": replica_convergencia.get("acknowledged", 1),
                    "cluster_size": 1 + len(PARES), "quorum": quorum,
                    "configuration_revision": revision_config,
                    "configuration_majority_revision": revision_mayoria,
                    "configuration_support": apoyo_config,
                    "convergence_replication": replica_convergencia,
                }
        resultado = {"ok": True, "consultados": [e["node"] for e in estados],
                     "fallos": fallos, "configuration_revision": revision_config,
                     "configuration_majority_revision": revision_mayoria,
                     "configuration_support": apoyo_config,
                     "ledger_revision": revision_ledger,
                     "acknowledged": len(estados), "cluster_size": 1 + len(PARES),
                     "quorum": quorum, "complete": not fallos,
                     "convergence_replication": replica_convergencia}
        configuracion.guardar_estado_operativo({
            "last_guardian_reconciliation": time.time(),
            "last_guardian_reconciliation_result": resultado,
        })
        return resultado
    except (configuracion.ErrorConfiguracion, vigilante.ErrorEstado,
            ValueError, TypeError) as error:
        return {"ok": False, "error": str(error), "fallos": {}}
    finally:
        _candado_config_salida.release()
        _candado_reconciliacion_guardian.release()


def _arrancar_reconciliacion_guardian():
    """Cura el estado propio aunque la réplica de NPM esté desactivada."""
    intervalo = max(15, int(os.environ.get("NPMG_GUARDIAN_SYNC_SECONDS", "30")))

    def bucle():
        time.sleep(5)
        while True:
            try:
                if quien_manda().get("soy_yo") is True:
                    previo = _reconciliar_guardian_desde_pares(exigir_quorum=True)
                    if previo.get("ok"):
                        _replicar_configuracion()
            except Exception as error:  # noqa: BLE001
                print(f"guardian-sync: {type(error).__name__}: {error}", flush=True)
            time.sleep(intervalo)

    threading.Thread(target=bucle, name="guardian-state-sync", daemon=True).start()


def _sincronizacion_programada(_forzar=False):
    """El cron reconcilia tanto NPM como el estado propio de Guardian."""
    convergencia = _reconciliar_guardian_desde_pares(exigir_quorum=True)
    if not convergencia.get("ok"):
        bloqueado = {"ok": False, "hecho": False,
                     "motivo": "no se confirmó la membresía y el estado de Guardian"}
        return {"ok": False, "guardian": {"reconciliation": convergencia},
                "npm": bloqueado}
    replicacion_guardian = _replicar_configuracion()
    estado_guardian = {"ok": bool(replicacion_guardian.get("ok")),
                       "reconciliation": convergencia,
                       "replication": replicacion_guardian}
    if not estado_guardian["ok"]:
        bloqueado = {"ok": False, "hecho": False,
                     "motivo": "el estado de Guardian no alcanzó quorum topológico"}
        return {"ok": False, "guardian": estado_guardian, "npm": bloqueado}
    estado_npm = sincronizar(False)
    return {"ok": bool(estado_guardian.get("ok") and estado_npm.get("ok")),
            "guardian": estado_guardian, "npm": estado_npm}


def _traducir_error_npm(error):
    mapas = {
        "invalid_credentials": ("INVALID_CREDENTIALS", 401),
        "admin_required": ("NPM_ADMIN_REQUIRED", 403),
        "unavailable": ("NPM_AUTH_UNAVAILABLE", 503),
        "invalid_response": ("NPM_AUTH_INVALID_RESPONSE", 502),
        "reauth_required": ("NPM_REAUTH_REQUIRED", 401),
    }
    codigo, http = mapas.get(error.codigo, ("NPM_AUTH_ERROR", 502))
    return seguridad.ErrorAcceso(str(error), codigo, http)


def _autenticar_con_npm(usuario, clave, origen="?"):
    mando = quien_manda()
    if mando.get("soy_yo") is not True or not mando.get("activo"):
        raise seguridad.ErrorAcceso("No se puede determinar el NPM activo",
                                    "ACTIVE_NODE_UNKNOWN", 503)
    seguridad.asegurar_intentos(origen)
    try:
        return npm_api.autenticar_usuario(mando["activo"], usuario, clave)
    except npm_api.ErrorNPM as error:
        if error.codigo == "invalid_credentials":
            seguridad.registrar_fallo(origen)
        raise _traducir_error_npm(error) from None


def _reautenticar_cuenta(clave, origen="?"):
    cuenta = configuracion.leer().get("account") or {}
    perfil_npm = _autenticar_con_npm(cuenta.get("username"), clave, origen)
    cuenta = seguridad.confirmar_identidad_npm(perfil_npm)
    seguridad.limpiar_fallos(origen)
    return cuenta


def estado_publico(url_activa=None):
    """Lo unico visible sin sesion en un pasivo."""
    mando = quien_manda()
    try:
        npm.salud_base()
        npm_ok = True
        error = None
    except npm.SinBaseDeDatos as e:
        npm_ok, error = False, str(e)
    try:
        contenedor = dockerd.estado(replica.CONTENEDOR)
    except dockerd.ErrorDocker as error_docker:
        contenedor = {"existe": False, "corriendo": False,
                      "error": str(error_docker)}
    operativo = configuracion.estado_operativo()
    ultima_aplicada = operativo.get("last_received_sync")
    ultima_verificada = operativo.get("last_verified_sync")
    marcas = [float(valor) for valor in (ultima_aplicada, ultima_verificada) if valor]
    ultima = max(marcas, default=None)
    if ultima_verificada and (not ultima_aplicada or
                              float(ultima_verificada) >= float(ultima_aplicada)):
        resultado_recepcion = operativo.get("last_verified_sync_result") or {}
    else:
        resultado_recepcion = operativo.get("last_received_sync_result") or {}
    max_edad = max(900, int(os.environ.get("NPMG_SYNC_STALE_SECONDS", "93600")))
    reciente = bool(ultima and time.time() - float(ultima) <= max_edad)
    receptor = dockerd.disponible() and contenedor.get("existe")
    npm_api_ok = npm_api.api_responde(NODO, timeout=3)
    preparado = bool(npm_ok and npm_api_ok and contenedor.get("corriendo") and receptor and
                     reciente and resultado_recepcion.get("ok") and
                     resultado_recepcion.get("topology_verified") is True and
                     resultado_recepcion.get("topology_fingerprint") ==
                     _huella_topologia())
    return {
        "product": "NPM Guardian", "version": VERSION, "node": NODO,
        "role": ("active" if mando.get("soy_yo") is True else
                 "passive" if mando.get("soy_yo") is False else "unknown"),
        "active_node": mando.get("activo"), "floating_ip": mando.get("ip"),
        "reason": mando.get("origen"), "active_url": url_activa,
        "setup_required": not bool(configuracion.leer().get("account")),
        "health": {"guardian": True, "npm": npm_ok,
                   "npm_api": npm_api_ok,
                   "npm_container": contenedor,
                   "replication_receiver": receptor,
                   "last_replica_recent": reciente,
                   "ready": preparado, "detail": error},
        "last_sync": ultima,
        "last_sync_result": resultado_recepcion,
    }


class Manejador(BaseHTTPRequestHandler):
    server_version = "npm-guardian"
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, formato, *args):
        pass

    def _proxy_confiable(self):
        try:
            cliente = ipaddress.ip_address(self.client_address[0])
            return any(cliente in red for red in REDES_PROXY)
        except ValueError:
            return False

    def _canal_https(self):
        if not self._proxy_confiable():
            return False
        valores = (self.headers.get("X-Forwarded-Proto") or "").split(",")
        return len(valores) == 1 and valores[0].strip().lower() == "https"

    def _exigir_canal_sensible(self):
        if PERMITIR_PORTAL_INSEGURO or self._canal_https():
            return True
        self._problema(
            "El acceso sensible requiere HTTPS mediante un proxy de confianza",
            426, "HTTPS_REQUIRED")
        return False

    def _cabeceras_seguridad(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                         "script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        if self._canal_https():
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def _json(self, datos, codigo=200, cabeceras=None):
        cuerpo = json.dumps(datos, ensure_ascii=False, indent=2).encode()
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        self._cabeceras_seguridad()
        for nombre, valor in (cabeceras or {}).items():
            self.send_header(nombre, valor)
        self.end_headers()
        self.wfile.write(cuerpo)

    def _problema(self, mensaje, codigo_http=400, codigo="REQUEST_REJECTED"):
        return self._json({"error": mensaje, "code": codigo,
                           "detail": {"code": codigo, "message": mensaje}}, codigo_http)

    def _estatico(self, ruta):
        if ruta in ("", "/"):
            ruta = "/index.html" if quien_manda().get("soy_yo") is True else "/passive.html"
        elif ruta == "/index.html" and quien_manda().get("soy_yo") is not True:
            ruta = "/passive.html"
        destino = os.path.join(DIR_WEB, os.path.normpath(ruta).lstrip("/\\"))
        if (os.path.commonpath((os.path.abspath(destino), os.path.abspath(DIR_WEB))) !=
                os.path.abspath(DIR_WEB) or not os.path.isfile(destino)):
            return self._problema("No existe", 404, "NOT_FOUND")
        with open(destino, "rb") as f:
            cuerpo = f.read()
        self.send_response(200)
        self.send_header("Content-Type", TIPOS.get(os.path.splitext(destino)[1],
                                                   "application/octet-stream"))
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-cache")
        self._cabeceras_seguridad()
        self.end_headers()
        self.wfile.write(cuerpo)

    def _url_activa(self, mando=None):
        fija = (os.environ.get("NPMG_PUBLIC_URL") or "").strip().rstrip("/")
        if fija:
            return fija + "/"
        mando = mando or quien_manda()
        ip = mando.get("ip")
        if not ip:
            return None
        esquema = "https" if self._canal_https() else "http"
        puerto = "" if ((esquema == "http" and PUERTO_PUBLICO == 80) or
                        (esquema == "https" and PUERTO_PUBLICO == 443)) else f":{PUERTO_PUBLICO}"
        return f"{esquema}://{ip}{puerto}/"

    def _json_interno(self, datos, destino, ruta, contexto, codigo=200):
        claro = json.dumps(datos, ensure_ascii=False).encode()
        return self._bytes_interno(claro, destino, ruta, contexto, codigo)

    def _bytes_interno(self, claro, destino, ruta, contexto, codigo=200):
        sobre = protocolo_cluster.cifrar(
            claro, f"response:{ruta}", NODO, destino, contexto=contexto)
        return self._json(json.loads(sobre.decode()), codigo)

    def _autenticar_interna(self, ruta, cuerpo=b""):
        try:
            return protocolo_cluster.verificar(
                self.command, ruta, self.headers, NODO, cuerpo,
                origenes=[par["nombre"] for par in PARES])
        except protocolo_cluster.ErrorProtocolo as error:
            self._problema(str(error), 401, "CLUSTER_AUTH_REQUIRED")
            return None

    def _emisor_es_activo(self, identidad):
        mando = quien_manda()
        if mando.get("soy_yo") is not False:
            self._problema(
                "No se acepta estado sin confirmar que este nodo es pasivo: " +
                str(mando.get("origen") or "sin motivo"), 409,
                "PASSIVE_ROLE_REQUIRED")
            return None
        if (str(mando.get("activo") or "").casefold() !=
                str(identidad.get("source") or "").casefold()):
            self._problema(
                "El emisor firmado no es el nodo activo actual", 409,
                "ACTIVE_SOURCE_REQUIRED")
            return None
        return mando

    def _identidad(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie") or "")
            token = cookie.get(seguridad.COOKIE)
            return seguridad.sesiones.leer(token.value if token else None)
        except Exception:  # noqa: BLE001
            return None

    def _exigir_activo(self):
        mando = quien_manda()
        if mando.get("soy_yo") is True:
            return mando
        self._problema(
            "El portal completo solo esta disponible en el nodo activo.", 409,
            "PASSIVE_NODE" if mando.get("soy_yo") is False else "ACTIVE_NODE_UNKNOWN")
        return None

    def _exigir_sesion(self, mutacion=False):
        identidad = self._identidad()
        if not identidad:
            self._problema("Inicia sesion para continuar", 401, "AUTH_REQUIRED")
            return None
        if mutacion:
            csrf = self.headers.get("X-CSRF-Token") or ""
            if not csrf or not hmac.compare_digest(csrf, identidad.csrf):
                self._problema("Falta el token CSRF de la sesion", 403, "CSRF_REQUIRED")
                return None
            cuenta = configuracion.leer().get("account") or {}
            mando = quien_manda()
            try:
                npm_api.validar_token_usuario(
                    mando.get("activo"), identidad.npm_token,
                    cuenta.get("npm_user_id"))
            except npm_api.ErrorNPM as error:
                traducido = _traducir_error_npm(error)
                self._problema(str(traducido), traducido.http, traducido.codigo)
                return None
        return identidad

    def _leer_cuerpo(self, maximo):
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise ValueError("Transfer-Encoding no está permitido")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError as e:
            self.close_connection = True
            raise ValueError("Content-Length no es valido") from e
        if n <= 0 or n > maximo:
            self.close_connection = True
            raise ValueError("el cuerpo esta vacio o es demasiado grande")
        cuerpo = self.rfile.read(n)
        if len(cuerpo) != n:
            self.close_connection = True
            raise ValueError("el cuerpo de la petición llegó incompleto")
        return cuerpo

    def _leer_json(self, maximo=1024 * 1024):
        cuerpo = self._leer_cuerpo(maximo)
        try:
            datos = json.loads(cuerpo.decode())
        except (ValueError, UnicodeError) as e:
            raise ValueError("el cuerpo JSON no es valido") from e
        if not isinstance(datos, dict):
            raise ValueError("el cuerpo debe ser un objeto JSON")
        return datos

    def _leer_crudo(self, maximo):
        return self._leer_cuerpo(maximo)

    def _cookie_sesion(self, token):
        segura = (not PERMITIR_PORTAL_INSEGURO) or self._canal_https()
        valor = f"{seguridad.COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={seguridad.sesiones.duracion}"
        return valor + ("; Secure" if segura else "")

    def _cookie_borrar(self):
        segura = (not PERMITIR_PORTAL_INSEGURO) or self._canal_https()
        valor = f"{seguridad.COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        return valor + ("; Secure" if segura else "")

    def do_GET(self):
        ruta = self.path.split("?")[0]
        try:
            if ruta == "/api/health":
                return self._json({"status": "ok"})
            if ruta == "/api/version":
                return self._json({"product": "NPM Guardian", "version": VERSION})
            if ruta == "/api/bootstrap/status":
                return self._json({"required": False, "version": VERSION})
            if ruta == "/api/public/status":
                return self._json(estado_publico(self._url_activa()))

            if ruta.startswith("/api/internal/"):
                identidad = self._autenticar_interna(ruta)
                if not identidad:
                    return
                if ruta == "/api/internal/local":
                    return self._json_interno(
                        vista_local(), identidad["source"], ruta, identidad["nonce"])
                if ruta == "/api/internal/inventario":
                    inv = inventario.inventario()
                    inv["nodo"] = NODO
                    return self._json_interno(
                        inv, identidad["source"], ruta, identidad["nonce"])
                if ruta == "/api/internal/export":
                    if not self._emisor_es_activo(identidad):
                        return
                    if not protocolo_cluster.consumir_nonce(
                            identidad["nonce"], identidad["timestamp"]):
                        return self._problema(
                            "la exportación interna ya fue procesada", 409,
                            "CLUSTER_REPLAY_DETECTED")
                    return self._exportar_replica(identidad, ruta)
                if ruta == "/api/internal/state":
                    if not self._emisor_es_activo(identidad):
                        return
                    return self._json_interno({
                        "topology_fingerprint": _huella_topologia(),
                        "security_key_ids": configuracion.identificadores_secretos(),
                        "configuration": configuracion.exportar(),
                        "renewal_state": vigilante.exportar_estado_cluster(),
                    }, identidad["source"], ruta, identidad["nonce"])
                return self._problema("No existe", 404, "NOT_FOUND")

            if ruta == "/api/session":
                if not self._exigir_activo():
                    return
                identidad = self._exigir_sesion()
                return self._json(seguridad.sesion_publica(identidad)) if identidad else None

            if ruta.startswith("/api/"):
                if not self._exigir_activo():
                    return
                identidad = self._exigir_sesion()
                if not identidad:
                    return
                if ruta == "/api/mando":
                    return self._json(quien_manda())
                if ruta == "/api/certificados":
                    return self._json({"certificados": npm.certificados()})
                if ruta == "/api/dominios":
                    return self._json({"dominios": npm.dominios()})
                if ruta == "/api/vigilancia":
                    return self._json(vigilante.ultimo())
                if ruta == "/api/namecheap":
                    return self._json(namecheap.comprobar())
                if ruta == "/api/credenciales":
                    return self._json(credenciales_desincronizadas())
                if ruta == "/api/sincronia":
                    return self._json(sincronia())
                if ruta == "/api/estado":
                    return self._json(cuadro())
                if ruta == "/api/config":
                    publica = configuracion.ajustes_publicos()
                    publica["sync"]["next_run"] = planificador.siguiente(publica["sync"]["cron"])
                    publica["node_settings"] = arranque.ajustes_publicos()
                    publica["topology"] = {
                        "node": NODO, "peers": [p["nombre"] for p in PARES],
                        "keepalived_url": PANEL_IP, "keepalived_service": SERVICIO_FLOTANTE,
                        "cluster_token_configured": bool(configuracion.TOKEN_CLUSTER),
                    }
                    return self._json(publica)
                if ruta == "/api/profile":
                    return self._json(seguridad.perfil())
                return self._problema("No existe", 404, "NOT_FOUND")
            return self._estatico(ruta)
        except npm.SinBaseDeDatos as e:
            return self._problema(str(e), 503, "NPM_DATABASE_UNAVAILABLE")
        except Exception as e:  # noqa: BLE001
            return self._problema(f"{type(e).__name__}: {e}", 500, "INTERNAL_ERROR")

    def _exportar_replica(self, identidad, ruta):
        """Entrega al activo una copia estable del pasivo elegido como fuente."""
        if not _candado_recibir.acquire(blocking=False):
            return self._problema(
                "el nodo fuente está recibiendo otra réplica", 409,
                "REPLICATION_BUSY")
        if not coordinacion.escritura_npm.acquire(blocking=False):
            _candado_recibir.release()
            return self._problema(
                "NPM está procesando otra operación", 409,
                "NPM_WRITE_BUSY")
        try:
            def comprobar_fuente_pasiva():
                mando = quien_manda()
                if (mando.get("soy_yo") is not False or
                        str(mando.get("activo") or "").casefold() !=
                        str(identidad["source"]).casefold()):
                    raise replica.RolCambiado(
                        "el nodo fuente cambió de rol durante la exportación")

            comprobar_fuente_pasiva()
            huella_antes = _huella_logica()
            paquete = replica.empaquetar()
            comprobar_fuente_pasiva()
            huella_despues = _huella_logica()
            if not hmac.compare_digest(huella_antes, huella_despues):
                raise replica.ErrorReplica(
                    "NPM cambió durante la exportación; se reintentará después")
            return self._bytes_interno(
                huella_despues.encode("ascii") + b"\n" + paquete,
                identidad["source"], ruta, identidad["nonce"])
        except replica.ErrorReplica as error:
            return self._problema(str(error), 409, "INVALID_REPLICA_SOURCE")
        finally:
            coordinacion.escritura_npm.release()
            _candado_recibir.release()

    def _recibir_replica(self, datos, identidad, ruta, topologia_verificada=False):
        if not _candado_recibir.acquire(blocking=False):
            return self._problema("ya se esta aplicando otra replica", 409, "REPLICATION_BUSY")
        try:
            def comprobar_pasivo():
                mando = quien_manda()
                if mando.get("soy_yo") is True:
                    raise replica.RolCambiado(
                        "el receptor fue promovido mientras aplicaba la réplica")
                if (mando.get("soy_yo") is not False or
                        str(mando.get("activo") or "").casefold() !=
                        str(identidad["source"]).casefold()):
                    raise replica.ErrorReplica(
                        "el papel del clúster cambió antes de aplicar la réplica")

            comprobar_pasivo()
            resultado = replica.aplicar(
                datos, soy_el_activo=False, comprobar_pasivo=comprobar_pasivo)
            resultado["topology_verified"] = bool(topologia_verificada)
            resultado["topology_fingerprint"] = (
                _huella_topologia() if topologia_verificada else None)
            configuracion.guardar_estado_operativo({"last_received_sync": time.time(),
                                                     "last_received_sync_result": resultado})
            return self._json_interno(
                resultado, identidad["source"], ruta, identidad["nonce"])
        except replica.ErrorReplica as e:
            return self._problema(str(e), 409, "INVALID_REPLICA")
        except dockerd.ErrorDocker as e:
            return self._problema(str(e), 503, "DOCKER_UNAVAILABLE")
        finally:
            _candado_recibir.release()

    def _recibir_config(self, paquete, identidad, ruta, topologia_verificada=False):
        if not _candado_config_recepcion.acquire(blocking=False):
            return self._problema(
                "ya se está aplicando otro estado de Guardian", 409,
                "CLUSTER_CONFIG_BUSY")
        try:
            contrato_v2 = (isinstance(paquete, dict) and paquete.get("schema") == 2 and
                           set(paquete) == {"schema", "security_key_ids",
                                            "configuration", "renewal_state"})
            contrato_v3 = (isinstance(paquete, dict) and paquete.get("schema") == 3 and
                           set(paquete) == {"schema", "topology_fingerprint",
                                            "security_key_ids", "configuration",
                                            "renewal_state"})
            if (not (contrato_v2 or contrato_v3) or
                    paquete.get("security_key_ids") !=
                    configuracion.identificadores_secretos() or
                    (contrato_v3 and (
                        not topologia_verificada or
                        paquete.get("topology_fingerprint") != _huella_topologia()))):
                return self._problema(
                    "configuración interna no válida", 422,
                    "INVALID_CLUSTER_CONFIG")
            # v2 sólo permite que un activo antiguo mantenga pasivos v1 durante
            # el rolling upgrade. Nunca produce un ACK apto para el quorum v1.
            if contrato_v2 and topologia_verificada:
                return self._problema(
                    "el esquema 2 no puede acreditar la topología v1", 422,
                    "LEGACY_CLUSTER_CONFIG")
            # Se validan las dos mitades antes de escribir ninguna. Después se
            # aplica primero la configuración: si es obsoleta, tampoco se toca
            # el ledger de renovaciones.
            configuracion.validar_replica(paquete["configuration"])
            vigilante.validar_estado_cluster(paquete["renewal_state"])
            resultado = configuracion.aplicar_replica(paquete["configuration"])
            resultado["renewal_state"] = vigilante.aplicar_estado_cluster(
                paquete["renewal_state"])
            resultado["topology_verified"] = bool(contrato_v3 and topologia_verificada)
            resultado["topology_fingerprint"] = (
                _huella_topologia() if resultado["topology_verified"] else None)
            configuracion.guardar_estado_operativo({
                "last_received_config": time.time(),
                "last_received_config_revision": resultado.get("revision"),
                "last_received_ledger_revision":
                    resultado["renewal_state"].get("revision"),
            })
            return self._json_interno(
                resultado, identidad["source"], ruta, identidad["nonce"])
        except (configuracion.ErrorConfiguracion, vigilante.ErrorEstado,
                ValueError, TypeError) as error:
            return self._problema(str(error), 409, "STALE_CLUSTER_STATE")
        finally:
            _candado_config_recepcion.release()

    def _recibir_confirmacion_sincronia(self, paquete, identidad, ruta,
                                        topologia_verificada=False):
        if (not isinstance(paquete, dict) or
                set(paquete) != {"schema", "inventory_hash"} or
                paquete.get("schema") != 1 or
                not isinstance(paquete.get("inventory_hash"), str) or
                len(paquete["inventory_hash"]) != 64):
            return self._problema(
                "confirmación de sincronía no válida", 422,
                "INVALID_SYNC_CONFIRMATION")
        local = _huella_sincronia()
        if not hmac.compare_digest(local, paquete["inventory_hash"]):
            return self._problema(
                "el inventario local ya no coincide con el activo", 409,
                "SYNC_CONFIRMATION_MISMATCH")
        resultado = {
            "ok": True, "inventory_hash": local,
            "topology_verified": bool(topologia_verificada),
            "topology_fingerprint": (
                _huella_topologia() if topologia_verificada else None),
        }
        configuracion.guardar_estado_operativo({
            "last_verified_sync": time.time(),
            "last_verified_sync_result": resultado,
        })
        return self._json_interno(
            resultado, identidad["source"], ruta, identidad["nonce"])

    def do_POST(self):
        ruta = self.path.split("?")[0]
        try:
            if ruta in ("/api/internal/receive", "/api/internal/config",
                        "/api/internal/sync-confirm"):
                maximo = (replica.MAX_TAMANO * 2 if ruta.endswith("receive")
                          else 2 * 1024 * 1024)
                cuerpo = self._leer_crudo(maximo)
                identidad = self._autenticar_interna(ruta, cuerpo)
                if not identidad or not self._emisor_es_activo(identidad):
                    return
                tipo = ("replica" if ruta.endswith("receive") else
                        "sync-confirm" if ruta.endswith("sync-confirm") else
                        "config")
                try:
                    claro, topologia_verificada = _descifrar_escritura_interna(
                        cuerpo, tipo, identidad)
                except protocolo_cluster.ErrorProtocolo as error:
                    return self._problema(str(error), 401, "INVALID_CLUSTER_ENVELOPE")
                if not protocolo_cluster.consumir_nonce(
                        identidad["nonce"], identidad["timestamp"]):
                    return self._problema(
                        "la operación interna ya fue procesada", 409,
                        "CLUSTER_REPLAY_DETECTED")
                if ruta == "/api/internal/receive":
                    if len(claro) > replica.MAX_TAMANO:
                        return self._problema(
                            f"paquete demasiado grande ({len(claro)} bytes)", 413)
                    return self._recibir_replica(
                        claro, identidad, ruta, topologia_verificada)
                # Se revalida después de abrir el sobre y justo antes de escribir.
                if not self._emisor_es_activo(identidad):
                    return
                try:
                    paquete_config = json.loads(claro.decode())
                except (ValueError, UnicodeError):
                    return self._problema(
                        "configuración interna no válida", 422,
                        "INVALID_CLUSTER_CONFIG")
                if ruta == "/api/internal/sync-confirm":
                    return self._recibir_confirmacion_sincronia(
                        paquete_config, identidad, ruta, topologia_verificada)
                return self._recibir_config(
                    paquete_config, identidad, ruta, topologia_verificada)

            if not self._exigir_canal_sensible():
                return

            if ruta == "/api/session":
                if not self._exigir_activo():
                    return
                convergencia = _reconciliar_guardian_desde_pares(exigir_quorum=True)
                if not convergencia.get("ok"):
                    return self._problema(
                        "No se puede alcanzar el quórum de seguridad del clúster",
                        503, "CLUSTER_STATE_UNAVAILABLE")
                datos = self._leer_json(32 * 1024)
                if datos.get("emergency"):
                    mando = quien_manda()
                    if npm_api.autenticacion_disponible(mando.get("activo")):
                        raise seguridad.ErrorAcceso(
                            "NPM esta disponible; utiliza el acceso normal",
                            "NPM_AUTH_AVAILABLE", 409)
                    perfil_npm = None
                else:
                    perfil_npm = _autenticar_con_npm(
                        datos.get("username"), datos.get("password"), self.client_address[0])
                with _candado_config_salida:
                    anterior = configuracion.exportar()
                    try:
                        if datos.get("emergency"):
                            token, identidad, cambiado = seguridad.iniciar_emergencia(
                                datos.get("username"), datos.get("recovery_code") or "",
                                self.client_address[0])
                        else:
                            token, identidad, cambiado = seguridad.iniciar_npm(
                                perfil_npm, datos.get("otp") or "", self.client_address[0])
                    except Exception:
                        if (int(configuracion.exportar().get("revision") or 0) !=
                                int(anterior.get("revision") or 0)):
                            configuracion.revertir_no_confirmada(anterior)
                            _replicar_configuracion_sin_candado()
                        raise
                    replica_config = (_confirmar_mutacion_config(anterior)
                                      if cambiado else None)
                if cambiado and not replica_config.get("ok"):
                    return self._problema(
                        "El cambio de seguridad no alcanzó quórum y fue revertido; "
                        "no se ha abierto la sesión",
                        503, "CLUSTER_STATE_NOT_REPLICATED")
                return self._json({**seguridad.sesion_publica(identidad),
                                   "config_replication": replica_config},
                                  cabeceras={"Set-Cookie": self._cookie_sesion(token)})

            if not self._exigir_activo():
                return
            identidad = self._exigir_sesion(mutacion=True)
            if not identidad:
                return
            rutas_sensibles = {
                "/api/config", "/api/node-config", "/api/profile", "/api/profile/2fa/setup",
                "/api/profile/2fa/enable", "/api/profile/2fa/disable",
                "/api/profile/2fa/recovery-codes", "/api/sincronizar",
                "/api/revisar",
            }
            if ruta in rutas_sensibles or ruta.startswith("/api/renovar/"):
                convergencia = _reconciliar_guardian_desde_pares(exigir_quorum=True)
                if not convergencia.get("ok"):
                    return self._problema(
                        "No se puede alcanzar el quórum de seguridad del clúster",
                        503, "CLUSTER_STATE_UNAVAILABLE")

            if ruta == "/api/config":
                entrada = self._leer_json()
                with _candado_config_salida:
                    anterior = configuracion.exportar()
                    configuracion.guardar_ajustes(entrada)
                    replicacion = _confirmar_mutacion_config(anterior)
                if not replicacion.get("ok"):
                    return self._problema(
                        "La configuración no alcanzó quórum y fue revertida",
                        503, "CLUSTER_STATE_NOT_REPLICATED")
                return self._json({"settings": configuracion.ajustes_publicos(),
                                   "replication": replicacion})
            if ruta == "/api/node-config":
                entrada = self._leer_json()
                ajustes = arranque.actualizar(entrada)
                self._json({"settings": ajustes, "restarting": True})
                threading.Thread(
                    target=_reiniciar_desde_configuracion, daemon=True).start()
                return
            if ruta == "/api/profile":
                datos = self._leer_json(32 * 1024)
                with _candado_config_salida:
                    anterior = configuracion.exportar()
                    perfil = seguridad.actualizar_perfil(datos.get("display_name"))
                    replicacion = _confirmar_mutacion_config(anterior)
                if not replicacion.get("ok"):
                    return self._problema("El perfil no alcanzó quórum y fue revertido",
                                          503, "CLUSTER_STATE_NOT_REPLICATED")
                return self._json({"profile": perfil, "replication": replicacion})
            if ruta == "/api/profile/password":
                return self._problema(
                    "La contraseña se administra desde Nginx Proxy Manager",
                    409, "PASSWORD_MANAGED_BY_NPM")
            if ruta == "/api/profile/2fa/setup":
                datos = self._leer_json(32 * 1024)
                _reautenticar_cuenta(datos.get("current_password") or "",
                                     self.client_address[0])
                with _candado_config_salida:
                    anterior = configuracion.exportar()
                    salida = seguridad.preparar_2fa()
                    salida["replication"] = _confirmar_mutacion_config(anterior)
                if not salida["replication"].get("ok"):
                    return self._problema("La preparación 2FA no alcanzó quórum y fue revertida",
                                          503, "CLUSTER_STATE_NOT_REPLICATED")
                return self._json(salida)
            if ruta == "/api/profile/2fa/enable":
                datos = self._leer_json(32 * 1024)
                with _candado_config_salida:
                    anterior = configuracion.exportar()
                    cuenta, codigos = seguridad.activar_2fa(datos.get("code") or "")
                    token, identidad_nueva = seguridad.sesiones.crear(
                        cuenta, identidad.npm_token)
                    replicacion = _confirmar_mutacion_config(anterior)
                if not replicacion.get("ok"):
                    return self._problema("2FA no alcanzó quórum y fue revertido; conserva los códigos anteriores",
                                          503, "CLUSTER_STATE_NOT_REPLICATED")
                return self._json({"profile": seguridad.perfil(cuenta),
                                   "recovery_codes": codigos,
                                   "replication": replicacion},
                                  cabeceras={"Set-Cookie": self._cookie_sesion(token)})
            if ruta == "/api/profile/2fa/disable":
                datos = self._leer_json(32 * 1024)
                _reautenticar_cuenta(datos.get("current_password") or "",
                                     self.client_address[0])
                with _candado_config_salida:
                    anterior = configuracion.exportar()
                    cuenta = seguridad.desactivar_2fa(datos.get("code") or "")
                    token, identidad_nueva = seguridad.sesiones.crear(
                        cuenta, identidad.npm_token)
                    replicacion = _confirmar_mutacion_config(anterior)
                if not replicacion.get("ok"):
                    return self._problema("La desactivación 2FA no alcanzó quórum y fue revertida",
                                          503, "CLUSTER_STATE_NOT_REPLICATED")
                return self._json({"profile": seguridad.perfil(cuenta),
                                   "replication": replicacion},
                                  cabeceras={"Set-Cookie": self._cookie_sesion(token)})
            if ruta == "/api/profile/2fa/recovery-codes":
                datos = self._leer_json(32 * 1024)
                _reautenticar_cuenta(datos.get("current_password") or "",
                                     self.client_address[0])
                with _candado_config_salida:
                    anterior = configuracion.exportar()
                    codigos = seguridad.regenerar_recuperacion(datos.get("code") or "")
                    replicacion = _confirmar_mutacion_config(anterior)
                if not replicacion.get("ok"):
                    return self._problema(
                        "Los códigos nuevos no alcanzaron quórum; se descartaron y los anteriores siguen vigentes",
                        503, "CLUSTER_STATE_NOT_REPLICATED")
                return self._json({"recovery_codes": codigos,
                                   "replication": replicacion})
            if ruta.startswith("/api/renovar/"):
                try:
                    idc = int(ruta.rsplit("/", 1)[1])
                except ValueError:
                    return self._problema("identificador no valido", 400)
                mando = quien_manda()
                certificados = {c["id"]: c for c in npm.certificados()}
                if idc not in certificados:
                    return self._problema(f"no hay ningun certificado {idc}", 404)
                certificado = certificados[idc]
                resultado = vigilante.renovar(
                    idc, certificado["nombre"], mando["activo"], manual=True,
                    dominios=certificado.get("dominios"))
                return self._json(resultado)
            if ruta == "/api/sincronizar":
                resultado = sincronizar(forzar=_bandera(self.path, "forzar"))
                configuracion.guardar_estado_operativo({"last_manual_sync": time.time(),
                                                        "last_manual_sync_result": resultado})
                return self._json(resultado)
            if ruta == "/api/revisar":
                return self._json(vigilante.revisar(
                    mando=quien_manda(), forzar_aviso=_bandera(self.path, "forzar")))
            return self._problema("No existe", 404, "NOT_FOUND")
        except seguridad.ErrorAcceso as e:
            return self._problema(str(e), e.http, e.codigo)
        except (configuracion.ErrorConfiguracion, planificador.ErrorCron, ValueError) as e:
            return self._problema(str(e), 422, "INVALID_CONFIGURATION")
        except Exception as e:  # noqa: BLE001
            return self._problema(f"{type(e).__name__}: {e}", 500, "INTERNAL_ERROR")

    def do_DELETE(self):
        ruta = self.path.split("?")[0]
        try:
            if not self._exigir_canal_sensible():
                return
            if ruta == "/api/session":
                return self._json({}, 200, cabeceras={
                    "Set-Cookie": self._cookie_borrar()})
            if not self._exigir_activo():
                return
            identidad = self._exigir_sesion(mutacion=True)
            if not identidad:
                return
            if ruta == "/api/profile/2fa/setup":
                convergencia = _reconciliar_guardian_desde_pares(exigir_quorum=True)
                if not convergencia.get("ok"):
                    return self._problema(
                        "No se puede alcanzar el quórum de seguridad del clúster",
                        503, "CLUSTER_STATE_UNAVAILABLE")
                with _candado_config_salida:
                    anterior = configuracion.exportar()
                    seguridad.cancelar_2fa()
                    replicacion = _confirmar_mutacion_config(anterior)
                if not replicacion.get("ok"):
                    return self._problema(
                        "La cancelación 2FA no alcanzó quórum y fue revertida",
                        503, "CLUSTER_STATE_NOT_REPLICATED")
                return self._json({"ok": True, "replication": replicacion})
            return self._problema("No existe", 404, "NOT_FOUND")
        except Exception as e:  # noqa: BLE001
            return self._problema(f"{type(e).__name__}: {e}", 500, "INTERNAL_ERROR")

class Servidor(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def handle_error(self, request, client_address):
        # Una pestaña que se cierra produce un ConnectionResetError. Sin esto,
        # cada una escupe una traza y ahoga el log que hace falta leer cuando
        # algo va mal de verdad.
        import sys
        import traceback
        exc = sys.exc_info()[0]
        if exc and issubclass(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return
        traceback.print_exc()


def _validar_transporte():
    if TOKEN_KEEPALIVED and (
            len(TOKEN_KEEPALIVED) > 4096 or
            any(ord(caracter) <= 32 or ord(caracter) == 127
                for caracter in TOKEN_KEEPALIVED)):
        raise configuracion.ErrorConfiguracion(
            "NPMG_KEEPALIVED_API_TOKEN no admite espacios ni caracteres de control")
    if not PERMITIR_PORTAL_INSEGURO:
        if not REDES_PROXY:
            raise configuracion.ErrorConfiguracion(
                "configura NPMG_TRUSTED_PROXY_IPS para el proxy HTTPS o autoriza "
                "explícitamente NPMG_ALLOW_INSECURE_PORTAL=1")
        publica = (os.environ.get("NPMG_PUBLIC_URL") or "").strip()
        if publica and urllib.parse.urlparse(publica).scheme.lower() != "https":
            raise configuracion.ErrorConfiguracion(
                "NPMG_PUBLIC_URL debe usar https en el perfil seguro")
    if (not MODO_INDEPENDIENTE and
            urllib.parse.urlparse(PANEL_IP).scheme.lower() == "http" and
            not PERMITIR_KEEPALIVED_INSEGURO):
        raise configuracion.ErrorConfiguracion(
            "la API de Keepalived debe usar HTTPS o declarar "
            "NPMG_ALLOW_INSECURE_KEEPALIVED_API=1")
    npm_api.esquema_api()


def main():
    configuracion.validar_secretos()
    topologia = _validar_topologia()
    _validar_transporte()
    recuperacion = replica.recuperar_transaccion()
    if recuperacion.get("recovered"):
        print(f"  réplica interrumpida recuperada: {recuperacion.get('action')}", flush=True)
    print(f"NPM Guardian · nodo={NODO} · versión={VERSION} · puerto={PUERTO}", flush=True)
    print(f"  base de datos de NPM: {npm.RUTA_DB}", flush=True)
    print(f"  panel de direcciones: {PANEL_IP}", flush=True)
    print(f"  pares: {[p['nombre'] for p in PARES] or 'ninguno'}", flush=True)
    print(f"  topología: {topologia['members']} · {topologia['fingerprint'][:12]}",
          flush=True)
    print(f"  autenticacion: {'lista' if seguridad.sesiones.disponible else 'NO CONFIGURADA'}",
          flush=True)
    print(f"  canal de cluster cifrado: {'sí' if protocolo_cluster.disponible() else 'NO'}",
          flush=True)
    try:
        print(f"  inventario: {npm.resumen()}", flush=True)
    except npm.SinBaseDeDatos as e:
        print(f"  ⚠ no se puede leer NPM: {e}", flush=True)
    print(f"  socket de Docker: {'sí' if dockerd.disponible() else 'NO — este nodo no puede recibir réplica'}",
          flush=True)
    vigilante.usar_replicador(sincronizar)
    vigilante.usar_autoridad(quien_manda)
    vigilante.usar_replicador_estado(_replicar_configuracion)
    _arrancar_reconciliacion_guardian()
    vigilante.arrancar_bucle(quien_manda)
    planificador.arrancar(_sincronizacion_programada, quien_manda)
    ajustes = configuracion.ajustes_publicos()
    print(f"  vigilancia cada {vigilante.INTERVALO}s · aviso a {ajustes['renewal']['warning_days']} días",
          flush=True)
    print(f"  sincronizacion: {ajustes['sync']['cron'] if ajustes['sync']['enabled'] else 'desactivada'}",
          flush=True)
    Servidor(("0.0.0.0", PUERTO), Manejador).serve_forever()  # nosec B104


if __name__ == "__main__":
    main()
