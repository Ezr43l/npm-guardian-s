"""Reintentar lo que fallo, sin gastar nunca el ultimo cartucho.

Una renovacion que falla no se puede olvidar hasta la siguiente vuelta: si falla
por algo pasajero —una propagacion lenta, un corte de red— hay que volver a
intentarlo. Pero cada intento cuesta cuota en Let's Encrypt, asi que se hace con
freno y con cuenta.

LOS TOPES DE LET'S ENCRYPT y lo que nos permitimos:

    5 validaciones fallidas por dominio y hora   ->  nosotros, 4
    5 emisiones del mismo conjunto por semana    ->  nosotros, 4

Se deja SIEMPRE uno sin usar. Ese es para ti: el dia que estes delante mirando
por que no renueva, quieres poder darle al boton y que no te lo bloquee el
propio guardian por haberse gastado la cuota reintentando solo.
"""
import hashlib
import json
import time

import configuracion

# Los topes reales de Let's Encrypt, para que el motivo quede escrito al lado
# del numero y nadie lo suba «porque si» dentro de un ano.
TOPE_LE_FALLOS_HORA = 5
TOPE_LE_EMISIONES_SEMANA = 5

MAX_FALLOS_HORA = TOPE_LE_FALLOS_HORA - 1
MAX_INTENTOS_SEMANA = TOPE_LE_EMISIONES_SEMANA - 1

HORA = 3600
SEMANA = 7 * 24 * 3600

# Cuanto se espera antes de cada reintento. El primero tarda mas de una hora a
# proposito: la cache negativa de DNS de esta zona dura 3601 segundos, asi que
# reintentar antes es tirar un cartucho a la basura.
ESPERAS = [90 * 60, 6 * 3600, 24 * 3600]


def max_intentos():
    """El usuario puede ser mas conservador, nunca superar el tope seguro."""
    elegido = int(configuracion.leer()["settings"]["renewal"].get(
        "max_automatic_attempts") or MAX_INTENTOS_SEMANA)
    return max(1, min(MAX_INTENTOS_SEMANA, elegido))


def _podar(marcas, ventana, ahora):
    return [t for t in marcas if ahora - t < ventana]


def normalizar_san(dominios, respaldo=""):
    salida = set()
    for dominio in (dominios or []):
        texto = str(dominio or "").strip().rstrip(".").casefold()
        if not texto:
            continue
        comodin = texto.startswith("*.")
        base = texto[2:] if comodin else texto
        try:
            base = base.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        salida.add(("*." if comodin else "") + base)
    if not salida and respaldo:
        salida.add(str(respaldo).strip().rstrip(".").casefold())
    return sorted(salida)


def clave_san(dominios, respaldo=""):
    """Clave estable por conjunto exacto de identificadores, no por fila SQL."""
    canonicos = normalizar_san(dominios, respaldo)
    canon = json.dumps(canonicos, separators=(",", ":"), ensure_ascii=False).encode()
    return "san:" + hashlib.sha256(canon).hexdigest()


def identificadores_fallo(dominios, respaldo=""):
    """Buckets de autorización de LE; wildcard y apex comparten nombre base."""
    return sorted({dominio[2:] if dominio.startswith("*.") else dominio
                   for dominio in normalizar_san(dominios, respaldo)})


def _fallos_por_identificador(estado, clave, dominios, ahora):
    entrada_objetivo = (estado.get("reintentos") or {}).get(str(clave)) or {}
    objetivo = set(identificadores_fallo(
        dominios or entrada_objetivo.get("domains") or []))
    if not objetivo:
        return {str(clave): len(_podar(
            entrada_objetivo.get("fallos", []), HORA, ahora))}
    cuentas = {identificador: 0 for identificador in objetivo}
    for clave_entrada, entrada in (estado.get("reintentos") or {}).items():
        ids_entrada = set(identificadores_fallo(entrada.get("domains") or []))
        if not ids_entrada and str(clave_entrada) == str(clave):
            ids_entrada = objetivo
        comunes = objetivo & ids_entrada
        if not comunes:
            continue
        cantidad = len(_podar(entrada.get("fallos", []), HORA, ahora))
        for identificador in comunes:
            cuentas[identificador] += cantidad
    return cuentas


def _emision_ambigua_solapada(estado, clave, dominios):
    entrada_objetivo = (estado.get("reintentos") or {}).get(str(clave)) or {}
    objetivo = set(identificadores_fallo(
        dominios or entrada_objetivo.get("domains") or []))
    for clave_entrada, entrada in (estado.get("reintentos") or {}).items():
        if ((entrada.get("reconciliacion") or {}).get("estado") not in
                ("en_curso", "indeterminado")):
            continue
        ids_entrada = set(identificadores_fallo(entrada.get("domains") or []))
        if not ids_entrada and str(clave_entrada) == str(clave):
            ids_entrada = objetivo
        if not objetivo or objetivo & ids_entrada:
            return True
    return False


def _entrada(estado, clave, id_cert=None, dominios=None):
    todos = estado.setdefault("reintentos", {})
    r = todos.setdefault(str(clave), {"intentos": [], "fallos": [], "agotado": False})
    if id_cert is not None:
        r["certificate_id"] = int(id_cert)
    if dominios is not None:
        r["domains"] = normalizar_san(dominios)
    return r


def registrar_intento(estado, clave, ok, ahora=None, id_cert=None, dominios=None):
    """Anota un intento y decide cuando seria el siguiente."""
    ahora = ahora or time.time()
    r = _entrada(estado, clave, id_cert, dominios)

    r["intentos"] = _podar(r["intentos"], SEMANA, ahora) + [ahora]
    if ok:
        # El éxito NO borra la ventana semanal: cinco emisiones válidas también
        # consumen la cuota de certificados duplicados de Let's Encrypt.
        r["fallos"] = _podar(r.get("fallos", []), HORA, ahora)
        r.pop("reconciliacion", None)
        r.pop("siguiente", None)
        r["agotado"] = False
        r["completed_at"] = ahora
        return {"siguiente": None, "agotado": False, "motivo": "renovado"}

    r["fallos"] = _podar(r["fallos"], HORA, ahora) + [ahora]
    n = len(r["intentos"])
    if n < max_intentos() and n - 1 < len(ESPERAS):
        r["siguiente"] = ahora + ESPERAS[n - 1]
        r["agotado"] = False
    else:
        r["siguiente"] = None
        r["agotado"] = True
    return {"siguiente": r.get("siguiente"), "agotado": r["agotado"], "intentos": n}


def registrar_en_curso(estado, clave, caducidad_anterior, ahora=None,
                       id_cert=None, dominios=None):
    """Reserva globalmente un intento antes de enviar la petición."""
    ahora = ahora or time.time()
    r = _entrada(estado, clave, id_cert, dominios)
    r["intentos"] = _podar(r.get("intentos", []), SEMANA, ahora) + [ahora]
    r["fallos"] = _podar(r.get("fallos", []), HORA, ahora)
    r["siguiente"] = None
    r["agotado"] = False
    r.pop("completed_at", None)
    r["reconciliacion"] = {
        "estado": "en_curso",
        "desde": ahora,
        "caducidad_anterior": caducidad_anterior,
    }
    return dict(r["reconciliacion"])


def marcar_indeterminado(estado, clave):
    r = (estado.get("reintentos") or {}).get(str(clave))
    if not r or not r.get("reconciliacion"):
        raise ValueError("no existe un intento en curso que reconciliar")
    r["reconciliacion"]["estado"] = "indeterminado"
    return dict(r["reconciliacion"])


def resolver_indeterminado(estado, clave, correcto, ahora=None):
    """Cierra una petición ambigua sin contar una segunda emisión."""
    ahora = ahora or time.time()
    todos = estado.setdefault("reintentos", {})
    r = todos.get(str(clave))
    if not r:
        return {"siguiente": None, "agotado": False}
    if correcto:
        r["fallos"] = _podar(r.get("fallos", []), HORA, ahora)
        r.pop("reconciliacion", None)
        r.pop("siguiente", None)
        r["agotado"] = False
        r["completed_at"] = ahora
        return {"siguiente": None, "agotado": False, "motivo": "reconciliado"}

    r.pop("completed_at", None)
    r["fallos"] = _podar(r.get("fallos", []), HORA, ahora) + [ahora]
    reconciliacion = r.get("reconciliacion") or {}
    reconciliacion["estado"] = "fallo_confirmado"
    reconciliacion["confirmado_en"] = ahora
    r["reconciliacion"] = reconciliacion
    n = len(_podar(r.get("intentos", []), SEMANA, ahora))
    if n < max_intentos() and n - 1 < len(ESPERAS):
        r["siguiente"] = ahora + ESPERAS[max(0, n - 1)]
        r["agotado"] = False
    else:
        r["siguiente"] = None
        r["agotado"] = True
    return {"siguiente": r.get("siguiente"), "agotado": r["agotado"],
            "intentos": n}


def toca_reintentar(estado, clave, ahora=None, dominios=None):
    """(bool, motivo). Solo True si toca por tiempo Y queda cuota de sobra."""
    ahora = ahora or time.time()
    r = (estado.get("reintentos") or {}).get(str(clave))
    if not r:
        return False, "no hay ningun fallo pendiente"
    if r.get("agotado"):
        return False, ("agotados los reintentos automaticos; queda un intento "
                       "reservado para que lo lances tu a mano")
    if (r.get("reconciliacion") or {}).get("estado") in ("en_curso", "indeterminado"):
        return False, "el resultado anterior sigue pendiente de reconciliar; no se reemite"
    if r.get("completed_at") and ahora - float(r["completed_at"]) < SEMANA:
        return False, "el mismo conjunto SAN ya se emitió durante la ventana semanal"
    siguiente = r.get("siguiente")
    if siguiente and ahora < siguiente:
        faltan = int(siguiente - ahora)
        return False, f"el siguiente reintento es en {faltan // 60} minutos"

    fallos_por_id = _fallos_por_identificador(estado, clave, dominios, ahora)
    identificador, fallos = max(fallos_por_id.items(), key=lambda par: par[1])
    if fallos >= MAX_FALLOS_HORA:
        return False, (f"{fallos} fallos para {identificador} en la ultima hora; "
                       f"el tope de Let's Encrypt es "
                       f"{TOPE_LE_FALLOS_HORA} y nos paramos en {MAX_FALLOS_HORA}")

    intentos = len(_podar(r.get("intentos", []), SEMANA, ahora))
    if intentos >= max_intentos():
        return False, (f"{intentos} intentos esta semana; el tope de Let's Encrypt es "
                       f"{TOPE_LE_EMISIONES_SEMANA} y nos paramos en {max_intentos()}")

    return True, "toca"


def puede_intentar(estado, clave, manual=False, ahora=None, dominios=None):
    """Guardia final de cuota para cualquier vía que pueda emitir.

    La vía manual puede usar el quinto intento reservado, pero nunca superar
    los topes públicos de Let's Encrypt ni repetir una emisión ambigua.
    """
    ahora = ahora or time.time()
    r = (estado.get("reintentos") or {}).get(str(clave))
    if _emision_ambigua_solapada(estado, clave, dominios):
        return False, "hay una emisión solapada pendiente de reconciliar"
    fallos_por_id = _fallos_por_identificador(estado, clave, dominios, ahora)
    identificador, fallos = max(fallos_por_id.items(), key=lambda par: par[1])
    limite_fallos = TOPE_LE_FALLOS_HORA if manual else MAX_FALLOS_HORA
    if fallos >= limite_fallos:
        return False, (f"{fallos} fallos para {identificador} en la última hora; "
                       "no queda cuota segura "
                       "para otro intento")
    if not r:
        return True, "primer intento"
    intentos = len(_podar(r.get("intentos", []), SEMANA, ahora))
    limite_intentos = TOPE_LE_EMISIONES_SEMANA if manual else max_intentos()
    if intentos >= limite_intentos:
        return False, (f"{intentos} intentos esta semana; no queda cuota segura "
                       "para otro intento")
    if manual:
        return True, "intento manual dentro del tope absoluto"
    return toca_reintentar(estado, clave, ahora, dominios)


def cuota(estado, clave, ahora=None, dominios=None):
    """Cuanto queda, para poder enseñarlo en el panel."""
    ahora = ahora or time.time()
    r = (estado.get("reintentos") or {}).get(str(clave)) or {}
    fallos_por_id = _fallos_por_identificador(estado, clave, dominios, ahora)
    fallos = max(fallos_por_id.values(), default=0)
    intentos = len(_podar(r.get("intentos", []), SEMANA, ahora))
    return {
        "fallos_ultima_hora": fallos,
        "fallos_por_identificador": fallos_por_id,
        "nos_paramos_en": MAX_FALLOS_HORA,
        "intentos_esta_semana": intentos,
        "tope_semana": max_intentos(),
        "reservado_para_ti": TOPE_LE_EMISIONES_SEMANA - max_intentos(),
        "agotado": bool(r.get("agotado")),
        "siguiente_reintento": r.get("siguiente"),
    }


def pendientes(estado, ahora=None):
    """Los que tienen un reintento programado, para enseñarlos."""
    ahora = ahora or time.time()
    salida = []
    for clave, r in (estado.get("reintentos") or {}).items():
        if r.get("completed_at") and not r.get("reconciliacion"):
            continue
        salida.append({
            "id": r.get("certificate_id"),
            "quota_key": clave,
            "intentos": len(_podar(r.get("intentos", []), SEMANA, ahora)),
            "agotado": bool(r.get("agotado")),
            "siguiente": r.get("siguiente"),
            "estado": (r.get("reconciliacion") or {}).get("estado", "fallo"),
            "faltan_minutos": (int((r["siguiente"] - ahora) // 60)
                               if r.get("siguiente") and r["siguiente"] > ahora else 0),
        })
    return salida


def tiene_fallo_pendiente(estado, clave):
    r = (estado.get("reintentos") or {}).get(str(clave)) or {}
    return bool(r and not r.get("completed_at"))


def migrar_clave(estado, anterior, nueva, id_cert, dominios):
    """Migra el ledger por ID antiguo al SAN y fusiona de forma conservadora."""
    todos = estado.setdefault("reintentos", {})
    if str(anterior) == str(nueva) or str(anterior) not in todos:
        return False
    vieja = todos.pop(str(anterior))
    actual = todos.get(str(nueva), {})
    combinada = {**vieja, **actual}
    combinada["intentos"] = sorted(set(
        list(vieja.get("intentos") or []) + list(actual.get("intentos") or [])))
    combinada["fallos"] = sorted(set(
        list(vieja.get("fallos") or []) + list(actual.get("fallos") or [])))
    combinada["agotado"] = bool(vieja.get("agotado") or actual.get("agotado"))
    siguientes = [v for v in (vieja.get("siguiente"), actual.get("siguiente")) if v]
    if siguientes:
        combinada["siguiente"] = max(siguientes)
    reconciliaciones = [v for v in (vieja.get("reconciliacion"),
                                    actual.get("reconciliacion")) if v]
    if reconciliaciones:
        combinada["reconciliacion"] = max(
            reconciliaciones, key=lambda v: float(v.get("desde") or 0))
    completados = [v for v in (vieja.get("completed_at"), actual.get("completed_at")) if v]
    if completados:
        combinada["completed_at"] = max(completados)
    combinada["certificate_id"] = int(id_cert)
    combinada["domains"] = normalizar_san(dominios)
    todos[str(nueva)] = combinada
    return True
