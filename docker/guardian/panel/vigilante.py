"""El vigilante: mira cada hora y avisa SOLO cuando algo cambia.

Dos cosas que vigilar:

  1. Si Namecheap aceptaria una renovacion desde la IP publica de ahora.
  2. Si algun certificado se acerca a su caducidad.

La regla de oro es avisar por CAMBIO de estado, no por estado. Un aviso cada
hora diciendo lo mismo se ignora a las dos veces, y entonces no sirve el dia que
de verdad importa.

El estado se guarda en disco para que un reinicio del contenedor no vuelva a
avisar de lo mismo — ni se calle algo que paso mientras estaba parado.
"""
import copy
import json
import os
import threading
import time

import avisos
import configuracion
import coordinacion
import dockerd
import namecheap
import npm
import npm_api
import reintentos

RUTA_ESTADO = os.path.join(os.environ.get("NPMG_DATA_DIR", os.environ.get(
    "NPMHA_DATOS", "/datos")), "vigilancia.json")
RUTA_ESTADO_BACKUP = RUTA_ESTADO + ".bak"
INTERVALO = int(os.environ.get("NPMG_WATCH_INTERVAL", os.environ.get("NPMHA_INTERVALO", "3600")))

# Un certificado por debajo de esto ya deberia haberse renovado solo: si sigue
# ahi, algo no funciona y hay que mirarlo.
DIAS_AVISO = int(os.environ.get("NPMG_WARNING_DAYS", os.environ.get("NPMHA_DIAS_AVISO", "15")))


# Se renueva ANTES de que NPM lo haga por su cuenta (el renueva a 30 dias). Asi
# lo hace el nodo activo y de forma deterministica, en vez de que gane el
# temporizador que salte primero. En cuanto ese nodo renueva, la fecha nueva se
# replica y los demas ya no ven nada pendiente.
DIAS_RENOVAR = int(os.environ.get("NPMG_RENEW_DAYS", os.environ.get("NPMHA_DIAS_RENOVAR", "35")))
ESPERA_ACTIVACION = max(5, int(os.environ.get("NPMG_TLS_ACTIVATION_TIMEOUT", "30")))
INTERVALO_ACTIVACION = max(1, int(os.environ.get("NPMG_TLS_ACTIVATION_INTERVAL", "2")))
ESPERA_RECONCILIACION = max(10, int(os.environ.get(
    "NPMG_RENEW_RECONCILE_TIMEOUT", "90")))


class ErrorAutoridad(RuntimeError):
    """El nodo ya no posee la IP flotante y no puede iniciar una emisión."""


class ErrorEstado(RuntimeError):
    """El ledger de cuota no se puede leer o persistir con seguridad."""


_consultar_mando = None
_candado_renovacion = threading.Lock()
_candado_estado = threading.RLock()


def dias_aviso():
    return int(configuracion.leer()["settings"]["renewal"].get("warning_days") or DIAS_AVISO)


def dias_renovar():
    return int(configuracion.leer()["settings"]["renewal"].get(
        "days_before_expiry") or DIAS_RENOVAR)


def _activar_certificado(id_certificado, host_activo):
    """Hace que Nginx cargue el certificado emitido y confirma el TLS real."""
    inicial = npm.comprobar_certificado_servido(id_certificado, host_activo)
    activacion = {
        "ok": bool(inicial.get("ok")),
        "reload_attempted": False,
        "reload_ok": False,
        "checks": 1,
    }
    # Sin proxy host activo no hay ningun endpoint que recargar ni comprobar.
    if inicial.get("ok"):
        activacion["reload_ok"] = True
        return inicial, activacion

    if not inicial.get("verificable"):
        activacion["error"] = inicial.get("motivo")
        return inicial, activacion

    activacion["reload_attempted"] = True
    try:
        dockerd.recargar_nginx()
        activacion["reload_ok"] = True
    except dockerd.ErrorDocker as e:
        activacion["error"] = str(e)
        return inicial, activacion

    limite = time.monotonic() + ESPERA_ACTIVACION
    ultimo = inicial
    while time.monotonic() < limite:
        time.sleep(min(INTERVALO_ACTIVACION, max(0, limite - time.monotonic())))
        ultimo = npm.comprobar_certificado_servido(id_certificado, host_activo)
        activacion["checks"] += 1
        if ultimo.get("ok"):
            activacion["ok"] = True
            return ultimo, activacion
    return ultimo, activacion


def _clave_cuota(dominios, nombre):
    return reintentos.clave_san(dominios, respaldo=nombre)


def _registrar_resultado(clave_cuota, id_certificado, dominios, correcto):
    est = leer_estado()
    if (est.get("reintentos") or {}).get(str(clave_cuota), {}).get("reconciliacion"):
        plan = reintentos.resolver_indeterminado(est, clave_cuota, correcto)
    else:
        plan = reintentos.registrar_intento(
            est, clave_cuota, correcto, id_cert=id_certificado, dominios=dominios)
    guardar_estado(est)
    plan["replication"] = _replicar_estado_cluster() if _replicar_estado_cluster else None
    return plan


def usar_autoridad(fn):
    global _consultar_mando
    _consultar_mando = fn


def _asegurar_autoridad(host_activo):
    # Las pruebas unitarias pueden usar el módulo aislado. En el servidor real
    # se inyecta siempre antes de aceptar peticiones.
    if _consultar_mando is None:
        return
    mando = _consultar_mando()
    if (mando.get("soy_yo") is not True or
            str(mando.get("activo") or "").casefold() != str(host_activo or "").casefold()):
        raise ErrorAutoridad(
            "este nodo ya no sostiene la IP flotante; la renovación no se ha enviado")


def _certificado_cambio(anterior, actual):
    if not anterior or not actual:
        return False
    huella_anterior = anterior.get("fingerprint")
    huella_actual = actual.get("fingerprint")
    if huella_anterior and huella_actual:
        return huella_actual != huella_anterior
    return bool(actual.get("caduca") and actual.get("caduca") != anterior.get("caduca"))


def _esperar_resultado(id_certificado, anterior):
    limite = time.monotonic() + ESPERA_RECONCILIACION
    while time.monotonic() < limite:
        actual = npm.estado_certificado(id_certificado)
        if _certificado_cambio(anterior, actual):
            return actual
        time.sleep(min(3, max(0, limite - time.monotonic())))
    return None


def _finalizar_emision(id_certificado, nombre, host_activo, respuesta,
                       reconciliada=False, clave_cuota=None, dominios=None):
    """Activa y verifica una emisión que ya consta como terminada."""
    try:
        _asegurar_autoridad(host_activo)
    except ErrorAutoridad as error:
        return {"ok": False, "hecho": True, "emision_ok": True,
                "code": "ACTIVE_ROLE_LOST_AFTER_ISSUANCE",
                "id": id_certificado, "nombre": nombre, "error": str(error),
                "reconciliada": reconciliada}
    try:
        servido, activacion = _activar_certificado(id_certificado, host_activo)
    except Exception as e:  # noqa: BLE001
        servido = {"ok": False, "verificable": False,
                   "motivo": f"no se pudo completar la comprobacion TLS ({type(e).__name__})"}
        activacion = {"ok": False, "reload_attempted": False,
                      "reload_ok": False, "checks": 0, "error": str(e)}

    try:
        _asegurar_autoridad(host_activo)
    except ErrorAutoridad as error:
        return {"ok": False, "hecho": True, "emision_ok": True,
                "code": "ACTIVE_ROLE_LOST_AFTER_ISSUANCE",
                "id": id_certificado, "nombre": nombre, "error": str(error),
                "reconciliada": reconciliada, "servido": servido,
                "activacion": activacion}

    try:
        replica_npm = (_replicar() if _replicar is not None else
                       {"ok": True, "complete": True, "resultados": {}})
    except Exception as error:  # noqa: BLE001
        replica_npm = {"ok": False, "error": type(error).__name__}
    if not replica_npm.get("ok"):
        aviso = avisos.avisar(
            "NPM · certificados", f"Renovado, pendiente de réplica: {nombre}",
            "El certificado cambió en el activo, pero aún no está duradero en un quórum.",
            "warning",
            f"Certificado: {nombre}\nServidor: {host_activo}\n\n"
            "No se solicitará otra emisión mientras Guardian reconcilia este resultado.")
        return {"ok": False, "hecho": True, "emision_ok": True,
                "code": "RENEWAL_DATA_NOT_REPLICATED", "id": id_certificado,
                "nombre": nombre, "respuesta": respuesta, "servido": servido,
                "activacion": activacion, "replication": replica_npm,
                "error": "el certificado nuevo aún no alcanzó el quórum de datos",
                "aviso": aviso, "reconciliada": reconciliada}

    try:
        _asegurar_autoridad(host_activo)
    except ErrorAutoridad as error:
        return {"ok": False, "hecho": True, "emision_ok": True,
                "code": "ACTIVE_ROLE_LOST_AFTER_ISSUANCE",
                "id": id_certificado, "nombre": nombre, "error": str(error),
                "reconciliada": reconciliada, "servido": servido,
                "activacion": activacion, "replication": replica_npm}

    clave_cuota = clave_cuota or _clave_cuota(dominios, nombre)
    plan = _registrar_resultado(
        clave_cuota, id_certificado, dominios or [], True)
    replica_ledger = plan.get("replication")
    if replica_ledger is not None and not replica_ledger.get("ok"):
        aviso = avisos.avisar(
            "NPM · certificados", f"Renovado, pendiente de confirmar: {nombre}",
            "El certificado ya se sirve y sus datos están replicados, pero el ledger no "
            "alcanzó quórum.", "warning",
            f"Certificado: {nombre}\nServidor: {host_activo}\n\n"
            "Guardian conservará el resultado y no repetirá la emisión localmente.")
        return {"ok": False, "hecho": True, "emision_ok": True,
                "code": "RENEWAL_LEDGER_NOT_CONFIRMED", "id": id_certificado,
                "nombre": nombre, "respuesta": respuesta, "servido": servido,
                "activacion": activacion, "replication": replica_npm,
                "ledger_replication": replica_ledger, "aviso": aviso,
                "error": "el resultado aún no alcanzó el quórum del ledger",
                "reconciliada": reconciliada}

    if activacion.get("ok"):
        recarga = ("Nginx se recargo y sirve el certificado nuevo." if
                   activacion.get("reload_attempted") else
                   "Nginx ya servia el certificado nuevo; no hizo falta otra recarga.")
        aviso = avisos.avisar(
            "NPM · certificados", f"Renovado y servido: {nombre}",
            "La renovacion se completo y el certificado nuevo ya esta activo.",
            "normal",
            f"Certificado: {nombre}\nServidor: {host_activo}\n\n"
            f"Guardado: {servido.get('caduca_guardado')}\n"
            f"Servido: {servido.get('caduca_servido')}\n\n{recarga}")
    else:
        error_recarga = activacion.get("error")
        detalle = (f"La recarga no pudo completarse: {error_recarga}" if error_recarga else
                   "Nginx acepto la recarga, pero la comprobacion TLS sigue viendo otro certificado.")
        aviso = avisos.avisar(
            "NPM · certificados", f"Renovado, pero aun no se sirve: {nombre}",
            servido.get("motivo"), "warning",
            f"Certificado: {nombre}\nServidor: {host_activo}\n\n"
            f"Guardado: {servido.get('caduca_guardado')}\n"
            f"Servido: {servido.get('caduca_servido')}\n\n{detalle}\n\n"
            "La emision ya termino y no se solicitara otra automaticamente.")

    return {"ok": True, "emision_ok": True, "id": id_certificado, "nombre": nombre,
            "respuesta": respuesta, "reconciliada": reconciliada,
            "servido": servido, "activacion": activacion, "aviso": aviso,
            "replication": replica_npm,
            "ledger_replication": plan.get("replication")}


def renovar(id_certificado, nombre, host_activo, manual=False, dominios=None):
    """Emite, activa y verifica; toda vía manual o automática comparte cerrojo."""
    if not _candado_renovacion.acquire(blocking=False):
        return {"ok": False, "hecho": False, "code": "RENEWAL_BUSY",
                "id": id_certificado, "nombre": nombre,
                "error": "ya hay otra renovación en curso"}
    if not coordinacion.escritura_npm.acquire(blocking=False):
        _candado_renovacion.release()
        return {"ok": False, "hecho": False, "code": "NPM_OPERATION_BUSY",
                "id": id_certificado, "nombre": nombre,
                "error": "NPM está preparando o aplicando una réplica"}
    try:
        return _renovar(id_certificado, nombre, host_activo, manual=manual,
                        dominios=dominios)
    finally:
        coordinacion.escritura_npm.release()
        _candado_renovacion.release()


def _renovar(id_certificado, nombre, host_activo, manual=False, dominios=None):
    """Implementación protegida de la renovación."""
    resultado_ya_esperado = False
    try:
        _asegurar_autoridad(host_activo)
        anterior = npm.estado_certificado(id_certificado)
        if not anterior:
            raise npm_api.ErrorNPM("el certificado ya no existe")
        clave_cuota = _clave_cuota(dominios, nombre)
        estado = leer_estado()
        estado_antes_de_reservar = copy.deepcopy(estado)
        permitido, motivo_cuota = reintentos.puede_intentar(
            estado, clave_cuota, manual=manual, dominios=dominios)
        if not permitido:
            return {"ok": False, "hecho": False, "code": "RENEWAL_QUOTA_BLOCKED",
                    "id": id_certificado, "nombre": nombre,
                    "error": motivo_cuota,
                    "quota": reintentos.cuota(
                        estado, clave_cuota, dominios=dominios)}
        reintentos.registrar_en_curso(
            estado, clave_cuota, anterior.get("caduca"),
            id_cert=id_certificado, dominios=dominios or [])
        guardar_estado(estado)
        replica_ledger = (_replicar_estado_cluster()
                          if _replicar_estado_cluster else {"ok": True, "resultados": {}})
        if not replica_ledger.get("ok"):
            # La petición aún no se ha enviado. Revocamos la reserva con una
            # revisión superior para que cualquier par que sí recibió el primer
            # paquete pueda converger sin dejar una emisión fantasma bloqueada.
            guardar_estado(estado_antes_de_reservar)
            replica_reversion = (_replicar_estado_cluster()
                                 if _replicar_estado_cluster else None)
            return {"ok": False, "hecho": False,
                    "code": "RENEWAL_LEDGER_NOT_REPLICATED",
                    "id": id_certificado, "nombre": nombre,
                    "error": "no se pudo fijar el intento en un quórum; no se ha enviado",
                    "ledger_replication": replica_ledger,
                    "ledger_rollback_replication": replica_reversion}
        cli = npm_api.cliente_del_activo(host_activo)
        respuesta = cli.renovar(
            id_certificado,
            validar_envio=lambda: _asegurar_autoridad(host_activo))
        # Un 200 sólo confirma que NPM aceptó la operación. La emisión no está
        # completa hasta que el registro/PEM local cambia realmente.
        renovado = _esperar_resultado(id_certificado, anterior)
        resultado_ya_esperado = True
        if not renovado:
            raise npm_api.ErrorNPM(
                "NPM aceptó la renovación, pero el certificado no cambió dentro de la ventana",
                "indeterminate", resultado_indeterminado=True)
        _asegurar_autoridad(host_activo)
    except ErrorAutoridad as error:
        return {"ok": False, "hecho": False, "code": "ACTIVE_ROLE_LOST",
                "id": id_certificado, "nombre": nombre, "error": str(error)}
    except npm_api.ErrorNPM as error:
        if error.resultado_indeterminado:
            reconciliado = (None if resultado_ya_esperado else
                            _esperar_resultado(id_certificado, anterior))
            if reconciliado:
                return _finalizar_emision(
                    id_certificado, nombre, host_activo,
                    {"reconciliada_tras_timeout": True}, reconciliada=True,
                    clave_cuota=clave_cuota, dominios=dominios)
            estado = leer_estado()
            reintentos.marcar_indeterminado(estado, clave_cuota)
            guardar_estado(estado)
            replica_ledger = (_replicar_estado_cluster()
                              if _replicar_estado_cluster else None)
            aviso = avisos.avisar(
                "NPM · certificados", f"Renovación pendiente de confirmar: {nombre}",
                "NPM agotó el tiempo de respuesta y aún no consta el resultado.",
                "warning",
                f"Certificado: {nombre}\nServidor: {host_activo}\n\n"
                "No se solicitará otra emisión mientras el resultado sea ambiguo. "
                "Guardian comprobará la base de NPM antes de decidir si procede reintentar.")
            return {"ok": False, "hecho": False, "indeterminado": True,
                    "emision_ok": None, "id": id_certificado, "nombre": nombre,
                    "error": str(error), "aviso": aviso,
                    "ledger_replication": replica_ledger}

        aviso = avisos.avisar(
            "NPM · certificados", f"NO se pudo renovar: {nombre}",
            str(error), "alert",
            f"Certificado: {nombre}\nServidor: {host_activo}\n\nMotivo: {error}\n\n"
            "El certificado anterior sigue en su sitio; una renovacion fallida no borra nada. "
            "Pero hay que arreglarlo antes de que caduque.")
        plan = _registrar_resultado(
            clave_cuota, id_certificado, dominios or [], False)
        if plan.get("agotado"):
            avisos.avisar(
                "NPM · certificados", f"Sin mas reintentos: {nombre}",
                "El guardian deja de intentarlo solo.", "alert",
                f"Se han agotado los reintentos automaticos de {nombre}.\n\n"
                "Queda UN intento sin gastar, reservado a proposito para que lo "
                "lances tu a mano desde el panel cuando puedas mirarlo.")
        return {"ok": False, "id": id_certificado, "nombre": nombre,
                "emision_ok": False, "error": str(error), "aviso": aviso}
    except Exception as error:  # noqa: BLE001
        # Fallos locales previos a enviar no consumen cuota de Let's Encrypt.
        return {"ok": False, "hecho": False, "id": id_certificado,
                "nombre": nombre, "emision_ok": False,
                "error": f"{type(error).__name__}: {error}"}

    return _finalizar_emision(
        id_certificado, nombre, host_activo, respuesta, reconciliada=False,
        clave_cuota=clave_cuota, dominios=dominios)


def _reconciliar_indeterminados(host_activo, certificados):
    """Resuelve timeouts antiguos mirando la verdad guardada por NPM."""
    resultados = []
    por_id = {str(c["id"]): c for c in certificados.values()}
    for clave_inicial, entrada_inicial in list(
            (leer_estado().get("reintentos") or {}).items()):
        clave_cuota = clave_inicial
        entrada = entrada_inicial
        id_certificado = entrada.get("certificate_id")
        if id_certificado is None and str(clave_cuota).isdigit():
            id_certificado = int(clave_cuota)  # migración del ledger pre-v1
        certificado = por_id.get(str(id_certificado))
        if not certificado:
            continue
        if not _candado_renovacion.acquire(blocking=False):
            continue
        if not coordinacion.escritura_npm.acquire(blocking=False):
            _candado_renovacion.release()
            continue
        try:
            _asegurar_autoridad(host_activo)
            # Otra petición puede haber cerrado o migrado esta entrada desde la
            # instantánea del inicio del bucle. Se relee bajo los dos cerrojos.
            estado_actual = leer_estado()
            entrada = (estado_actual.get("reintentos") or {}).get(clave_inicial)
            if not entrada:
                continue
            clave_real = _clave_cuota(
                certificado.get("dominios"), certificado["nombre"])
            if clave_real != clave_inicial:
                if reintentos.migrar_clave(
                        estado_actual, clave_inicial, clave_real, id_certificado,
                        certificado.get("dominios")):
                    guardar_estado(estado_actual)
                    if _replicar_estado_cluster:
                        _replicar_estado_cluster()
                clave_cuota = clave_real
                entrada = ((estado_actual.get("reintentos") or {})
                           .get(clave_cuota, entrada))
            reconciliacion = entrada.get("reconciliacion") or {}
            if not reconciliacion:
                continue
            anterior = {"caduca": reconciliacion.get("caducidad_anterior")}
            actual = npm.estado_certificado(int(id_certificado))
            if _certificado_cambio(anterior, actual):
                resultados.append(_finalizar_emision(
                    int(id_certificado), certificado["nombre"], host_activo,
                    {"reconciliada_en_revision": True}, reconciliada=True,
                    clave_cuota=clave_cuota, dominios=certificado.get("dominios")))
                continue

            if reconciliacion.get("estado") not in ("en_curso", "indeterminado"):
                continue
            espera_api = int(configuracion.leer()["settings"]["npm_api"].get(
                "timeout_seconds") or 720)
            edad = time.time() - float(reconciliacion.get("desde") or time.time())
            if edad < espera_api + ESPERA_RECONCILIACION + 60:
                continue
            plan = _registrar_resultado(
                clave_cuota, int(id_certificado),
                certificado.get("dominios") or [], False)
            avisos.avisar(
                "NPM · certificados", f"Renovación no confirmada: {certificado['nombre']}",
                "NPM no guardó un certificado nuevo tras agotar la ventana de reconciliación.",
                "warning",
                "Ahora se considera un intento fallido y se aplican las esperas y límites "
                "de seguridad antes de cualquier reintento."
                + (" No quedan reintentos automáticos." if plan.get("agotado") else ""))
        except ErrorAutoridad:
            pass
        finally:
            coordinacion.escritura_npm.release()
            _candado_renovacion.release()
    return resultados


def _es_namecheap(certificado):
    return (bool(certificado.get("reto_dns")) and
            str(certificado.get("proveedor_dns") or "").casefold() in
            ("namecheap", "dns_namecheap"))


def _credenciales_namecheap_coinciden(certificado):
    usuario, clave = namecheap.credenciales()
    if not usuario or not clave:
        return False
    huella = namecheap.huella(clave)
    usada = npm.credencial_dns_certificado(certificado["id"])
    return bool(usada and usada.get("usuario") == usuario and
                usada.get("huella") == huella)


def _renovar_los_que_tocan(nc, mando):
    """Los que entran en ventana, si se puede renovar y si mandamos nosotros."""
    hechas = []
    # SOLO si consta que mando YO. Antes ponia `is False`, que dejaba pasar el
    # `None` — y `None` es justo lo que devuelve `quien_manda()` cuando no se
    # llega al panel de direcciones. Es decir: si ese panel se caia, los TRES
    # nodos se creian el activo y renovaban a la vez, que es lo contrario de lo
    # que este codigo existe para garantizar.
    #
    # «No se quien manda» no es «mando yo». Cuando no se sabe, no se toca nada.
    if not mando or mando.get("soy_yo") is not True:
        return hechas
    usuario, clave = npm_api.credenciales()
    if not usuario or not clave:
        return hechas
    # Sin nombre de nodo activo no se renueva. Antes caia a «127.0.0.1», que en
    # red puente es ESTE contenedor y no NPM: la renovacion fallaba igual, pero
    # gastando un intento y ensuciando la cuenta.
    activo = mando.get("activo")
    if not activo:
        return hechas

    try:
        todos = {c["id"]: c for c in npm.certificados()}
    except npm.SinBaseDeDatos:
        return hechas

    hechas.extend(_reconciliar_indeterminados(activo, todos))
    est = leer_estado()
    ledger = est.get("reintentos") or {}

    # LA CUOTA SE MIRA PARA TODOS, no solo para los «pendientes».
    #
    # Antes, cualquier certificado dentro de la ventana de renovacion se repetia en
    # cada vuelta sin preguntar nada. Si fallaba —Namecheap caido, DNS lento— se
    # reintentaba A LA HORA SIGUIENTE, y otra vez, y otra. En un dia se ventilaba
    # la cuota semanal de Let's Encrypt y de paso el intento que se reserva a
    # proposito para lanzarlo a mano.
    #
    # `toca_reintentar` ya sabe de esperas y de topes; lo que faltaba era
    # llamarlo. Solo se salta cuando el certificado no tiene ningun fallo
    # apuntado, que es el caso normal del primer intento.
    aspirantes = []
    for c in todos.values():
        # Los certificados subidos a mano no tienen endpoint de renovación.
        if str(c.get("proveedor") or "").casefold() != "letsencrypt":
            continue
        en_ventana = c["dias"] is not None and c["dias"] <= dias_renovar()
        clave_cuota = _clave_cuota(c.get("dominios"), c["nombre"])
        tiene_historial = clave_cuota in ledger
        fallo_pendiente = reintentos.tiene_fallo_pendiente(est, clave_cuota)
        if not en_ventana and not fallo_pendiente:
            continue
        if tiene_historial:
            toca, motivo = reintentos.toca_reintentar(
                est, clave_cuota, dominios=c.get("dominios"))
            if not toca:
                print(f"vigilante: {c['nombre']} no se reintenta todavia: {motivo}", flush=True)
                continue
        elif not en_ventana:
            continue
        if _es_namecheap(c):
            if not configuracion.leer()["settings"]["namecheap"].get("enabled"):
                print(f"vigilante: {c['nombre']} no se renueva: la integración "
                      "Namecheap está desactivada", flush=True)
                continue
            # La integración opcional sólo condiciona los DNS-01 de Namecheap.
            # HTTP-01 y otros proveedores nunca dependen de su IP o credencial.
            if nc.get("estado") != "ok":
                print(f"vigilante: {c['nombre']} bloqueado por Namecheap: "
                      f"{nc.get('estado')}", flush=True)
                continue
            if not _credenciales_namecheap_coinciden(c):
                print(f"vigilante: {c['nombre']} bloqueado: las credenciales "
                      "de Guardian y NPM no coinciden", flush=True)
                continue
        aspirantes.append(c)

    for c in aspirantes:
        hechas.append(renovar(
            c["id"], c["nombre"], activo, manual=False,
            dominios=c.get("dominios")))

    # Cada renovación replica el snapshot dentro de su propia transacción antes
    # de marcar el ledger como completado; aquí ya no hay una segunda ventana.
    return hechas


# Lo pone el servidor al arrancar. Se inyecta en vez de importarlo para no hacer
# un círculo entre los dos módulos.
_replicar = None
_replicar_estado_cluster = None


def usar_replicador(fn):
    global _replicar
    _replicar = fn


def usar_replicador_estado(fn):
    global _replicar_estado_cluster
    _replicar_estado_cluster = fn

_candado = threading.Lock()
_ultimo = {"cuando": None, "namecheap": None, "certificados_en_riesgo": None,
           "avisos": [], "renovaciones": [], "mando": None}


def leer_estado():
    with _candado_estado:
        if not os.path.exists(RUTA_ESTADO):
            if not os.path.exists(RUTA_ESTADO_BACKUP):
                return {}
        errores = []
        for ruta in (RUTA_ESTADO, RUTA_ESTADO_BACKUP):
            try:
                with open(ruta, "r", encoding="utf-8") as fichero:
                    datos = json.load(fichero)
                if not isinstance(datos, dict):
                    raise ValueError("el estado no es un objeto")
                _validar_estado_cluster({
                    "revision": datos.get("ledger_revision", 0),
                    "reintentos": datos.get("reintentos") or {},
                })
                if ruta == RUTA_ESTADO_BACKUP:
                    _escribir_estado(datos, guardar_anterior=False)
                return datos
            except FileNotFoundError:
                continue
            except (OSError, ValueError, TypeError) as error:
                errores.append(f"{os.path.basename(ruta)}: {type(error).__name__}")
        raise ErrorEstado("el ledger de renovaciones está corrupto: " + ", ".join(errores))


def _validar_estado_cluster(datos):
    if not isinstance(datos, dict) or set(datos) != {"revision", "reintentos"}:
        raise ValueError("estado de clúster no válido")
    revision = datos.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("revisión de ledger no válida")
    ledger = datos.get("reintentos")
    if not isinstance(ledger, dict):
        raise ValueError("ledger de reintentos no válido")
    for identificador, entrada in ledger.items():
        if (not isinstance(identificador, str) or not identificador or
                len(identificador) > 80 or
                not (identificador.isdigit() or
                     (identificador.startswith("san:") and len(identificador) == 68))):
            raise ValueError("clave de cuota no válida")
        if not isinstance(entrada, dict):
            raise ValueError("entrada de reintento no válida")
        extras = set(entrada) - {
            "intentos", "fallos", "agotado", "siguiente", "reconciliacion",
            "certificate_id", "domains", "completed_at"}
        if extras:
            raise ValueError("campos desconocidos en el ledger")
        for campo in ("intentos", "fallos"):
            if not isinstance(entrada.get(campo, []), list) or not all(
                    isinstance(v, (int, float)) for v in entrada.get(campo, [])):
                raise ValueError("marcas de reintento no válidas")
        if ("certificate_id" in entrada and
                (isinstance(entrada["certificate_id"], bool) or
                 not isinstance(entrada["certificate_id"], int))):
            raise ValueError("identificador de certificado no válido")
        if ("domains" in entrada and
                (not isinstance(entrada["domains"], list) or
                 not all(isinstance(v, str) and 0 < len(v) <= 253
                         for v in entrada["domains"]))):
            raise ValueError("conjunto SAN no válido")
        if ("completed_at" in entrada and
                (isinstance(entrada["completed_at"], bool) or
                 not isinstance(entrada["completed_at"], (int, float)))):
            raise ValueError("marca de emisión no válida")
        reconciliacion = entrada.get("reconciliacion")
        if reconciliacion is not None:
            if (not isinstance(reconciliacion, dict) or
                    set(reconciliacion) - {
                        "estado", "desde", "caducidad_anterior", "confirmado_en"} or
                    reconciliacion.get("estado") not in
                    ("en_curso", "indeterminado", "fallo_confirmado")):
                raise ValueError("reconciliación no válida")
    return datos


def validar_estado_cluster(datos):
    """Valida un ledger recibido sin mutar el documento del llamador."""
    import copy
    return copy.deepcopy(_validar_estado_cluster(datos))


def fusionar_estados_cluster(estados):
    """Une ledgers divergentes sin perder intentos por una revisión minoritaria.

    Las marcas de cuota forman un conjunto creciente durante sus ventanas. Por
    eso la unión conservadora es más segura que elegir ciegamente el contador
    más alto: un nodo aislado nunca puede borrar una emisión confirmada por el
    resto cuando vuelve al clúster.
    """
    import copy
    validados = [copy.deepcopy(_validar_estado_cluster(estado)) for estado in estados]
    if not validados:
        return {"revision": 0, "reintentos": {}}
    validados.sort(key=lambda estado: int(estado["revision"]))
    fusionados = {}
    eventos = {}
    for estado in validados:
        for clave, entrada in estado["reintentos"].items():
            actual = fusionados.setdefault(clave, {})
            actual["intentos"] = sorted(set(
                list(actual.get("intentos") or []) +
                list(entrada.get("intentos") or [])))
            actual["fallos"] = sorted(set(
                list(actual.get("fallos") or []) +
                list(entrada.get("fallos") or [])))
            for campo in ("certificate_id", "domains"):
                if campo in entrada:
                    actual[campo] = copy.deepcopy(entrada[campo])

            completado = (float(entrada["completed_at"])
                           if entrada.get("completed_at") is not None else 0)
            reconciliacion = entrada.get("reconciliacion")
            marca_reconciliacion = (max(
                float(reconciliacion.get("desde") or 0),
                float(reconciliacion.get("confirmado_en") or 0))
                if reconciliacion else 0)
            marca_fallo = max(
                (float(valor) for valor in entrada.get("fallos") or []),
                default=0)
            if completado >= max(marca_reconciliacion, marca_fallo) and completado:
                evento = {
                    "orden": (completado, 2), "tipo": "completado",
                    "completed_at": entrada["completed_at"], "agotado": False,
                }
            elif reconciliacion is not None and marca_reconciliacion >= marca_fallo:
                evento = {
                    "orden": (marca_reconciliacion, 1), "tipo": "reconciliacion",
                    "reconciliacion": copy.deepcopy(reconciliacion),
                    "agotado": bool(entrada.get("agotado")),
                    "siguiente": entrada.get("siguiente"),
                }
            else:
                evento = {
                    "orden": (marca_fallo, 0), "tipo": "fallo",
                    "agotado": bool(entrada.get("agotado")),
                    "siguiente": entrada.get("siguiente"),
                }
            # El certificado pertenece al evento, no a la revisión global del
            # documento. Dos registros de NPM pueden compartir el mismo SAN y
            # un nodo rezagado puede tener una revisión global mayor por otra
            # clave totalmente distinta.
            for campo in ("certificate_id", "domains"):
                if campo in entrada:
                    evento[campo] = copy.deepcopy(entrada[campo])
            anterior = eventos.get(clave)
            if anterior is None or evento["orden"] > anterior["orden"]:
                eventos[clave] = evento
            elif evento["orden"] == anterior["orden"]:
                # Dos nodos pueden describir el mismo evento. Ante empate se
                # conserva el resultado más restrictivo y una elección canónica,
                # para que la fusión no dependa del orden de respuesta de red.
                anterior["agotado"] = bool(
                    anterior.get("agotado") or evento.get("agotado"))
                siguientes = [valor for valor in
                               (anterior.get("siguiente"), evento.get("siguiente"))
                               if valor]
                if siguientes:
                    anterior["siguiente"] = max(siguientes)
                if evento.get("reconciliacion"):
                    opciones = [anterior.get("reconciliacion"),
                                evento["reconciliacion"]]
                    anterior["reconciliacion"] = max(
                        (opcion for opcion in opciones if opcion),
                        key=lambda opcion: json.dumps(
                            opcion, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":")))
                metadatos = [{campo: copy.deepcopy(candidato[campo])
                              for campo in ("certificate_id", "domains")
                              if campo in candidato}
                             for candidato in (anterior, evento)]
                elegido = max(
                    metadatos,
                    key=lambda valor: (
                        len(valor), json.dumps(
                            valor, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":"))))
                for campo, valor in elegido.items():
                    anterior[campo] = valor

    for clave, actual in fusionados.items():
        evento = eventos[clave]
        actual["agotado"] = bool(evento.get("agotado"))
        for campo in ("certificate_id", "domains"):
            if campo in evento:
                actual[campo] = copy.deepcopy(evento[campo])
        if evento["tipo"] == "completado":
            actual["completed_at"] = evento["completed_at"]
        elif evento["tipo"] == "reconciliacion":
            actual["reconciliacion"] = evento["reconciliacion"]
            if evento.get("siguiente"):
                actual["siguiente"] = evento["siguiente"]
        elif evento.get("siguiente"):
            actual["siguiente"] = evento["siguiente"]

    max_revision = max(int(estado["revision"]) for estado in validados)
    huellas = {json.dumps(estado["reintentos"], ensure_ascii=False,
                         sort_keys=True, separators=(",", ":"))
               for estado in validados}
    resultado = {"revision": max_revision + (1 if len(huellas) > 1 else 0),
                 "reintentos": fusionados}
    return _validar_estado_cluster(resultado)


def _escribir_bytes(ruta, contenido):
    temporal = ruta + ".tmp"
    descriptor = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as fichero:
            fichero.write(contenido)
            fichero.flush()
            os.fsync(fichero.fileno())
        os.replace(temporal, ruta)
        carpeta = os.path.dirname(ruta) or "."
        descriptor_carpeta = os.open(carpeta, os.O_RDONLY)
        try:
            os.fsync(descriptor_carpeta)
        finally:
            os.close(descriptor_carpeta)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporal)
        except OSError:
            pass
        raise


def _escribir_estado(datos, guardar_anterior=True):
    if not isinstance(datos, dict):
        raise ErrorEstado("el estado operativo no es un objeto")
    contenido = (json.dumps(datos, ensure_ascii=False, indent=2) + "\n").encode()
    if len(contenido) > 2 * 1024 * 1024:
        raise ErrorEstado("el ledger supera el límite de tamaño")
    os.makedirs(os.path.dirname(RUTA_ESTADO), mode=0o700, exist_ok=True)
    if guardar_anterior and os.path.isfile(RUTA_ESTADO):
        try:
            with open(RUTA_ESTADO, "rb") as fichero:
                anterior = fichero.read()
            cargado = json.loads(anterior.decode())
            if isinstance(cargado, dict):
                _escribir_bytes(RUTA_ESTADO_BACKUP, anterior)
        except (OSError, ValueError, UnicodeError):
            pass  # nunca se reemplaza un backup bueno por un primario corrupto
    _escribir_bytes(RUTA_ESTADO, contenido)


def guardar_estado(datos):
    with _candado_estado:
        try:
            anterior = leer_estado()
            canon = lambda valor: json.dumps(  # noqa: E731
                valor or {}, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"))
            cambio_ledger = (canon(anterior.get("reintentos")) !=
                             canon(datos.get("reintentos")))
            revision = max(int(anterior.get("ledger_revision") or 0),
                           int(datos.get("ledger_revision") or 0))
            if cambio_ledger:
                revision += 1
            _validar_estado_cluster({"revision": revision,
                                     "reintentos": datos.get("reintentos") or {}})
            datos["ledger_revision"] = revision
            _escribir_estado(datos)
        except (OSError, ValueError, TypeError) as error:
            raise ErrorEstado(f"no se pudo persistir el ledger: {error}") from error
    return datos


def exportar_estado_cluster():
    estado = leer_estado()
    salida = {
        "revision": int(estado.get("ledger_revision") or 0),
        "reintentos": json.loads(json.dumps(estado.get("reintentos") or {})),
    }
    return _validar_estado_cluster(salida)


def aplicar_estado_cluster(datos):
    import copy
    entrada = copy.deepcopy(_validar_estado_cluster(datos))
    with _candado_estado:
        try:
            actual = leer_estado()
        except ErrorEstado:
            actual = {}
        revision_actual = int(actual.get("ledger_revision") or 0)
        revision_entrante = int(entrada["revision"])
        if revision_entrante < revision_actual:
            raise ErrorEstado(
                f"ledger obsoleto ({revision_entrante} < {revision_actual})")
        if revision_entrante == revision_actual:
            canon = lambda valor: json.dumps(  # noqa: E731
                valor, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"))
            if canon(entrada["reintentos"]) != canon(actual.get("reintentos") or {}):
                raise ErrorEstado(
                    "la misma revisión de ledger contiene datos distintos")
            return {"ok": True, "revision": revision_actual,
                    "renewal_entries": len(entrada["reintentos"]),
                    "idempotent": True}
        actual["reintentos"] = entrada["reintentos"]
        actual["ledger_revision"] = revision_entrante
        _escribir_estado(actual)
    return {"ok": True, "revision": revision_entrante,
            "renewal_entries": len(entrada["reintentos"]),
            "idempotent": False}


def _certificados_en_riesgo():
    try:
        return [c for c in npm.certificados()
                if c["dias"] is not None and c["dias"] <= dias_aviso()]
    except npm.SinBaseDeDatos:
        return None


def revisar(mando=None, forzar_aviso=False):
    """Una pasada. Devuelve lo visto y lo avisado."""
    with _candado:
        previo = leer_estado()
        nuevos = []

        # ── Namecheap ────────────────────────────────────────────────────
        nc = namecheap.comprobar()
        antes = previo.get("namecheap_estado")
        ahora = nc["estado"]

        # «indeterminado» no cambia el estado conocido: un corte de red no es
        # una noticia, y avisar por cada uno seria ruido que acaba ignorandose.
        if ahora != "indeterminado" and (ahora != antes or forzar_aviso):
            if ahora == "ip_rechazada":
                nuevos.append(avisos.avisar(
                    "NPM · certificados",
                    f"Namecheap no acepta la IP {nc.get('ip')}",
                    "Las renovaciones de certificados NO funcionan hasta arreglarlo.",
                    "alert",
                    f"Tu IP publica ha cambiado a {nc.get('ip')} y no esta en la lista blanca "
                    f"de Namecheap.\n\nAnadela en su panel: Profile > Tools > API Access > "
                    f"Edit whitelisted IPs.\n\nNamecheap no permite automatizar esto: no existe "
                    f"ningun comando de su API para actualizar la lista."))
            elif ahora == "ok" and antes in ("ip_rechazada", "otro_error", "sin_credenciales"):
                nuevos.append(avisos.avisar(
                    "NPM · certificados",
                    "Namecheap vuelve a aceptar la IP",
                    f"Las renovaciones funcionan otra vez desde {nc.get('ip')}.",
                    "normal",
                    "Ya se puede renovar con normalidad."))
            elif ahora == "sin_credenciales" and antes is not None:
                nuevos.append(avisos.avisar(
                    "NPM · certificados", "Faltan las credenciales de Namecheap",
                    "El guardian no puede comprobar si se podria renovar.",
                    "warning",
                    "Se configuran desde el portal: usuario y clave de la API."))
            elif ahora == "otro_error":
                nuevos.append(avisos.avisar(
                    "NPM · certificados", "Namecheap responde con un error",
                    nc.get("mensaje", ""), "warning",
                    "No es la lista blanca. Conviene mirarlo."))

        # Un modo de prueba que no manda nada no prueba nada. Si se fuerza y
        # ninguna rama tenia algo que contar, se manda igual: la gracia de
        # forzar es comprobar que el aviso LLEGA.
        if forzar_aviso and not nuevos:
            nuevos.append(avisos.avisar(
                "NPM · certificados", "Prueba de avisos del guardián",
                f"Namecheap: {nc.get('mensaje', 'sin detalle')}",
                "normal",
                "Este aviso se ha pedido a mano para comprobar la cadena de "
                "notificaciones configurada. Si lo estás leyendo, funciona."))

        # ── caducidades ──────────────────────────────────────────────────
        riesgo = _certificados_en_riesgo()
        antes_riesgo = set(previo.get("certificados_en_riesgo") or [])
        ahora_riesgo = set()
        if riesgo is not None:
            ahora_riesgo = {c["nombre"] for c in riesgo}
            entrantes = [c for c in riesgo if c["nombre"] not in antes_riesgo]
            if entrantes or forzar_aviso:
                for c in (entrantes or riesgo):
                    caducado = c["dias"] < 0
                    nuevos.append(avisos.avisar(
                        "NPM · certificados",
                        f"{'CADUCADO' if caducado else 'Caduca pronto'}: {c['nombre']}",
                        f"{'Caduco hace ' + str(-c['dias']) if caducado else 'Quedan ' + str(c['dias'])} dias.",
                        "alert" if caducado else "warning",
                        f"Certificado: {c['nombre']}\nCaduca: {c['caduca']}\n\n" +
                        ("Deberia haberse renovado solo. " +
                         ("Comprueba la IP permitida y las credenciales de Namecheap."
                          if _es_namecheap(c) else
                          "Revisa el reto ACME y los registros del NPM activo."))))

        renovaciones = _renovar_los_que_tocan(nc, mando)

        # SE VUELVE A LEER EL ESTADO, no se reutiliza `previo`.
        #
        # `_renovar_los_que_tocan` acaba de escribir en el fichero: cada intento
        # apunta su marca en `reintentos`. Construir aqui un diccionario nuevo y
        # guardarlo borraba esa cuenta enterita en la misma pasada — con lo cual
        # no habia reintentos con espera, la lista de pendientes salia siempre
        # vacia, y el control de cuota de Let's Encrypt se reseteaba cada hora
        # sin que nadie lo notara.
        estado = leer_estado()
        estado.update({
            "namecheap_estado": ahora if ahora != "indeterminado" else antes,
            "namecheap_ip": nc.get("ip"),
            "certificados_en_riesgo": sorted(ahora_riesgo),
            "ultima_revision": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        guardar_estado(estado)

        _ultimo.update({
            "cuando": estado["ultima_revision"],
            "namecheap": nc,
            "certificados_en_riesgo": riesgo,
            "avisos": nuevos,
            "renovaciones": renovaciones,
            "reintentos_pendientes": reintentos.pendientes(leer_estado()),
            "mando": mando,
        })
        return dict(_ultimo)


def ultimo():
    return dict(_ultimo)


def arrancar_bucle(quien_manda):
    """Revisa cada INTERVALO. Solo avisa el nodo que manda: si avisaran los tres,
    recibirias tres mensajes identicos y acabarias silenciando el canal."""
    def bucle():
        time.sleep(10)  # dar tiempo a que el panel de direcciones responda
        while True:
            try:
                m = quien_manda()
                if m.get("soy_yo") is True:
                    revisar(mando=m)
                elif m.get("soy_yo") is False:
                    _ultimo.update({"mando": m, "cuando": time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "namecheap": {"estado": "no_me_toca",
                                                  "mensaje": f"manda «{m.get('activo')}»; aqui no se comprueba ni se avisa"}})
                else:
                    # No se sabe quien manda. Antes se revisaba igual, y con el
                    # panel de direcciones caido los TRES nodos avisaban a la vez.
                    #
                    # No revisar deja un hueco de vigilancia, asi que ese hueco se
                    # DICE en pantalla en vez de quedarse callado: un silencio que
                    # parece normalidad es peor que un aviso incomodo.
                    _ultimo.update({"mando": m, "cuando": time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "namecheap": {"estado": "sin_saber_quien_manda",
                                                  "mensaje": "no se sabe qué servidor sostiene la dirección "
                                                             f"({m.get('origen') or 'sin motivo'}). Nadie está "
                                                             "vigilando los certificados hasta que se aclare."}})
                    print("vigilante: no se sabe quien manda; no se revisa ni se avisa "
                          f"({m.get('origen')})", flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"vigilante: fallo en la revision: {type(e).__name__}: {e}", flush=True)
            time.sleep(INTERVALO)

    h = threading.Thread(target=bucle, daemon=True)
    h.start()
    return h
