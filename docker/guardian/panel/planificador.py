"""Planificador cron pequeño, sin ejecutar comandos de shell.

Solo interpreta las cinco columnas de cron. NPM Guardian necesita decidir si
una tarea toca en un minuto dado; no necesita ni quiere un demonio cron dentro
del contenedor.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta

import configuracion


class ErrorCron(ValueError):
    pass


LIMITES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


def _campo(texto, minimo, maximo, domingo=False):
    valores = set()
    for parte in texto.split(","):
        parte = parte.strip()
        if not parte:
            raise ErrorCron("hay una lista vacia en la expresion cron")
        paso = 1
        if "/" in parte:
            base, salto = parte.split("/", 1)
            try:
                paso = int(salto)
            except ValueError as e:
                raise ErrorCron(f"paso cron no valido: {salto}") from e
            if paso <= 0:
                raise ErrorCron("el paso cron debe ser mayor que cero")
        else:
            base = parte
        if base == "*":
            inicio, fin = minimo, maximo
        elif "-" in base:
            a, b = base.split("-", 1)
            try:
                inicio, fin = int(a), int(b)
            except ValueError as e:
                raise ErrorCron(f"rango cron no valido: {base}") from e
        else:
            try:
                inicio = fin = int(base)
            except ValueError as e:
                raise ErrorCron(f"valor cron no valido: {base}") from e
        if inicio < minimo or fin > maximo or inicio > fin:
            raise ErrorCron(f"{parte} queda fuera del rango {minimo}-{maximo}")
        valores.update(range(inicio, fin + 1, paso))
    if domingo and 7 in valores:
        valores.remove(7)
        valores.add(0)
    return valores


def compilar(expresion):
    partes = str(expresion or "").split()
    if len(partes) != 5:
        raise ErrorCron("una expresion cron debe tener cinco campos")
    return tuple(_campo(texto, *limite, domingo=(i == 4))
                 for i, (texto, limite) in enumerate(zip(partes, LIMITES)))


def validar_cron(expresion):
    compilar(expresion)
    return expresion


def coincide(expresion, momento=None):
    momento = momento or datetime.now()
    compilado = compilar(expresion)
    return _coincide_compilado(expresion, compilado, momento)


def _coincide_compilado(expresion, compilado, momento):
    minuto, hora, dia, mes, semana = compilado
    # Python: lunes=0. Cron: domingo=0, lunes=1.
    dia_semana = (momento.weekday() + 1) % 7
    partes = str(expresion).split()
    coincide_dia = momento.day in dia
    coincide_semana = dia_semana in semana
    # Semántica cron/Vixie: si día del mes y día de semana están ambos
    # restringidos, basta que coincida uno. Si alguno es '*', se exige el otro.
    calendario = ((coincide_dia or coincide_semana)
                  if partes[2] != "*" and partes[4] != "*"
                  else (coincide_dia and coincide_semana))
    return (momento.minute in minuto and momento.hour in hora and
            momento.month in mes and calendario)


def siguiente(expresion, desde=None, limite_dias=370):
    actual = (desde or datetime.now()).replace(second=0, microsecond=0) + timedelta(minutes=1)
    limite = actual + timedelta(days=limite_dias)
    compilado = compilar(expresion)
    while actual <= limite:
        if _coincide_compilado(expresion, compilado, actual):
            return actual.isoformat(timespec="minutes")
        actual += timedelta(minutes=1)
    return None


def arrancar(sincronizar, quien_manda):
    """Ejecuta a lo sumo una vez por minuto y solo en el nodo activo."""
    def bucle():
        ultimo_minuto = None
        while True:
            ahora = datetime.now()
            marca = ahora.strftime("%Y-%m-%d %H:%M")
            try:
                ajustes = configuracion.leer()["settings"]["sync"]
                if (marca != ultimo_minuto and ajustes.get("enabled") and
                        coincide(ajustes.get("cron"), ahora)):
                    ultimo_minuto = marca
                    mando = quien_manda()
                    if mando.get("soy_yo") is True:
                        configuracion.guardar_estado_operativo({
                            "last_scheduled_sync_started": time.time(),
                            "last_scheduled_sync": sincronizar(False),
                        })
            except Exception as e:  # noqa: BLE001
                configuracion.guardar_estado_operativo({
                    "last_scheduled_sync_error": f"{type(e).__name__}: {e}",
                })
            time.sleep(15)

    hilo = threading.Thread(target=bucle, daemon=True, name="npmg-cron")
    hilo.start()
    return hilo
