"""Inventario lógico completo de NPM y comparación entre nodos.

La réplica transporta la base SQLite entera. Por tanto, la decisión de si hace
falta replicar no puede mirar sólo certificados y proxy hosts: también deben
contar usuarios, contraseñas, listas de acceso, redirecciones, streams, ajustes
y el esquema de la base. Los datos nunca salen de aquí; sólo viajan huellas.

``audit_log`` y los cerrojos de migración son estado operativo de cada proceso,
no configuración autoritativa. Una tabla desconocida bloquea la comparación en
vez de declarar una sincronía falsa ante una versión de NPM aún no revisada.
"""
import hashlib
import json
import os
import re
import sqlite3

import npm
import replica

TABLAS_DETALLE = {
    "certificate": ("certificado", "nice_name"),
    "proxy_host": ("dominio", "domain_names"),
}

TABLAS_AUTORITATIVAS = {
    "access_list", "access_list_auth", "access_list_client", "auth",
    "certificate", "dead_host", "proxy_host", "redirection_host", "setting",
    "stream", "user", "user_permission", "knex_migrations", "migrations",
}
TABLAS_OPERATIVAS = {"audit_log", "knex_migrations_lock", "migrations_lock"}
TABLAS_REQUERIDAS = {
    "access_list", "access_list_auth", "access_list_client", "auth",
    "certificate", "dead_host", "proxy_host", "redirection_host", "setting",
    "stream", "user", "user_permission",
}


def _identificador_tabla(tabla):
    """Devuelve un identificador SQL solo tras contrastarlo con la allowlist."""
    if tabla not in TABLAS_AUTORITATIVAS or not re.fullmatch(r"[a-z_]+", tabla):
        raise ErrorInventario("identificador de tabla no permitido")
    return f'"{tabla}"'


class ErrorInventario(npm.SinBaseDeDatos):
    """El esquema existe, pero no es compatible con esta versión."""

# CAMPOS QUE CAMBIAN SOLOS, y que por tanto NO cuentan como diferencia.
#
# NPM reescribe algunas filas por su cuenta sin que nadie haya tocado nada: en
# `meta` lleva su propio seguimiento del destino (`nginx_online`, `nginx_err`) y
# lo vuelve a escribir aunque el valor sea el mismo. Cada nodo lo hace por su
# lado y a su hora, asi que `modified_on` acaba distinto entre ellos.
#
# Comparar por fecha decia «no estan sincronizados» siempre, con el contenido
# identico. Un indicador que grita cuando no pasa nada se deja de mirar, y
# entonces no sirve el dia que pasa algo de verdad. Se compara el CONTENIDO;
# la fecha solo decide quien gana cuando el contenido de verdad difiere.
VOLATILES_META = ("nginx_online", "nginx_err")
VOLATILES_FILA = ("modified_on",)


def _normalizar(fila):
    """Representación canónica sin marcas que NPM cambia por sí solo."""
    d = {}
    for k in fila.keys():
        if k in VOLATILES_FILA:
            continue
        valor = fila[k]
        if isinstance(valor, bytes):
            valor = {"sha256": hashlib.sha256(valor).hexdigest()}
        elif isinstance(valor, str) and valor[:1] in ("{", "["):
            try:
                valor = json.loads(valor)
            except ValueError:
                pass
        if k == "meta" and isinstance(valor, dict):
            valor = dict(valor)
            for volatil in VOLATILES_META:
                valor.pop(volatil, None)
        d[k] = valor
    return d


def _huella(fila):
    """Huella del contenido de una fila, sin lo que cambia solo.

    Es un hash, no los datos: en estas filas hay credenciales, y el inventario
    viaja entre nodos y se enseña en pantalla.
    """
    d = _normalizar(fila)
    return hashlib.sha256(
        json.dumps(d, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode()
    ).hexdigest()[:16]


def _huella_tabla(columnas, filas):
    canonicas = [json.dumps(_normalizar(f), sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False) for f in filas]
    contenido = {"columnas": columnas, "filas": sorted(canonicas)}
    return hashlib.sha256(json.dumps(
        contenido, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode()).hexdigest()[:16]


def _ultima_fecha(filas):
    fechas = []
    for fila in filas:
        for campo in ("modified_on", "created_on", "migration_time"):
            if campo in fila.keys() and fila[campo]:
                fechas.append(str(fila[campo])[:19])
                break
    return max(fechas, default="")


def _clave(tabla, fila_id):
    return f"{tabla}:{fila_id}"


def inventario():
    """Cada elemento con su fecha, para poder compararlo con el de otro nodo."""
    # Se comprueba como hace `npm._abrir`: sin esto, un nodo sin el appdata de
    # NPM montado devolvia un 500 pelado en cada refresco del panel —y dejaba la
    # conexion sin cerrar, porque el `close()` estaba fuera de un `finally`.
    if not os.path.exists(npm.RUTA_DB):
        raise npm.SinBaseDeDatos(
            f"No existe {npm.RUTA_DB}. ¿Está montado el appdata de NPM?")

    con = sqlite3.connect(f"file:{npm.RUTA_DB}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    elementos = {}
    try:
        tablas = {fila[0] for fila in con.execute(
            "select name from sqlite_master where type='table' and name not like 'sqlite_%'")}
        desconocidas = tablas - TABLAS_AUTORITATIVAS - TABLAS_OPERATIVAS
        ausentes = TABLAS_REQUERIDAS - tablas
        if desconocidas:
            raise ErrorInventario(
                "NPM contiene tablas aún no soportadas por Guardian: " +
                ", ".join(sorted(desconocidas)))
        if ausentes:
            raise ErrorInventario(
                "A la base de NPM le faltan tablas necesarias: " +
                ", ".join(sorted(ausentes)))

        for tabla in sorted(tablas & TABLAS_AUTORITATIVAS):
            identificador = _identificador_tabla(tabla)
            # El identificador procede de la allowlist cerrada anterior.
            columnas = [fila[1] for fila in con.execute(
                f"pragma table_info({identificador})")]
            filas = list(con.execute(
                f"select * from {identificador}"))  # nosec B608
            if tabla in TABLAS_DETALLE:
                tipo, etiqueta = TABLAS_DETALLE[tabla]
                for fila in filas:
                    elementos[_clave(tabla, fila["id"])] = {
                        "tipo": tipo,
                        "id": fila["id"],
                        "nombre": (fila[etiqueta] or "").strip('[]"'),
                        "modificado": (fila["modified_on"] or "")[:19],
                        "borrado": bool(fila["is_deleted"]),
                        "huella": _huella(fila),
                    }
                continue

            elementos[_clave("tabla", tabla)] = {
                "tipo": "estado_npm",
                "id": tabla,
                "nombre": tabla,
                "modificado": _ultima_fecha(filas),
                "borrado": False,
                "huella": _huella_tabla(columnas, filas),
            }

        artefactos = replica.inventario_artefactos()
        elementos["artefactos:estado"] = {
            "tipo": "artefactos_npm",
            "id": "estado",
            "nombre": "claves, configuración y certificados en disco",
            "modificado": artefactos["modificado"],
            "borrado": False,
            "huella": artefactos["huella"],
        }
    except sqlite3.Error as e:
        raise npm.SinBaseDeDatos(f"no se pudo leer el inventario de NPM: {e}")
    finally:
        con.close()
    vivos = [e for e in elementos.values() if not e["borrado"]]
    return {
        "elementos": elementos,
        "resumen": {
            "certificados": len([e for e in vivos if e["tipo"] == "certificado"]),
            "dominios": len([e for e in vivos if e["tipo"] == "dominio"]),
            "tablas_autoritativas": len(tablas & TABLAS_AUTORITATIVAS),
            "ultimo_cambio": max((e["modificado"] for e in elementos.values()), default=None),
        },
    }


def comparar(inventarios):
    """`inventarios` es {nodo: inventario()}. Dice quien gana cada elemento.

    No decide nada ni toca nada: solo cuenta lo que hay. Lo que se hace con
    esto se decide fuera, y se enseña antes de hacerlo.
    """
    todas = set()
    for inv in inventarios.values():
        todas |= set((inv.get("elementos") or {}).keys())

    diferencias = []
    ganadores = {}
    conflictos = []
    for clave in sorted(todas):
        versiones = {}
        for nodo, inv in inventarios.items():
            e = (inv.get("elementos") or {}).get(clave)
            versiones[nodo] = e  # None = ese nodo no lo tiene
        fechas = {n: (e or {}).get("modificado") or "" for n, e in versiones.items()}
        huellas = {n: (e or {}).get("huella") for n, e in versiones.items()}

        # Hay diferencia si alguno no lo tiene, o si el CONTENIDO no coincide.
        # Por fecha no: NPM reescribe filas solo, cada nodo a su hora, y eso
        # daria una diferencia permanente con el contenido identico.
        if all(versiones.values()) and any(h is None for h in huellas.values()):
            # Algun nodo todavia no manda huella (version anterior, a mitad de un
            # despliegue). Se compara por fecha, que es lo que habia antes: peor,
            # pero mejor que tratar «no lo se» como «son distintos».
            iguales = len(set(fechas.values())) == 1
        else:
            iguales = all(versiones.values()) and len(set(huellas.values())) == 1
        if iguales:
            # Si todos lo tienen igual no hay ganador que elegir. Anotar uno
            # seria inventarse un dato: `max()` devolveria el primero del
            # diccionario, que es solo el orden en que se preguntó.
            continue

        mejor = max(fechas.values())
        gana = [n for n, f in fechas.items() if f == mejor and versiones[n] is not None]
        firmas_empatadas = {
            (huellas[n], bool((versiones[n] or {}).get("borrado"))) for n in gana
        }
        empate_ambiguo = len(gana) > 1 and (
            any(huellas[n] is None for n in gana) or len(firmas_empatadas) > 1)
        ganadores[clave] = None if empate_ambiguo else (gana[0] if gana else None)

        muestra = next(e for e in versiones.values() if e)
        diferencias.append({
            "clave": clave,
            "tipo": muestra["tipo"],
            "nombre": muestra["nombre"],
            "borrado": muestra["borrado"],
            "gana": ganadores[clave],
            "conflicto": empate_ambiguo,
            "por_nodo": {
                n: ("no lo tiene" if e is None else
                    ("borrado " if e["borrado"] else "") + (e["modificado"] or "sin fecha"))
                for n, e in versiones.items()
            },
        })
        if empate_ambiguo:
            conflictos.append(clave)

    # ¿Gana todo un solo nodo? Entonces basta con empujar su estado entero, que
    # es lo simple. Si no, hay que armar el conjunto ganador primero.
    quien_gana = {g for g in ganadores.values() if g}
    # Los ficheros de Nginx se regeneran de forma local y sus mtimes no pueden
    # decidir qué base NPM es autoritativa. Viajan con el snapshot, pero cuando
    # existe una diferencia lógica es ésta la que determina el origen coherente.
    # Sin esta separación, reiniciar Nginx en un pasivo podía impedir para
    # siempre la réplica de un proxy host modificado legítimamente en el activo.
    ganadores_logicos = {
        ganadores.get(diferencia["clave"])
        for diferencia in diferencias
        if diferencia["clave"] != "artefactos:estado" and
        ganadores.get(diferencia["clave"])
    }
    return {
        "en_sincronia": not diferencias,
        "diferencias": diferencias,
        "conflictos": conflictos,
        "nodos_con_algo_ganador": sorted(quien_gana),
        "un_solo_ganador": (sorted(quien_gana)[0] if len(quien_gana) == 1 else None),
        "nodos_con_cambio_logico": sorted(ganadores_logicos),
        "un_solo_ganador_logico": (
            sorted(ganadores_logicos)[0] if len(ganadores_logicos) == 1 else None
        ),
        "resumen_por_nodo": {n: inv.get("resumen") for n, inv in inventarios.items()},
    }
