"""Avisos por el centro de notificaciones de Unraid, que ya reenvia a Discord.

Se hacen las dos cosas que hace el `notify` de Unraid:

  1. Se deja el fichero `.notify` en su cola  -> aparece en la interfaz de Unraid.
  2. Se invoca su agente `Discord.sh`         -> llega al canal de Discord.

No se llama al `notify` original porque es PHP y no esta en este contenedor. Y
NO se copia el webhook a ningun sitio nuestro: el agente lo lleva dentro y se
queda donde ya estaba. Un secreto duplicado es un secreto que se filtra.

REGLA: solo se avisa cuando el estado CAMBIA. Un aviso cada hora repitiendo lo
mismo se ignora a las dos veces, y entonces no sirve para nada el dia que
importa.
"""
import os
import re
import secrets
import stat
# El modulo solo ejecuta descriptores regulares abiertos sin seguir enlaces.
import subprocess  # nosec B404
import time

COLA = os.environ.get("NPMHA_COLA_UNRAID", "/unraid-cola/unread")
AGENTES = os.environ.get("NPMHA_AGENTES_UNRAID", "/unraid-notificaciones/agents")
NODO = os.environ.get("NPMG_NODE_NAME", os.environ.get("NPMHA_NODO", "?"))

# normal = informativo · warning = mirar sin prisa · alert = hay que actuar
NIVELES = ("normal", "warning", "alert")


def _escapar(texto):
    return str(texto or "").replace('"', "'").replace("\n", "<br>")


def _dejar_en_la_cola(evento, asunto, descripcion, nivel, mensaje):
    """Fichero .notify para que salga en la interfaz de Unraid."""
    if not os.path.isdir(COLA):
        return False, f"no existe la cola {COLA}"
    ts = int(time.time())
    etiqueta = re.sub(r"[^A-Za-z0-9_.-]+", "_", evento).strip("._") or "npm-guardian"
    nombre = f"{etiqueta}_{time.time_ns()}_{secrets.token_hex(4)}.notify"
    try:
        ruta = os.path.join(COLA, nombre)
        descriptor = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as f:
            f.write(f"timestamp={ts}\n")
            f.write(f'event="{_escapar(evento)}"\n')
            f.write(f'subject="{_escapar(asunto)}"\n')
            f.write(f'description="{_escapar(descripcion)}"\n')
            f.write(f'importance="{nivel}"\n')
            f.write(f'message="{_escapar(mensaje)}"\n')
        return True, None
    except OSError as e:
        return False, str(e)


def _mandar_a_los_agentes(evento, asunto, descripcion, nivel, mensaje):
    """Los agentes de Unraid son guiones que leen variables de entorno."""
    if not os.path.isdir(AGENTES):
        return False, f"no existe la carpeta de agentes {AGENTES}"
    # No se hereda el entorno completo: contiene las claves de sesión/clúster y
    # puede contener credenciales legacy. Los agentes sólo necesitan utilidades
    # del sistema, locale/zona y el contrato de notificación.
    entorno = {clave: os.environ[clave] for clave in
               ("PATH", "LANG", "LC_ALL", "TZ") if clave in os.environ}
    entorno.update({
        "EVENT": evento, "SUBJECT": asunto, "DESCRIPTION": descripcion,
        "IMPORTANCE": nivel, "CONTENT": mensaje, "HOSTNAME": NODO,
    })
    enviados, fallos = [], []
    for fichero in sorted(os.listdir(AGENTES)):
        ruta = os.path.join(AGENTES, fichero)
        if not fichero.endswith(".sh"):
            continue
        descriptor = None
        try:
            # Abrir una sola vez con O_NOFOLLOW evita que un agente se cambie
            # por un enlace entre la comprobacion y la ejecucion (TOCTOU).
            descriptor = os.open(
                ruta, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            estado = os.fstat(descriptor)
            if not stat.S_ISREG(estado.st_mode) or estado.st_size > 1024 * 1024:
                raise OSError("el agente no es un fichero regular de tamano razonable")
            ruta_estable = f"/proc/self/fd/{descriptor}"
            # La ruta apunta al descriptor ya validado y el entorno es reducido.
            r = subprocess.run(  # nosec B603
                ["/bin/bash", ruta_estable], env=entorno, capture_output=True,
                text=True, timeout=30, pass_fds=(descriptor,))
            (enviados if r.returncode == 0 else fallos).append(fichero)
        except Exception as e:  # noqa: BLE001
            fallos.append(f"{fichero} ({type(e).__name__})")
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return (not fallos), {"enviados": enviados, "fallos": fallos}


def avisar(evento, asunto, descripcion, nivel="warning", mensaje=""):
    """Manda el aviso por los dos caminos y cuenta que tal fue cada uno."""
    if nivel not in NIVELES:
        nivel = "warning"
    ok_cola, err_cola = _dejar_en_la_cola(evento, asunto, descripcion, nivel, mensaje)
    ok_agentes, detalle = _mandar_a_los_agentes(evento, asunto, descripcion, nivel, mensaje)
    return {
        "evento": evento, "nivel": nivel, "asunto": asunto,
        "interfaz_unraid": {"ok": ok_cola, "error": err_cola},
        "agentes": {"ok": ok_agentes, "detalle": detalle},
        "cuando": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
