"""Los fallos que encontro la revision del 2026-08-20, para que no vuelvan.

Los tres eran del mismo tipo: codigo que parecia funcionar y no hacia su trabajo.
Ninguno daba error, ninguno se veia en el panel.
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, "/opt/panel")
os.environ["NPMG_DATA_DIR"] = tempfile.mkdtemp()

import reintentos  # noqa: E402
import vigilante  # noqa: E402

ok = []


def caso(titulo, real, esperado):
    bien = real == esperado
    ok.append(bien)
    print(f"{'OK ' if bien else 'MAL'} {titulo}")
    print(f"     obtenido={real!r}  esperado={esperado!r}")


# ── 1. `revisar()` borraba la cuenta de reintentos ───────────────────────────
# `renovar()` apuntaba el intento en el fichero y, en la misma pasada,
# `revisar()` guardaba un diccionario nuevo que no la incluia. Resultado: cero
# reintentos con espera, lista de pendientes siempre vacia, y el control de
# cuota de Let's Encrypt reseteandose cada hora.
est = vigilante.leer_estado()
clave_estado = reintentos.clave_san(["state.example.test"])
reintentos.registrar_intento(
    est, clave_estado, ok=False, id_cert=999,
    dominios=["state.example.test"])
vigilante.guardar_estado(est)

previo = vigilante.leer_estado()
previo.update({"namecheap_estado": "ok", "ultima_revision": "ahora"})
vigilante.guardar_estado(previo)

caso("guardar el estado de la revision NO borra los reintentos",
     clave_estado in (vigilante.leer_estado().get("reintentos") or {}), True)


# ── 2. «no se quien manda» se trataba como «mando yo» ────────────────────────
# `quien_manda()` devuelve soy_yo=None cuando no se llega al panel de
# direcciones. Con `is False` ese None pasaba el filtro y los TRES nodos
# renovaban a la vez.
class NC(dict):
    pass


nc_ok = {"estado": "ok"}
for etiqueta, mando, espera in (
    ("no se sabe quien manda (None)", {"soy_yo": None, "activo": None}, []),
    ("manda otro", {"soy_yo": False, "activo": "otro"}, []),
    ("no hay mando", None, []),
):
    caso(f"no se renueva si {etiqueta}",
         vigilante._renovar_los_que_tocan(nc_ok, mando), espera)


# ── 3. la cuota solo se miraba para los «pendientes» ─────────────────────────
# Un certificado dentro de la ventana de renovacion se repetia en CADA vuelta sin
# preguntar por la cuota. Si fallaba, se reintentaba a la hora siguiente, y otra,
# hasta ventilarse el tope semanal de Let's Encrypt y el intento reservado.
est = {}
clave_cuota = reintentos.clave_san(["quota.example.test"])
for _ in range(4):
    reintentos.registrar_intento(
        est, clave_cuota, ok=False, id_cert=42,
        dominios=["quota.example.test"])
toca, motivo = reintentos.toca_reintentar(est, clave_cuota)
caso("con la cuota agotada, toca_reintentar dice que no", toca, False)
print(f"     motivo: {motivo}")

r = (est.get("reintentos") or {}).get(clave_cuota) or {}
caso("y queda marcado como agotado", bool(r.get("agotado")), True)
caso("sin gastar el ultimo cartucho de Let's Encrypt",
     len(r.get("intentos", [])) <= reintentos.MAX_INTENTOS_SEMANA, True)


# 4. La cuota semanal pertenece al conjunto SAN, no al ID interno de NPM.
# Una emision valida tambien consume cuota y no se puede olvidar al cambiar de
# fila/certificado tras una importacion o una recreacion en NPM.
est = {}
san_a = ["WWW.Example.Test.", "*.Example.Test"]
san_b = ["*.example.test", "www.example.test"]
clave_a = reintentos.clave_san(san_a)
clave_b = reintentos.clave_san(san_b)
reintentos.registrar_intento(
    est, clave_a, ok=True, id_cert=7, dominios=san_a)
reintentos.registrar_intento(
    est, clave_b, ok=True, id_cert=99, dominios=san_b)
entrada = est["reintentos"][clave_a]
caso("el mismo SAN produce la misma clave aunque cambie el ID", clave_a, clave_b)
caso("dos exitos del mismo SAN conservan dos usos semanales",
     len(entrada.get("intentos", [])), 2)
caso("el ledger conserva el ID mas reciente solo como metadato",
     entrada.get("certificate_id"), 99)


# 5. Los fallos de autorización de Let's Encrypt se limitan por hostname. Dos
# conjuntos SAN diferentes que comparten un nombre consumen el mismo bucket;
# uno totalmente independiente conserva su propia cuota.
est = {}
ahora = time.time()
san_fallido = ["shared.example.test", "first.example.test"]
clave_fallida = reintentos.clave_san(san_fallido)
for offset in range(reintentos.MAX_FALLOS_HORA):
    reintentos.registrar_intento(
        est, clave_fallida, ok=False, ahora=ahora - offset,
        id_cert=7, dominios=san_fallido)
san_solapado = ["shared.example.test", "second.example.test"]
permitido, _ = reintentos.puede_intentar(
    est, reintentos.clave_san(san_solapado), ahora=ahora,
    dominios=san_solapado)
caso("dos SAN que comparten hostname comparten la cuota de fallos",
     permitido, False)
san_aislado = ["unrelated.example.test"]
permitido, _ = reintentos.puede_intentar(
    est, reintentos.clave_san(san_aislado), ahora=ahora,
    dominios=san_aislado)
caso("un SAN sin hostnames comunes conserva su cuota", permitido, True)

print()
print("TODO BIEN" if all(ok) else "HAY FALLOS")
sys.exit(0 if all(ok) else 1)
