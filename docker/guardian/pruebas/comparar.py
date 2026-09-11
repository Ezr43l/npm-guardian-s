import sys
sys.path.insert(0, "/opt/panel")
import inventario as inv

def el(tipo, fid, nombre, fecha, borrado=False, contenido="igual"):
    # `huella` = el contenido. Dos elementos con la misma huella son el mismo
    # aunque tengan fechas distintas: NPM reescribe filas solo, y eso no es un
    # cambio. La fecha solo decide quien gana cuando el contenido SI difiere.
    return {"tipo": tipo, "id": fid, "nombre": nombre, "modificado": fecha,
            "borrado": borrado, "huella": f"{contenido}-{borrado}"}

def caso(titulo, invs, espera_dif, espera_gana):
    r = inv.comparar(invs)
    ok = len(r["diferencias"]) == espera_dif and r["un_solo_ganador"] == espera_gana
    print(f"{'OK ' if ok else 'MAL'} {titulo}")
    print(f"     diferencias={len(r['diferencias'])} (esperado {espera_dif})"
          f"  un_solo_ganador={r['un_solo_ganador']!r} (esperado {espera_gana!r})")
    for d in r["diferencias"]:
        print(f"     · {d['nombre']}: gana {d['gana']} | {d['por_nodo']}")
    return ok

base = {"certificate:1": el("certificado", 1, "web.ejemplo", "2026-08-01 10:00:00")}
todo = []

# 1. Todo igual: ni diferencias, ni ganador inventado.
todo.append(caso("los tres iguales",
    {"node-a": {"elementos": dict(base)}, "node-b": {"elementos": dict(base)},
     "node-c": {"elementos": dict(base)}}, 0, None))

# 2. Alta en un solo nodo: ese gana, es el unico que lo tiene.
a = dict(base); a["certificate:9"] = el("certificado", 9, "nuevo.ejemplo", "2026-08-19 09:00:00")
todo.append(caso("alta solo en node-a",
    {"node-a": {"elementos": a}, "node-b": {"elementos": dict(base)},
     "node-c": {"elementos": dict(base)}}, 1, "node-a"))

# 3. Renovacion en dos sitios: gana la fecha mas nueva. Este es el caso que
#    parecia un conflicto y no lo es.
r1 = {"certificate:1": el("certificado", 1, "web.ejemplo", "2026-08-10 10:00:00", contenido="cert-b")}
r2 = {"certificate:1": el("certificado", 1, "web.ejemplo", "2026-08-12 10:00:00", contenido="cert-c")}
todo.append(caso("renovado en node-a y despues en node-b",
    {"node-a": {"elementos": r1}, "node-b": {"elementos": r2},
     "node-c": {"elementos": dict(base)}}, 1, "node-b"))

# 4. Borrado: es una fila con fecha, y si es la mas nueva gana y se propaga.
b = {"certificate:1": el("certificado", 1, "web.ejemplo", "2026-08-15 10:00:00", borrado=True)}
todo.append(caso("borrado en node-c, mas nuevo que el alta",
    {"node-a": {"elementos": dict(base)}, "node-b": {"elementos": dict(base)},
     "node-c": {"elementos": b}}, 1, "node-c"))

# 5. Cambios en nodos distintos: no hay un solo ganador, hay que mezclar.
x = dict(base); x["certificate:7"] = el("certificado", 7, "x.ejemplo", "2026-08-18 08:00:00")
y = dict(base); y["certificate:8"] = el("certificado", 8, "y.ejemplo", "2026-08-19 08:00:00")
todo.append(caso("uno nuevo en node-a y otro en node-c",
    {"node-a": {"elementos": x}, "node-b": {"elementos": dict(base)},
     "node-c": {"elementos": y}}, 2, None))

# 6. NPM reescribe filas por su cuenta (su seguimiento del destino), cada nodo a
#    su hora. Contenido identico, fechas distintas: NO es una diferencia. Esto
#    daba «no sincronizados» para siempre.
f1 = {"certificate:1": el("certificado", 1, "web.ejemplo", "2026-08-20 06:38:36")}
f2 = {"certificate:1": el("certificado", 1, "web.ejemplo", "2026-08-20 06:43:14")}
f3 = {"certificate:1": el("certificado", 1, "web.ejemplo", "2026-08-20 06:43:22")}
todo.append(caso("misma cosa reescrita sola, con fechas distintas",
    {"node-a": {"elementos": f1}, "node-b": {"elementos": f2},
     "node-c": {"elementos": f3}}, 0, None))

# 7. Si la marca temporal empata pero el contenido no, no existe un ganador
# seguro. Debe declararse conflicto para que la sincronizacion automatica no
# elija por el orden casual de respuesta de los nodos.
empate_a = {"certificate:1": el(
    "certificado", 1, "web.ejemplo", "2026-08-28 10:00:00", contenido="cert-a")}
empate_b = {"certificate:1": el(
    "certificado", 1, "web.ejemplo", "2026-08-28 10:00:00", contenido="cert-b")}
empate = inv.comparar({
    "node-a": {"elementos": empate_a},
    "node-b": {"elementos": empate_b},
})
empate_ok = (empate["conflictos"] == ["certificate:1"] and
             empate["diferencias"][0]["gana"] is None and
             empate["un_solo_ganador"] is None)
todo.append(empate_ok)
print(f"{'OK ' if empate_ok else 'MAL'} empate de fecha con huellas distintas es conflicto")

print()
print("TODO BIEN" if all(todo) else "HAY FALLOS")
sys.exit(0 if all(todo) else 1)
