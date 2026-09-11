"""Smoke test autocontenido del contrato seguro de réplica.

Se ejecuta dentro de la imagen publicada. Construye un estado NPM mínimo pero
real (incluida una SQLite válida), genera el paquete con el código de producción
y comprueba sus defensas sin tocar Docker ni los datos del servidor.
"""
import io
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile


ROOT = tempfile.mkdtemp(prefix="npmg-smoke-replica-")
DATA = os.path.join(ROOT, "npm")
LE = os.path.join(ROOT, "letsencrypt")
BACKUPS = os.path.join(ROOT, "backups")
os.makedirs(DATA)
os.makedirs(LE)
os.environ["NPMG_NPM_DATA"] = DATA
os.environ["NPMG_NPM_LETSENCRYPT"] = LE
os.environ["NPMG_DATA_DIR"] = BACKUPS
sys.path.insert(0, "/opt/panel")

import dockerd  # noqa: E402
import replica  # noqa: E402


connection = sqlite3.connect(os.path.join(DATA, "database.sqlite"))
connection.execute("create table smoke (value text not null)")
connection.execute("insert into smoke values ('coherent snapshot')")
connection.commit()
connection.close()
os.makedirs(os.path.join(DATA, "nginx"))
with open(os.path.join(DATA, "nginx", "proxy.conf"), "w", encoding="utf-8") as output:
    output.write("server {}")
os.makedirs(os.path.join(DATA, "access"))
with open(os.path.join(DATA, "access", "access.log"), "w", encoding="utf-8") as output:
    output.write("smoke")
os.makedirs(os.path.join(LE, "renewal-hooks", "deploy"))
with open(os.path.join(LE, "renewal-hooks", "deploy", "reload.sh"),
          "w", encoding="utf-8") as output:
    output.write("#!/bin/sh\n")


results = []


def case(title, operation, expected_error=None):
    try:
        operation()
        actual = "ok"
    except replica.ErrorReplica as error:
        actual = str(error)
    passed = ((expected_error is None and actual == "ok") or
              (expected_error is not None and expected_error in actual))
    results.append(passed)
    print(f"{'OK ' if passed else 'BAD'} {title}\n     -> {actual[:100]}")


def validate_archive(payload):
    extracted = replica._extraer_validado(payload)
    shutil.rmtree(extracted, ignore_errors=True)


def archive_with_member(member):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        archive.addfile(member, io.BytesIO(b"x") if member.isreg() else None)
    with tarfile.open(fileobj=io.BytesIO(buffer.getvalue()), mode="r:gz") as archive:
        replica._validar_paquete(archive)


valid = replica.empaquetar()
case("a generated package has a valid manifest and SQLite snapshot",
     lambda: validate_archive(valid))
case("an active node refuses inbound state",
     lambda: replica.aplicar(valid, soy_el_activo=True), "activo")

original_docker_state = dockerd.estado
try:
    dockerd.estado = lambda _container: {"existe": True, "corriendo": False}
    case("a stopped passive NPM is refused instead of being silently rewritten",
         lambda: replica.aplicar(valid, soy_el_activo=False), "marcha")
finally:
    dockerd.estado = original_docker_state

case("a v1 transaction journal records whether NPM was running",
     lambda: replica._validar_cambios_journal({
         "version": 1, "state": "prepared", "was_running": True,
         "keep_new_on_recovery": False,
         "changes": [],
     }))
case("a legacy v1 journal without was_running fails closed",
     lambda: replica._validar_cambios_journal({
         "version": 1, "state": "prepared", "keep_new_on_recovery": False,
         "changes": [],
     }), "journal")
case("a legacy v1 journal without recovery direction fails closed",
     lambda: replica._validar_cambios_journal({
         "version": 1, "state": "prepared", "was_running": True,
         "changes": [],
     }), "journal")

traversal = tarfile.TarInfo("data/../../etc/passwd")
traversal.size = 1
case("path traversal is rejected", lambda: archive_with_member(traversal), "se sale")

absolute_link = tarfile.TarInfo("letsencrypt/live/npm-1/cert.pem")
absolute_link.type = tarfile.SYMTYPE
absolute_link.linkname = "/etc/shadow"
case("absolute symlinks are rejected",
     lambda: archive_with_member(absolute_link), "fuera")


def tampered_package():
    extracted = tempfile.mkdtemp(prefix="npmg-smoke-tamper-")
    try:
        with tarfile.open(fileobj=io.BytesIO(valid), mode="r:gz") as archive:
            archive.extractall(extracted, filter="data")
        with open(os.path.join(extracted, "data", "nginx", "proxy.conf"),
                  "w", encoding="utf-8") as output:
            output.write("tampered")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.add(os.path.join(extracted, "manifest.json"), arcname="manifest.json")
            archive.add(os.path.join(extracted, "data"), arcname="data")
            archive.add(os.path.join(extracted, "letsencrypt"), arcname="letsencrypt")
        validate_archive(buffer.getvalue())
    finally:
        shutil.rmtree(extracted, ignore_errors=True)


case("content changed after the manifest is rejected", tampered_package, "huella")

try:
    dockerd.parar("not-the-configured-npm-container")
    docker_result = "accepted"
except dockerd.ErrorDocker as error:
    docker_result = str(error)
docker_ok = "lista" in docker_result
results.append(docker_ok)
print(f"{'OK ' if docker_ok else 'BAD'} Docker operations are limited to NPM\n"
      f"     -> {docker_result[:100]}")

os.makedirs(BACKUPS, exist_ok=True)
for stamp in ("20260101-000000", "20260102-000000", "20260103-000000",
              "20260104-000000", "20260105-000000"):
    open(os.path.join(BACKUPS, f"{replica.PREFIJO_RESPALDO}{stamp}.tar.gz"), "wb").close()
open(os.path.join(BACKUPS, "unrelated.tar.gz"), "wb").close()
old = [os.path.basename(path) for path in replica._respaldos_a_borrar()]
expected = [f"{replica.PREFIJO_RESPALDO}20260102-000000.tar.gz",
            f"{replica.PREFIJO_RESPALDO}20260101-000000.tar.gz"]
rotation_ok = old == expected and "unrelated.tar.gz" not in [
    os.path.basename(path) for path in replica.respaldos()]
results.append(rotation_ok)
print(f"{'OK ' if rotation_ok else 'BAD'} only old Guardian backups are rotated\n"
      f"     -> {old}")

shutil.rmtree(ROOT, ignore_errors=True)
print("\nALL GOOD" if all(results) else "\nFAILURES")
sys.exit(0 if all(results) else 1)
