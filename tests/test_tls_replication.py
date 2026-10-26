from __future__ import annotations

import ast
import datetime
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PANEL = Path(__file__).resolve().parents[1] / "docker/guardian/panel"
sys.path.insert(0, str(PANEL))
import certificados_tls as tls
import replica


def material(nombre="service.example.test", minutes_before=1):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=minutes_before))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())


class TestTLSReplication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="npmg-tls-test-")
        self.root = Path(self.temp.name)
        self.data, self.le, self.backups = [self.root / n for n in ("data", "le", "backups")]
        self.data.mkdir()
        self.archive = self.le / "archive/npm-1"
        self.archive.mkdir(parents=True)
        self.live = self.le / "live/npm-1"
        self.live.mkdir(parents=True)
        self.cert, self.key = material()
        self.old_cert, self.wrong_key = material()
        (self.archive / "fullchain1.pem").write_bytes(self.cert)
        (self.archive / "cert1.pem").write_bytes(self.cert)
        (self.archive / "chain1.pem").write_bytes(b"")
        (self.archive / "privkey1.pem").write_bytes(self.key)
        (self.live / "fullchain.pem").symlink_to("../../archive/npm-1/fullchain1.pem")
        (self.live / "privkey.pem").symlink_to("../../archive/npm-1/privkey1.pem")
        (self.live / "cert.pem").symlink_to("../../archive/npm-1/cert1.pem")
        (self.live / "chain.pem").symlink_to("../../archive/npm-1/chain1.pem")
        with sqlite3.connect(self.data / "database.sqlite") as db:
            db.execute("create table certificate(id integer, provider text, is_deleted integer, expires_on text)")
            db.execute("insert into certificate values(1,'letsencrypt',0,'old-expiry')")
            db.execute("create table proxy_host(id integer, domain_names text)")
            db.execute("insert into proxy_host values(9,'[\"new.example.test\"]')")
        self.paths = mock.patch.multiple(replica, RUTA_DATOS=str(self.data),
                                        RUTA_LE=str(self.le), RUTA_RESPALDOS=str(self.backups))
        self.paths.start()

    def tearDown(self):
        self.paths.stop()
        self.temp.cleanup()

    def break_key(self):
        (self.archive / "privkey1.pem").write_bytes(self.wrong_key)

    def test_valid_pair_needs_no_peer_or_write(self):
        fetch = mock.Mock()
        result = tls.recuperar(self.data, self.le, self.backups, fetch)
        self.assertEqual(result["certificados_recuperados"], [])
        fetch.assert_not_called()
        self.assertFalse(self.backups.exists())

    def test_invalid_pair_is_rejected(self):
        self.break_key()
        with self.assertRaises(tls.ErrorTLS):
            tls.validar(self.data, self.le)

    def test_matching_local_key_recovers_current_certificate(self):
        self.break_key()
        (self.archive / "privkey2.pem").write_bytes(self.key)
        result = tls.recuperar(self.data, self.le, self.backups)
        self.assertEqual(result["certificados_recuperados"], [1])
        self.assertEqual((self.live / "fullchain.pem").read_bytes(), self.cert)
        self.assertEqual((self.live / "privkey.pem").read_bytes(), self.key)

    def test_peer_recovery_preserves_new_host_and_current_certificate(self):
        self.break_key()
        original_db = (self.data / "database.sqlite").read_bytes()
        result = tls.recuperar(self.data, self.le, self.backups, lambda ids: [(1, self.key)])
        self.assertEqual(result["certificados_recuperados"], [1])
        self.assertEqual((self.data / "database.sqlite").read_bytes(), original_db)
        self.assertEqual((self.live / "fullchain.pem").read_bytes(), self.cert)
        self.assertEqual(next((self.backups / "tls-recovery").glob("*.key")).read_bytes(), self.wrong_key)

    def test_older_certificate_key_is_not_a_recovery_candidate(self):
        self.break_key()
        with self.assertRaises(tls.ErrorTLS):
            tls.recuperar(self.data, self.le, self.backups, lambda ids: [(1, self.wrong_key)])
        self.assertEqual((self.live / "fullchain.pem").read_bytes(), self.cert)

    def test_recovery_stops_after_finding_the_exact_key(self):
        self.break_key()
        def fetch(ids):
            yield 1, self.key
            raise RuntimeError("No debe consultar otro par")
        self.assertTrue(tls.recuperar(self.data, self.le, self.backups, fetch)["ok"])

    def test_key_for_other_id_is_not_accepted(self):
        self.break_key()
        with self.assertRaises(tls.ErrorTLS):
            tls.recuperar(self.data, self.le, self.backups, lambda ids: [(2, self.key)])

    def test_newer_valid_pair_preserves_new_host_and_updates_expiry(self):
        self.break_key()
        cert, key = material(minutes_before=0)
        result = tls.recuperar(self.data, self.le, self.backups,
                               lambda ids: [(1, {"key": key, "fullchain": cert})])
        self.assertEqual(result["certificados_mas_recientes"], [1])
        self.assertEqual((self.live / "fullchain.pem").read_bytes(), cert)
        self.assertEqual((self.live / "privkey.pem").read_bytes(), key)
        with sqlite3.connect(self.data / "database.sqlite") as db:
            self.assertEqual(db.execute("select domain_names from proxy_host where id=9").fetchone()[0], '["new.example.test"]')
            self.assertNotEqual(db.execute("select expires_on from certificate where id=1").fetchone()[0], "old-expiry")

    def test_valid_older_pair_does_not_replace_today_certificate(self):
        self.break_key()
        cert, key = material(minutes_before=5)
        with self.assertRaises(tls.ErrorTLS):
            tls.recuperar(self.data, self.le, self.backups,
                          lambda ids: [(1, {"key": key, "fullchain": cert})])

    def test_newer_pair_for_different_names_is_rejected(self):
        self.break_key()
        cert, key = material("other.example.test", minutes_before=0)
        with self.assertRaises(tls.ErrorTLS):
            tls.recuperar(self.data, self.le, self.backups,
                          lambda ids: [(1, {"key": key, "fullchain": cert})])

    def test_role_change_prevents_writing(self):
        self.break_key()
        guard = mock.Mock(side_effect=replica.RolCambiado("changed"))
        with self.assertRaises(replica.RolCambiado):
            tls.recuperar(self.data, self.le, self.backups, lambda ids: [(1, self.key)], guard)
        self.assertEqual((self.live / "privkey.pem").read_bytes(), self.wrong_key)

    def test_certificate_rotating_during_lookup_is_not_overwritten(self):
        self.break_key()
        def fetch(ids):
            (self.archive / "fullchain1.pem").write_bytes(self.old_cert)
            return [(1, self.key)]
        with self.assertRaises(tls.ErrorTLS):
            tls.recuperar(self.data, self.le, self.backups, fetch)
        self.assertEqual((self.live / "privkey.pem").read_bytes(), self.wrong_key)

    def test_paths_outside_certificate_storage_are_rejected(self):
        outside = self.root / "private.key"
        outside.write_bytes(self.key)
        (self.live / "privkey.pem").unlink()
        (self.live / "privkey.pem").symlink_to(outside)
        with self.assertRaises(tls.ErrorTLS):
            tls.validar(self.data, self.le)

    def test_sender_rejects_bad_tls_before_export(self):
        self.break_key()
        with self.assertRaisesRegex(replica.ErrorReplica, "clave privada"):
            replica.empaquetar()

    def test_receiver_rejects_bad_tls_before_stopping_npm(self):
        self.break_key()
        package = replica.empaquetar(validar_tls=False)
        with mock.patch.object(replica.dockerd, "parar") as stop:
            with self.assertRaisesRegex(replica.ErrorReplica, "clave privada"):
                replica.aplicar(package, soy_el_activo=False)
        stop.assert_not_called()

    def test_scheduled_sync_uses_recovery_without_force(self):
        tree = ast.parse((PANEL / "servidor.py").read_text(encoding="utf-8"))
        funcs = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ("_sincronizar", "_sincronizacion_programada")]
        recovery = mock.Mock(return_value={"ok": True, "certificados_recuperados": [1]})
        reload = mock.Mock()
        namespace = {"quien_manda": lambda: {"soy_yo": True}, "PARES": [],
                     "NODO": "node-a", "dockerd": types.SimpleNamespace(recargar_nginx=reload, ErrorDocker=RuntimeError),
                     "replica": types.SimpleNamespace(recuperar_tls=recovery, CONTENEDOR="npm", ErrorReplica=RuntimeError),
                     "sincronia": lambda: {"en_sincronia": True},
                     "_confirmar_sincronia_pares": lambda: {"ok": True, "complete": True},
                     "_reconciliar_guardian_desde_pares": lambda **kw: {"ok": True},
                     "_replicar_configuracion": lambda: {"ok": True}}
        exec(compile(ast.Module(body=funcs, type_ignores=[]), "<scheduled-sync>", "exec"), namespace)
        namespace["sincronizar"] = namespace["_sincronizar"]
        self.assertTrue(namespace["_sincronizacion_programada"]()["ok"])
        recovery.assert_called_once()
        reload.assert_called_once_with("npm")


if __name__ == "__main__":
    unittest.main()
