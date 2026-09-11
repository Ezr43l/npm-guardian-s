from __future__ import annotations

import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker" / "guardian" / "panel"))
DATA = tempfile.mkdtemp(prefix="npm-guardian-http-")
os.environ.update({
    "NPMG_DATA_DIR": DATA,
    "NPMG_CONFIG_FILE": str(Path(DATA) / "guardian.json"),
    "NPMG_SESSION_SECRET": "http-session-secret-for-tests-that-is-long",
    "NPMG_CLUSTER_TOKEN": "http-cluster-token-for-tests-that-is-different",
    "NPMG_STANDALONE": "1",
    "NPMG_NODE_NAME": "node-http",
    # Este servidor de pruebas sólo escucha en loopback y no dispone de un
    # terminador TLS. Producción exige HTTPS salvo este opt-in explícito.
    "NPMG_ALLOW_INSECURE_PORTAL": "1",
})

import configuracion  # noqa: E402
import protocolo_cluster  # noqa: E402
import servidor  # noqa: E402
import vigilante  # noqa: E402


class TestHttpContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # unittest importa todos los modulos antes de ejecutarlos; se cambia el
        # almacenamiento al empezar esta clase, una vez acabadas las otras.
        configuracion.DATOS = DATA
        configuracion.RUTA = str(Path(DATA) / "guardian.json")
        configuracion.RUTA_BACKUP = configuracion.RUTA + ".bak"
        vigilante.RUTA_ESTADO = str(Path(DATA) / "vigilancia.json")
        vigilante.RUTA_ESTADO_BACKUP = vigilante.RUTA_ESTADO + ".bak"
        servidor.MODO_INDEPENDIENTE = True
        servidor.NODO = "node-http"
        configuracion._cache = None
        cls.server = servidor.Servidor(("127.0.0.1", 0), servidor.Manejador)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(DATA, ignore_errors=True)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        encoded = (body if isinstance(body, bytes) else
                   json.dumps(body).encode() if body is not None else None)
        all_headers = dict(headers or {})
        if encoded is not None and "Content-Type" not in all_headers:
            all_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=encoded, headers=all_headers)
        response = connection.getresponse()
        raw = response.read()
        result = (response.status, dict(response.getheaders()), raw)
        connection.close()
        return result

    def login_for_sensitive_mutation(self):
        profile = {"id": "17", "username": "http-admin@example.test",
                   "display_name": "HTTP Admin"}
        with mock.patch.object(servidor.npm_api, "autenticar_usuario",
                               return_value=profile), \
                mock.patch.object(servidor, "_replicar_configuracion_sin_candado",
                                  return_value={"ok": True, "complete": True}):
            status, headers, body = self.request("POST", "/api/session", {
                "username": profile["username"], "password": "npm-password",
            })
        self.assertEqual(status, 200, body.decode())
        session = json.loads(body)
        return (headers["Set-Cookie"].split(";", 1)[0],
                session["csrf_token"])

    def test_plain_http_is_rejected_by_default_without_an_explicit_opt_in(self):
        with mock.patch.object(servidor, "PERMITIR_PORTAL_INSEGURO", False), \
                mock.patch.object(servidor, "REDES_PROXY", []), \
                mock.patch.object(servidor.npm_api, "esquema_api") as npm_scheme, \
                self.assertRaisesRegex(
                    configuracion.ErrorConfiguracion,
                    "NPMG_ALLOW_INSECURE_PORTAL"):
            servidor._validar_transporte()
        npm_scheme.assert_not_called()

    def test_health_is_minimal_and_version_has_no_node_identity(self):
        status, _, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "ok"})
        status, _, body = self.request("GET", "/api/version")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {
            "product": "NPM Guardian", "version": servidor.VERSION})

    def test_active_login_csrf_and_settings(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"id=\"login-view\"", body)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")

        status, _, body = self.request("GET", "/api/public/status")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["setup_required"])

        with mock.patch.object(
                servidor.npm_api, "autenticar_usuario",
                side_effect=servidor.npm_api.ErrorNPM("NPM no disponible", "unavailable")):
            status, _, body = self.request("POST", "/api/session", {
                "username": "http-admin@example.test", "password": "npm-password",
            })
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["code"], "NPM_AUTH_UNAVAILABLE")

        npm_profile = {"id": "17", "username": "http-admin@example.test",
                       "display_name": "HTTP Admin"}
        with mock.patch.object(servidor.npm_api, "autenticar_usuario",
                               return_value=npm_profile) as authenticate:
            status, headers, body = self.request("POST", "/api/session", {
                "username": "http-admin@example.test", "password": "npm-password",
            })
        self.assertEqual(status, 200)
        authenticate.assert_called_once_with("node-http", "http-admin@example.test",
                                             "npm-password")
        session = json.loads(body)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])

        status, _, body = self.request("GET", "/api/public/status")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["setup_required"])
        self.assertNotIn("password_hash", Path(configuracion.RUTA).read_text(encoding="utf-8"))

        status, _, _ = self.request("GET", "/api/config", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        status, _, body = self.request("POST", "/api/config", {}, {"Cookie": cookie})
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["code"], "CSRF_REQUIRED")

        status, _, body = self.request("POST", "/api/profile/password", {}, {
            "Cookie": cookie, "X-CSRF-Token": session["csrf_token"],
        })
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["code"], "NPM_REAUTH_REQUIRED")
        with mock.patch.object(servidor.npm_api, "validar_token_usuario",
                               return_value=True):
            status, _, body = self.request("POST", "/api/profile/password", {}, {
                "Cookie": cookie, "X-CSRF-Token": session["csrf_token"],
            })
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["code"], "PASSWORD_MANAGED_BY_NPM")

        emergency_payload = {
            "username": "http-admin@example.test", "emergency": True,
            "recovery_code": "AAAA-BBBB-CCCC-DDDD",
        }
        with mock.patch.object(servidor.npm_api, "autenticacion_disponible",
                               return_value=True):
            status, _, body = self.request("POST", "/api/session", emergency_payload)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["code"], "NPM_AUTH_AVAILABLE")

        with mock.patch.object(servidor.npm_api, "autenticacion_disponible",
                               return_value=False):
            status, _, body = self.request("POST", "/api/session", {
                "username": "http-admin@example.test", "emergency": True,
                "recovery_code": "AAAA-BBBB-CCCC-DDDD",
            })
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["code"], "EMERGENCY_ACCESS_NOT_CONFIGURED")

        payload = {
            "sync": {"enabled": True, "cron": "*/15 * * * *"},
            "namecheap": {"enabled": False, "api_user": "", "api_key": None},
            "renewal": {"days_before_expiry": 35, "warning_days": 15,
                        "max_automatic_attempts": 4},
            "npm_api": {"user": "", "password": None, "port": 81,
                        "https_port": 443, "timeout_seconds": 720},
        }
        with mock.patch.object(servidor.npm_api, "validar_token_usuario",
                               return_value=True):
            status, _, body = self.request("POST", "/api/config", payload, {
                "Cookie": cookie, "X-CSRF-Token": session["csrf_token"],
            })
        self.assertEqual(status, 200, body.decode())

    def test_passive_never_serves_full_portal(self):
        original_mode = servidor.MODO_INDEPENDIENTE
        original_request = servidor._pedir
        try:
            servidor.MODO_INDEPENDIENTE = False
            servidor._pedir = lambda *_args, **_kwargs: {"direcciones": [{
                "servicio": servidor.SERVICIO_FLOTANTE, "estado": "en_uso",
                "portador": "node-other", "ip": "192.0.2.20",
            }]}
            for path in ("/", "/index.html"):
                status, _, body = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertIn(b"Este nodo est", body)
                self.assertNotIn(b"id=\"config-form\"", body)
            status, _, body = self.request("GET", "/api/config")
            self.assertEqual(status, 409)
            self.assertEqual(json.loads(body)["code"], "PASSIVE_NODE")
        finally:
            servidor.MODO_INDEPENDIENTE = original_mode
            servidor._pedir = original_request

    def test_passive_receive_records_operational_timestamp(self):
        original_mode = servidor.MODO_INDEPENDIENTE
        original_request = servidor._pedir
        original_peers = servidor.PARES
        try:
            servidor.MODO_INDEPENDIENTE = False
            servidor.PARES = [{"nombre": "node-other", "url": "http://node-other:6061"}]
            servidor._pedir = lambda *_args, **_kwargs: {"direcciones": [{
                "servicio": servidor.SERVICIO_FLOTANTE, "estado": "en_uso",
                "portador": "node-other", "ip": "192.0.2.20",
            }]}
            ruta = "/api/internal/receive"
            paquete = b"paquete-prueba"
            sobre = protocolo_cluster.cifrar(
                paquete, "replica", "node-other", "node-http")
            signed = protocolo_cluster.firmar(
                "POST", ruta, "node-other", "node-http", sobre)
            nonce = signed["X-NPMG-Nonce"]
            with mock.patch.object(servidor.replica, "aplicar",
                                   return_value={"aplicado": True}), \
                    mock.patch.object(configuracion, "guardar_estado_operativo") as guardar:
                status, _, body = self.request(
                    "POST", ruta, sobre,
                    {"Content-Type": "application/json", **signed})
                self.assertEqual(status, 200, body.decode())
                respuesta = json.loads(protocolo_cluster.descifrar(
                    body, f"response:{ruta}", "node-http", "node-other",
                    contexto=nonce).decode())
                self.assertEqual(respuesta, {
                    "aplicado": True,
                    "topology_verified": False,
                    "topology_fingerprint": None,
                })
                servidor.replica.aplicar.assert_called_once()
                self.assertEqual(servidor.replica.aplicar.call_args.args[0], paquete)
                guardar.assert_called_once()
                marca = guardar.call_args.args[0]["last_received_sync"]
                self.assertIsInstance(marca, float)
        finally:
            servidor.MODO_INDEPENDIENTE = original_mode
            servidor._pedir = original_request
            servidor.PARES = original_peers

    def test_active_can_export_once_from_the_unique_passive_source(self):
        original_mode = servidor.MODO_INDEPENDIENTE
        original_request = servidor._pedir
        original_peers = servidor.PARES
        try:
            servidor.MODO_INDEPENDIENTE = False
            servidor.PARES = [{"nombre": "node-other", "url": "http://node-other:6061"}]
            servidor._pedir = lambda *_args, **_kwargs: {"direcciones": [{
                "servicio": servidor.SERVICIO_FLOTANTE, "estado": "en_uso",
                "portador": "node-other", "ip": "192.0.2.20",
            }]}
            route = "/api/internal/export"
            signed = protocolo_cluster.firmar(
                "GET", route, "node-other", "node-http", b"")
            with mock.patch.object(servidor, "_huella_logica",
                                   return_value="a" * 64), \
                    mock.patch.object(servidor.replica, "empaquetar",
                                      return_value=b"validated-snapshot") as package:
                first = self.request("GET", route, headers=signed)
                second = self.request("GET", route, headers=signed)

            self.assertEqual(first[0], 200, first[2].decode(errors="replace"))
            plain = protocolo_cluster.descifrar(
                first[2], f"response:{route}", "node-http", "node-other",
                contexto=signed["X-NPMG-Nonce"])
            self.assertEqual(plain, b"a" * 64 + b"\nvalidated-snapshot")
            self.assertEqual(second[0], 409, second[2].decode(errors="replace"))
            self.assertEqual(json.loads(second[2])["code"],
                             "CLUSTER_REPLAY_DETECTED")
            package.assert_called_once()
        finally:
            servidor.MODO_INDEPENDIENTE = original_mode
            servidor._pedir = original_request
            servidor.PARES = original_peers

    def test_internal_write_replay_is_rejected_before_second_apply(self):
        original_mode = servidor.MODO_INDEPENDIENTE
        original_request = servidor._pedir
        original_peers = servidor.PARES
        try:
            servidor.MODO_INDEPENDIENTE = False
            servidor.PARES = [{"nombre": "node-other", "url": "http://node-other:6061"}]
            servidor._pedir = lambda *_args, **_kwargs: {"direcciones": [{
                "servicio": servidor.SERVICIO_FLOTANTE, "estado": "en_uso",
                "portador": "node-other", "ip": "192.0.2.20",
            }]}
            ruta = "/api/internal/receive"
            sobre = protocolo_cluster.cifrar(
                b"snapshot", "replica", "node-other", "node-http")
            signed = protocolo_cluster.firmar(
                "POST", ruta, "node-other", "node-http", sobre)
            with mock.patch.object(servidor.replica, "aplicar",
                                   return_value={"ok": True}) as apply_replica:
                first = self.request("POST", ruta, sobre,
                                     {"Content-Type": "application/json", **signed})
                second = self.request("POST", ruta, sobre,
                                      {"Content-Type": "application/json", **signed})
            self.assertEqual(first[0], 200, first[2].decode())
            self.assertEqual(second[0], 409, second[2].decode())
            self.assertEqual(json.loads(second[2])["code"], "CLUSTER_REPLAY_DETECTED")
            apply_replica.assert_called_once()
        finally:
            servidor.MODO_INDEPENDIENTE = original_mode
            servidor._pedir = original_request
            servidor.PARES = original_peers

    @mock.patch.object(
        servidor,
        "quien_manda",
        new=mock.Mock(return_value={"soy_yo": False, "activo": "node-other"}),
    )
    def test_sync_heartbeat_is_recorded_only_for_the_matching_semantic_hash(self):
        original_mode = servidor.MODO_INDEPENDIENTE
        original_peers = servidor.PARES
        servidor.MODO_INDEPENDIENTE = False
        servidor.PARES = [{
            "nombre": "node-other", "url": "https://node-other:6061",
        }]
        route = "/api/internal/sync-confirm"

        def signed_request(inventory_hash):
            payload = json.dumps({
                "schema": 1, "inventory_hash": inventory_hash,
            }).encode()
            envelope = protocolo_cluster.cifrar(
                payload, "sync-confirm", "node-other", "node-http")
            signed = protocolo_cluster.firmar(
                "POST", route, "node-other", "node-http", envelope)
            return self.request(
                "POST", route, envelope,
                {"Content-Type": "application/json", **signed})

        try:
            with mock.patch.object(servidor, "_huella_sincronia",
                                   return_value="a" * 64), \
                    mock.patch.object(configuracion, "guardar_estado_operativo") as save:
                status, _, body = signed_request("a" * 64)
            self.assertEqual(status, 200, body.decode(errors="replace"))
            saved = save.call_args.args[0]
            self.assertIn("last_verified_sync", saved)
            self.assertTrue(saved["last_verified_sync_result"]["ok"])
            self.assertEqual(
                saved["last_verified_sync_result"]["inventory_hash"], "a" * 64)

            with mock.patch.object(servidor, "_huella_sincronia",
                                   return_value="b" * 64), \
                    mock.patch.object(configuracion, "guardar_estado_operativo") as save:
                status, _, _body = signed_request("a" * 64)
            self.assertIn(status, (409, 422))
            save.assert_not_called()
        finally:
            servidor.MODO_INDEPENDIENTE = original_mode
            servidor.PARES = original_peers

    def test_manual_renewal_uses_reserved_manual_quota_path(self):
        servidor.MODO_INDEPENDIENTE = True
        profile = {"id": "17", "username": "http-admin@example.test",
                   "display_name": "HTTP Admin"}
        with mock.patch.object(servidor.npm_api, "autenticar_usuario",
                               return_value=profile):
            status, headers, body = self.request("POST", "/api/session", {
                "username": profile["username"], "password": "npm-password",
            })
        self.assertEqual(status, 200, body.decode())
        session = json.loads(body)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        with mock.patch.object(servidor.npm, "certificados", return_value=[
                {"id": 7, "nombre": "manual.example.test",
                 "dominios": ["manual.example.test"]}]), \
                mock.patch.object(servidor.npm_api, "validar_token_usuario",
                                  return_value=True), \
                mock.patch.object(servidor.vigilante, "renovar",
                                  return_value={"ok": False, "hecho": False}) as renew, \
                mock.patch.object(servidor, "sincronizar") as synchronize:
            status, _, body = self.request("POST", "/api/renovar/7", {}, {
                "Cookie": cookie, "X-CSRF-Token": session["csrf_token"],
            })
        self.assertEqual(status, 200, body.decode())
        renew.assert_called_once_with(
            7, "manual.example.test", "node-http", manual=True,
            dominios=["manual.example.test"])
        synchronize.assert_not_called()

    def test_config_route_rolls_back_when_cluster_quorum_is_missing(self):
        cookie, csrf = self.login_for_sensitive_mutation()
        before = configuracion.exportar()

        def mutate(_incoming):
            def change(document):
                document["settings"]["sync"]["cron"] = "17 * * * *"
            configuracion.actualizar(change)
            return configuracion.leer()

        replication = mock.Mock(side_effect=[
            {"ok": False, "acknowledged": 1, "quorum": 2},
            {"ok": True, "acknowledged": 2, "quorum": 2},
        ])
        with mock.patch.object(servidor.npm_api, "validar_token_usuario",
                               return_value=True), \
                mock.patch.object(configuracion, "guardar_ajustes",
                                  side_effect=mutate), \
                mock.patch.object(servidor, "_replicar_configuracion_sin_candado",
                                  replication):
            status, headers, body = self.request("POST", "/api/config", {}, {
                "Cookie": cookie, "X-CSRF-Token": csrf,
            })

        self.assertEqual(status, 503, body.decode())
        self.assertEqual(json.loads(body)["code"], "CLUSTER_STATE_NOT_REPLICATED")
        after = configuracion.exportar()
        self.assertEqual(after["settings"], before["settings"])
        self.assertEqual(after["account"], before["account"])
        self.assertGreater(after["revision"], before["revision"])
        self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(replication.call_count, 2)

    def test_quorum_failure_does_not_return_a_2fa_session(self):
        cookie, csrf = self.login_for_sensitive_mutation()
        before = configuracion.exportar()

        def enable(_code):
            def change(document):
                document["settings"]["sync"]["cron"] = "18 * * * *"
            configuracion.actualizar(change)
            return (configuracion.leer()["account"],
                    ["RECOVERY-CODE-MUST-NOT-LEAK"])

        replication = mock.Mock(side_effect=[
            {"ok": False, "acknowledged": 1, "quorum": 2},
            {"ok": True, "acknowledged": 2, "quorum": 2},
        ])
        with mock.patch.object(servidor.npm_api, "validar_token_usuario",
                               return_value=True), \
                mock.patch.object(servidor.seguridad, "activar_2fa",
                                  side_effect=enable), \
                mock.patch.object(servidor, "_replicar_configuracion_sin_candado",
                                  replication):
            status, headers, body = self.request(
                "POST", "/api/profile/2fa/enable", {"code": "123456"}, {
                    "Cookie": cookie, "X-CSRF-Token": csrf,
                })

        self.assertEqual(status, 503, body.decode())
        self.assertEqual(json.loads(body)["code"], "CLUSTER_STATE_NOT_REPLICATED")
        after = configuracion.exportar()
        self.assertEqual(after["settings"], before["settings"])
        self.assertEqual(after["account"], before["account"])
        self.assertGreater(after["revision"], before["revision"])
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn(b"123456", body)

    def test_recovery_codes_are_not_disclosed_when_cluster_quorum_is_missing(self):
        cookie, csrf = self.login_for_sensitive_mutation()
        before = configuracion.exportar()
        plaintext = "RECOVERY-CODE-MUST-NOT-LEAK"

        def regenerate(_code):
            def change(document):
                document["settings"]["sync"]["cron"] = "19 * * * *"
            configuracion.actualizar(change)
            return [plaintext]

        replication = mock.Mock(side_effect=[
            {"ok": False, "acknowledged": 1, "quorum": 2},
            {"ok": True, "acknowledged": 2, "quorum": 2},
        ])
        with mock.patch.object(servidor.npm_api, "validar_token_usuario",
                               return_value=True), \
                mock.patch.object(servidor, "_reautenticar_cuenta",
                                  return_value=True), \
                mock.patch.object(servidor.seguridad, "regenerar_recuperacion",
                                  side_effect=regenerate), \
                mock.patch.object(servidor, "_replicar_configuracion_sin_candado",
                                  replication):
            status, headers, body = self.request(
                "POST", "/api/profile/2fa/recovery-codes", {
                    "current_password": "npm-password", "code": "123456",
                }, {"Cookie": cookie, "X-CSRF-Token": csrf})

        self.assertEqual(status, 503, body.decode())
        self.assertEqual(json.loads(body)["code"], "CLUSTER_STATE_NOT_REPLICATED")
        after = configuracion.exportar()
        self.assertEqual(after["settings"], before["settings"])
        self.assertEqual(after["account"], before["account"])
        self.assertGreater(after["revision"], before["revision"])
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn(plaintext.encode(), body)

    def test_ui_uses_only_application_dialogs(self):
        status, _, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b'id="app-dialog-layer"', page)
        self.assertIn(b'id="toast-region"', page)

        for path in ("/app.js", "/passive.js"):
            status, _, script = self.request("GET", path)
            self.assertEqual(status, 200)
            for native_call in (b"alert(", b"confirm(", b"prompt(",
                                b"window.alert", b"window.confirm", b"window.prompt"):
                with self.subTest(path=path, native_call=native_call):
                    self.assertNotIn(native_call, script)
        self.assertIn(b"confirmAction(", self.request("GET", "/app.js")[2])
        self.assertIn(b"notify(", self.request("GET", "/app.js")[2])

    def test_state_dashboard_prioritizes_structured_operational_status(self):
        status, _, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        namecheap = page.index(b'id="namecheap-card"')
        floating_ip = page.index(b'id="ha-card"')
        cluster = page.index(b'id="nodes-summary"')
        synchronization = page.index(b'id="sincronia"')
        certificates = page.index(b'id="cuerpo-certs"')
        self.assertLess(namecheap, floating_ip)
        self.assertLess(floating_ip, cluster)
        self.assertLess(cluster, synchronization)
        self.assertLess(synchronization, certificates)
        for element_id in (
                b'namecheap-status', b'namecheap-ip', b'namecheap-readiness',
                b'active-node', b'floating-ip', b'role-source',
                b'cert-total', b'cert-risk', b'proxy-total'):
            with self.subTest(element_id=element_id):
                self.assertIn(b'id="' + element_id + b'"', page)
        self.assertNotIn(b'id="namecheap-section"', page)

        status, _, script = self.request("GET", "/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"sin_saber_quien_manda", script)
        self.assertNotIn(b"namecheap-section", script)


if __name__ == "__main__":
    unittest.main()
