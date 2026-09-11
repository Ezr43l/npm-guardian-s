from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "docker" / "guardian" / "panel"
sys.path.insert(0, str(PANEL))

TEST_DATA = tempfile.mkdtemp(prefix="npm-guardian-tests-")
os.environ.update({
    "NPMG_DATA_DIR": TEST_DATA,
    "NPMG_CONFIG_FILE": str(Path(TEST_DATA) / "guardian.json"),
    "NPMG_SESSION_SECRET": "session-secret-for-tests-that-is-long-and-random",
    "NPMG_CLUSTER_TOKEN": "cluster-token-for-tests-that-is-different",
    "NPMG_STANDALONE": "1",
    "NPMG_NODE_NAME": "node-a",
})

import configuracion  # noqa: E402
import dockerd  # noqa: E402
import npm_api  # noqa: E402
import planificador  # noqa: E402
import reintentos  # noqa: E402
import seguridad  # noqa: E402
import vigilante  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        # unittest descubre e importa todos los modulos antes de ejecutar la
        # suite. Reafirmar las rutas evita que otro fichero de pruebas deje el
        # singleton de configuracion apuntando a su directorio temporal.
        configuracion.DATOS = TEST_DATA
        configuracion.RUTA = str(Path(TEST_DATA) / "guardian.json")
        configuracion.RUTA_BACKUP = configuracion.RUTA + ".bak"
        vigilante.RUTA_ESTADO = str(Path(TEST_DATA) / "vigilancia.json")
        vigilante.RUTA_ESTADO_BACKUP = vigilante.RUTA_ESTADO + ".bak"
        for item in Path(TEST_DATA).glob("*"):
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        configuracion._cache = None


class TestCron(unittest.TestCase):
    def test_presets_and_custom_expression(self):
        self.assertTrue(planificador.coincide("*/15 * * * *", datetime(2026, 8, 26, 12, 30)))
        self.assertFalse(planificador.coincide("*/15 * * * *", datetime(2026, 8, 26, 12, 31)))
        self.assertTrue(planificador.coincide("0 3 * * 0", datetime(2026, 8, 30, 3, 0)))

    def test_invalid_cron_is_rejected(self):
        for expression in ("", "* * *", "61 * * * *", "*/0 * * * *", "* 25 * * *"):
            with self.subTest(expression=expression), self.assertRaises(planificador.ErrorCron):
                planificador.validar_cron(expression)

    def test_day_of_month_and_week_use_standard_cron_or_semantics(self):
        expression = "0 3 1 * 1"  # dia 1 O lunes, cuando ambos estan restringidos
        self.assertTrue(planificador.coincide(
            expression, datetime(2026, 6, 8, 3, 0)))   # lunes, no dia 1
        self.assertTrue(planificador.coincide(
            expression, datetime(2026, 8, 1, 3, 0)))   # dia 1, no lunes
        self.assertFalse(planificador.coincide(
            expression, datetime(2026, 8, 2, 3, 0)))   # ninguno

    def test_sunday_accepts_zero_and_seven(self):
        sunday = datetime(2026, 8, 30, 3, 0)
        self.assertTrue(planificador.coincide("0 3 * * 0", sunday))
        self.assertTrue(planificador.coincide("0 3 * * 7", sunday))


class TestConfiguration(Base):
    def payload(self):
        return {
            "sync": {"enabled": True, "cron": "*/30 * * * *"},
            "namecheap": {"enabled": True, "api_user": "api-user", "api_key": "api-secret"},
            "renewal": {"days_before_expiry": 35, "warning_days": 15,
                        "max_automatic_attempts": 4},
            "npm_api": {"user": "admin@example.test", "password": "npm-secret",
                        "port": 81, "https_port": 443, "timeout_seconds": 720},
        }

    def test_new_install_has_optional_namecheap(self):
        self.assertFalse(configuracion.ajustes_publicos()["namecheap"]["enabled"])

    def test_secrets_are_encrypted_and_never_returned(self):
        configuracion.guardar_ajustes(self.payload())
        raw = Path(configuracion.RUTA).read_text(encoding="utf-8")
        self.assertNotIn("api-secret", raw)
        self.assertNotIn("npm-secret", raw)
        self.assertIn("fernet:", raw)
        public = configuracion.ajustes_publicos()
        self.assertTrue(public["namecheap"]["api_key_configured"])
        self.assertNotIn("api_key", public["namecheap"])
        self.assertEqual(configuracion.secretos_namecheap(), ("api-user", "api-secret"))

    def test_safety_limits_cannot_be_weakened(self):
        payload = self.payload()
        payload["renewal"]["max_automatic_attempts"] = 5
        with self.assertRaises(configuracion.ErrorConfiguracion):
            configuracion.guardar_ajustes(payload)
        payload = self.payload()
        payload["renewal"]["days_before_expiry"] = 30
        with self.assertRaises(configuracion.ErrorConfiguracion):
            configuracion.guardar_ajustes(payload)


class TestSecurity(Base):
    PROFILE = {"id": "7", "username": "guardian@example.test",
               "display_name": "Guardian Admin"}

    def test_npm_identity_creates_session_without_password_hash(self):
        token, identity, changed = seguridad.iniciar_npm(
            self.PROFILE, origen="127.0.0.1")
        self.assertTrue(changed)
        self.assertEqual(identity.usuario, "guardian@example.test")
        self.assertEqual(seguridad.sesiones.leer(token).usuario, "guardian@example.test")
        raw = Path(configuracion.RUTA).read_text(encoding="utf-8")
        self.assertNotIn("password_hash", raw)
        self.assertEqual(configuracion.leer()["account"]["npm_user_id"], "7")
        with self.assertRaises(seguridad.ErrorAcceso) as error:
            seguridad.iniciar_npm({**self.PROFILE, "id": "8"}, origen="127.0.0.8")
        self.assertEqual(error.exception.codigo, "NPM_ACCOUNT_NOT_ALLOWED")

    def test_legacy_account_is_migrated_after_npm_authentication(self):
        datos = configuracion.leer()
        datos["account"] = {
            "id": "legacy", "username": self.PROFILE["username"],
            "display_name": self.PROFILE["username"],
            "auth_provider": "local", "npm_user_id": "",
            "password_hash": seguridad.hash_clave("old-local-password"),
            "session_version": 1, "created_at": 1,
            "totp": {"enabled": False, "secret": "", "pending_secret": "",
                     "recovery_code_hashes": []},
        }
        configuracion.guardar(datos)
        _, _, changed = seguridad.iniciar_npm(self.PROFILE, origen="127.0.0.9")
        self.assertTrue(changed)
        cuenta = configuracion.leer()["account"]
        self.assertEqual(cuenta["auth_provider"], "npm")
        self.assertNotIn("password_hash", cuenta)

    def test_totp_setup_and_recovery_codes(self):
        seguridad.iniciar_npm(self.PROFILE, origen="127.0.0.2")
        setup = seguridad.preparar_2fa()
        code = seguridad._totp(setup["secret"], int(time.time()) // 30)
        account, recovery = seguridad.activar_2fa(code)
        self.assertTrue(seguridad.perfil(account)["two_factor_enabled"])
        self.assertEqual(len(recovery), 10)
        with self.assertRaises(seguridad.ErrorAcceso) as error:
            seguridad.iniciar_npm(self.PROFILE, origen="127.0.0.3")
        self.assertEqual(error.exception.codigo, "TWO_FACTOR_REQUIRED")
        _, _, consumed = seguridad.iniciar_npm(
            self.PROFILE, recovery[0], "127.0.0.3")
        self.assertTrue(consumed)
        self.assertEqual(seguridad.perfil()["recovery_codes_remaining"], 9)
        _, _, consumed = seguridad.iniciar_emergencia(
            self.PROFILE["username"], recovery[1], "127.0.0.4")
        self.assertTrue(consumed)
        self.assertEqual(seguridad.perfil()["recovery_codes_remaining"], 8)

    def test_same_recovery_code_cannot_win_two_concurrent_logins(self):
        seguridad.iniciar_npm(self.PROFILE, origen="127.0.1.1")
        setup = seguridad.preparar_2fa()
        code = seguridad._totp(setup["secret"], int(time.time()) // 30)
        _, recovery = seguridad.activar_2fa(code)

        def login(origin):
            try:
                seguridad.iniciar_npm(self.PROFILE, recovery[0], origin)
                return "accepted"
            except seguridad.ErrorAcceso as error:
                return error.codigo

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(login, ("127.0.1.2", "127.0.1.3")))
        self.assertEqual(results.count("accepted"), 1)
        self.assertEqual(results.count("INVALID_SECOND_FACTOR"), 1)
        self.assertEqual(seguridad.perfil()["recovery_codes_remaining"], 9)


class _JsonResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class TestNpmAuthentication(Base):
    def test_login_uses_token_and_requires_admin_profile(self):
        responses = [
            _JsonResponse({"token": "signed-token", "expires": "later"}),
            _JsonResponse({"id": 42, "email": "admin@example.test",
                           "name": "Admin", "roles": ["admin"], "is_disabled": False}),
        ]
        with mock.patch.dict(os.environ, {
                "NPMG_NPM_API_SCHEME": "http",
                "NPMG_ALLOW_INSECURE_NPM_API": "1"}), \
                mock.patch.object(npm_api, "_base_del_activo", return_value="http://npm:81"), \
                mock.patch.object(npm_api.urllib.request, "urlopen", side_effect=responses):
            profile = npm_api.autenticar_usuario("node-a", "admin@example.test", "secret")
        self.assertEqual(profile["id"], "42")
        self.assertEqual(profile["username"], "admin@example.test")

        responses = [
            _JsonResponse({"token": "signed-token"}),
            _JsonResponse({"id": 43, "email": "viewer@example.test",
                           "roles": ["user"], "is_disabled": False}),
        ]
        with mock.patch.dict(os.environ, {
                "NPMG_NPM_API_SCHEME": "http",
                "NPMG_ALLOW_INSECURE_NPM_API": "1"}), \
                mock.patch.object(npm_api, "_base_del_activo", return_value="http://npm:81"), \
                mock.patch.object(npm_api.urllib.request, "urlopen", side_effect=responses), \
                self.assertRaises(npm_api.ErrorNPM) as error:
            npm_api.autenticar_usuario("node-a", "viewer@example.test", "secret")
        self.assertEqual(error.exception.codigo, "admin_required")


class TestNginxActivation(Base):
    @staticmethod
    def _raw_stream(text):
        payload = text.encode()
        return b"\x02\x00\x00\x00" + len(payload).to_bytes(4, "big") + payload

    def test_reload_validates_configuration_and_uses_fixed_commands(self):
        responses = [
            (201, b'{"Id":"exec-test"}'),
            (200, self._raw_stream("syntax is ok\n")),
            (200, b'{"ExitCode":0}'),
            (201, b'{"Id":"exec-reload"}'),
            (200, self._raw_stream("signal process started\n")),
            (200, b'{"ExitCode":0}'),
        ]
        with mock.patch.object(dockerd, "_llamar", side_effect=responses) as call:
            result = dockerd.recargar_nginx("NPM")
        self.assertTrue(result["ok"])
        commands = [entry.kwargs.get("cuerpo", {}).get("Cmd")
                    for entry in call.call_args_list if entry.kwargs.get("cuerpo")]
        self.assertIn(["/usr/sbin/nginx", "-t"], commands)
        self.assertIn(["/usr/sbin/nginx", "-s", "reload"], commands)

    def test_invalid_configuration_prevents_reload(self):
        responses = [
            (201, b'{"Id":"exec-test"}'),
            (200, self._raw_stream("configuration test failed\n")),
            (200, b'{"ExitCode":1}'),
        ]
        with mock.patch.object(dockerd, "_llamar", side_effect=responses) as call, \
                self.assertRaises(dockerd.ErrorDocker):
            dockerd.recargar_nginx("NPM")
        self.assertEqual(call.call_count, 3)

    def test_stale_certificate_is_reloaded_and_checked_again(self):
        stale = {"ok": False, "verificable": True,
                 "caduca_guardado": "2026-11-25T18:17:40+00:00",
                 "caduca_servido": "2026-10-06T12:04:10+00:00"}
        fresh = {**stale, "ok": True,
                 "caduca_servido": "2026-11-25T18:17:40+00:00"}
        with mock.patch.object(vigilante.npm, "comprobar_certificado_servido",
                               side_effect=[stale, fresh]) as check, \
                mock.patch.object(vigilante.dockerd, "recargar_nginx") as reload_nginx, \
                mock.patch.object(vigilante.time, "sleep"):
            served, activation = vigilante._activar_certificado(148, "node-a")
        self.assertTrue(served["ok"])
        self.assertTrue(activation["ok"])
        self.assertTrue(activation["reload_attempted"])
        self.assertEqual(activation["checks"], 2)
        reload_nginx.assert_called_once_with()
        self.assertEqual(check.call_count, 2)

    def test_activation_failure_never_turns_into_another_issuance(self):
        client = mock.Mock()
        client.renovar.return_value = {"id": 148}
        domains = ["cipher.example.test"]
        quota_key = reintentos.clave_san(domains)
        activation = {"ok": False, "reload_attempted": True,
                      "reload_ok": False, "checks": 1, "error": "reload failed"}
        served = {"ok": False, "verificable": True, "motivo": "old certificate",
                  "caduca_guardado": "new", "caduca_servido": "old"}
        with mock.patch.object(vigilante.npm_api, "cliente_del_activo", return_value=client), \
                mock.patch.object(vigilante.npm, "estado_certificado",
                                  return_value={"caduca": "2026-10-06 12:04:10"}), \
                mock.patch.object(vigilante, "_esperar_resultado",
                                  return_value={"caduca": "2026-12-01 00:00:00"}), \
                mock.patch.object(vigilante, "_activar_certificado",
                                  return_value=(served, activation)), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={}), \
                mock.patch.object(vigilante, "_registrar_resultado") as register:
            result = vigilante.renovar(
                148, "cipher.example.test", "node-a", dominios=domains)
        self.assertTrue(result["ok"])
        self.assertTrue(result["emision_ok"])
        self.assertFalse(result["activacion"]["ok"])
        client.renovar.assert_called_once()
        self.assertEqual(client.renovar.call_args.args, (148,))
        self.assertTrue(callable(client.renovar.call_args.kwargs["validar_envio"]))
        register.assert_called_once_with(quota_key, 148, domains, True)


class TestKeepalivedRole(Base):
    def test_only_vip_holder_is_active(self):
        import servidor
        original = servidor._pedir
        original_standalone = servidor.MODO_INDEPENDIENTE
        try:
            servidor.MODO_INDEPENDIENTE = False
            servidor.NODO = "node-a"
            servidor._pedir = lambda *_args, **_kwargs: {"direcciones": [{
                "servicio": "npm", "estado": "en_uso", "portador": "node-b",
                "ip": "192.0.2.20",
            }]}
            self.assertIs(servidor.quien_manda()["soy_yo"], False)
            servidor._pedir = lambda *_args, **_kwargs: {"direcciones": [{
                "servicio": "npm", "estado": "en_uso", "portador": "node-a",
                "ip": "192.0.2.20",
            }]}
            self.assertIs(servidor.quien_manda()["soy_yo"], True)
        finally:
            servidor._pedir = original
            servidor.MODO_INDEPENDIENTE = original_standalone


def tearDownModule():
    shutil.rmtree(TEST_DATA, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
