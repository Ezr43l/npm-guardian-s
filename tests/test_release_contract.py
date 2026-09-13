from __future__ import annotations

import copy
import io
import json
import os
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "docker" / "guardian" / "panel"
sys.path.insert(0, str(PANEL))

os.environ.setdefault(
    "NPMG_SESSION_SECRET", "release-session-9VZ!3mQ#tK2xLp8Wd6Rc1Fy7Hs4Bn")
os.environ.setdefault(
    "NPMG_CLUSTER_TOKEN", "release-cluster-7Qa@4Nx8Vp2Jd9Kt5Zm3Fr6Wy1Lc")
os.environ.setdefault("NPMG_STANDALONE", "1")
os.environ.setdefault("NPMG_NODE_NAME", "release-node")

import avisos  # noqa: E402
import arranque  # noqa: E402
import configuracion  # noqa: E402
import inventario  # noqa: E402
import npm  # noqa: E402
import npm_api  # noqa: E402
import protocolo_cluster  # noqa: E402
import reintentos  # noqa: E402
import replica  # noqa: E402
import vigilante  # noqa: E402


class IsolatedData(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="npmg-release-contract-"))
        self.old_data_env = os.environ.get("NPMG_DATA_DIR")
        os.environ["NPMG_DATA_DIR"] = str(self.temp)
        configuracion.DATOS = str(self.temp)
        configuracion.RUTA = str(self.temp / "guardian.json")
        configuracion.RUTA_BACKUP = configuracion.RUTA + ".bak"
        configuracion._cache = None
        vigilante.RUTA_ESTADO = str(self.temp / "vigilancia.json")
        vigilante.RUTA_ESTADO_BACKUP = vigilante.RUTA_ESTADO + ".bak"

    def tearDown(self):
        configuracion._cache = None
        if self.old_data_env is None:
            os.environ.pop("NPMG_DATA_DIR", None)
        else:
            os.environ["NPMG_DATA_DIR"] = self.old_data_env
        shutil.rmtree(self.temp, ignore_errors=True)


class TestStableVersionContract(unittest.TestCase):
    def test_single_stable_version_source(self):
        self.assertEqual((ROOT / "VERSION").read_text(encoding="utf-8").strip(), "1.0.5")
        self.assertFalse((ROOT / "docker" / "guardian" / "VERSION").exists())
        dockerfile = (ROOT / "docker" / "guardian" / "Dockerfile").read_text(
            encoding="utf-8")
        build_script = (ROOT / "build-image.sh").read_text(encoding="utf-8")
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("COPY VERSION /opt/APP_VERSION", dockerfile)
        self.assertIn("COPY docker/guardian/panel /opt/panel", dockerfile)
        self.assertIn('org.opencontainers.image.version="${APP_VERSION}"', dockerfile)
        self.assertIn('"$RAIZ/VERSION"', build_script)
        self.assertIn('-f "$RAIZ/docker/guardian/Dockerfile"', build_script)
        self.assertIn("PUBLISH", build_script)
        self.assertIn("npm-guardian-s", dockerfile)
        self.assertIn("!.env.example", dockerignore.splitlines())

    def test_runtime_dependencies_and_single_container_socket_are_explicit(self):
        dockerfile = (ROOT / "docker/guardian/Dockerfile").read_text(encoding="utf-8")
        requirements = (ROOT / "docker/guardian/requirements.txt").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("python:3.12-alpine@sha256:", dockerfile)
        self.assertIn("--only-binary=:all:", dockerfile)
        self.assertIn("cryptography==50.0.1", requirements)
        self.assertNotIn("docker-control:", compose)
        self.assertIn("${DOCKER_SOCKET:-/var/run/docker.sock}:/var/run/docker.sock", compose)
        self.assertNotIn("NPMG_DOCKER_SOCKET:", compose)
        self.assertFalse(
            (ROOT / "docker/guardian/panel/docker_proxy.py").exists())
        guardian_xml = (ROOT / "unraid" / "my-NPM-Guardian.xml").read_text(
            encoding="utf-8")
        self.assertIn('Target="/var/run/docker.sock"', guardian_xml)
        self.assertFalse(
            (ROOT / "unraid" / "my-NPM-Guardian-Docker-Control.xml").exists())

    def test_secret_files_and_conflicts(self):
        with tempfile.TemporaryDirectory(prefix="npmg-secret-file-") as directory:
            secret = Path(directory) / "secret"
            secret.write_text("file-secret-value\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {
                    "NPMG_SESSION_SECRET": "",
                    "NPMHA_SESSION_SECRET": "",
                    "NPMG_SESSION_SECRET_FILE": str(secret),
                    "NPMHA_SESSION_SECRET_FILE": "",
            }, clear=False):
                self.assertEqual(
                    configuracion._secreto_entorno(
                        "NPMG_SESSION_SECRET", "NPMHA_SESSION_SECRET"),
                    "file-secret-value")
            with mock.patch.dict(os.environ, {
                    "NPMG_SESSION_SECRET": "direct-secret-value",
                    "NPMHA_SESSION_SECRET": "",
                    "NPMG_SESSION_SECRET_FILE": str(secret),
                    "NPMHA_SESSION_SECRET_FILE": "",
            }, clear=False), self.assertRaises(configuracion.ErrorConfiguracion):
                configuracion._secreto_entorno(
                    "NPMG_SESSION_SECRET", "NPMHA_SESSION_SECRET")

    def test_secret_files_reject_links_and_oversized_content(self):
        with tempfile.TemporaryDirectory(prefix="npmg-secret-hardening-") as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("safe-secret-value", encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError:
                link = None
            if link is not None:
                with mock.patch.dict(os.environ, {
                        "NPMG_SESSION_SECRET": "",
                        "NPMHA_SESSION_SECRET": "",
                        "NPMG_SESSION_SECRET_FILE": str(link),
                        "NPMHA_SESSION_SECRET_FILE": "",
                }, clear=False), self.assertRaisesRegex(
                        configuracion.ErrorConfiguracion, "regular"):
                    configuracion._secreto_entorno(
                        "NPMG_SESSION_SECRET", "NPMHA_SESSION_SECRET")
            grande = root / "oversized"
            grande.write_bytes(b"x" * (16 * 1024 + 1))
            with mock.patch.dict(os.environ, {
                    "NPMG_SESSION_SECRET": "",
                    "NPMHA_SESSION_SECRET": "",
                    "NPMG_SESSION_SECRET_FILE": str(grande),
                    "NPMHA_SESSION_SECRET_FILE": "",
            }, clear=False), self.assertRaisesRegex(
                    configuracion.ErrorConfiguracion, "tamaño"):
                configuracion._secreto_entorno(
                    "NPMG_SESSION_SECRET", "NPMHA_SESSION_SECRET")


class TestKeepalivedApiAuthentication(unittest.TestCase):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def read():
            return b'{"direcciones":[]}'

    def test_keepalived_token_is_sent_only_as_bearer_header(self):
        import servidor

        token = "fip_" + "0" * 72
        with mock.patch.object(servidor, "TOKEN_KEEPALIVED", token), \
                mock.patch.object(servidor.ssl, "create_default_context",
                                  return_value=object()), \
                mock.patch.object(servidor.urllib.request, "urlopen",
                                  return_value=self.Response()) as abrir:
            self.assertEqual(
                servidor._pedir("https://floating.example.test/api/direcciones"),
                {"direcciones": []})

        peticion = abrir.call_args.args[0]
        self.assertEqual(peticion.get_header("Authorization"), f"Bearer {token}")
        self.assertNotIn(token, json.dumps(servidor.quien_manda()))

    def test_missing_token_does_not_invent_an_authorization_header(self):
        import servidor

        with mock.patch.object(servidor, "TOKEN_KEEPALIVED", ""), \
                mock.patch.object(servidor.ssl, "create_default_context",
                                  return_value=object()), \
                mock.patch.object(servidor.urllib.request, "urlopen",
                                  return_value=self.Response()) as abrir:
            servidor._pedir("https://floating.example.test/api/direcciones")

        self.assertIsNone(abrir.call_args.args[0].get_header("Authorization"))

    def test_token_with_header_control_characters_is_rejected(self):
        import servidor

        with mock.patch.object(servidor, "TOKEN_KEEPALIVED", "valid-prefix\nInjected: yes"):
            with self.assertRaises(configuracion.ErrorConfiguracion):
                servidor._validar_transporte()

    def test_public_template_contains_only_docker_wiring(self):
        template = (ROOT / "unraid" / "my-NPM-Guardian.xml").read_text(
            encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        for direct in (
                "NPMG_SESSION_SECRET", "NPMG_CLUSTER_TOKEN",
                "NPMG_KEEPALIVED_API_TOKEN"):
            self.assertNotIn(f'Target="{direct}"', template)
        self.assertIn('Target="/var/run/docker.sock"', template)
        self.assertEqual(template.count("<Config "), 5)
        self.assertNotIn('Type="Variable"', template)
        self.assertNotIn('/run/secrets', template)
        self.assertFalse(
            (ROOT / "unraid" / "my-NPM-Guardian-Docker-Control.xml").exists())
        self.assertNotIn('/run/secrets', compose)
        self.assertNotIn('NPMG_NODE_NAME=', example)
        self.assertNotIn('NPMG_SESSION_SECRET', example)
        self.assertIn('/datos', template)


class TestFirstRunAssistant(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="npmg-first-run-"))
        self.patches = [
            mock.patch.object(arranque, "DATOS", self.temp),
            mock.patch.object(arranque, "RUTA_NODO", self.temp / "node.json"),
            mock.patch.object(arranque, "DIR_SECRETOS", self.temp / "secrets"),
            mock.patch.object(arranque, "RUTA_SESION", self.temp / "secrets/session-secret"),
            mock.patch.object(arranque, "RUTA_CLUSTER", self.temp / "secrets/cluster-token"),
            mock.patch.object(arranque, "RUTA_KEEPALIVED", self.temp / "secrets/keepalived-api-token"),
            mock.patch.object(arranque, "RUTA_KEEPALIVED_CA", self.temp / "secrets/keepalived-ca.pem"),
            mock.patch.object(arranque, "RUTA_NPM_CA", self.temp / "secrets/npm-ca.pem"),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        shutil.rmtree(self.temp, ignore_errors=True)

    @staticmethod
    def payload(code=""):
        return {
            "node": "node-a", "standalone": False, "enrollment_code": code,
            "members": [
                {"name": "node-a", "address": "npm-a.internal", "guardian_url": ""},
                {"name": "node-b", "address": "npm-b.internal",
                 "guardian_url": "http://guardian-b.internal:6061"},
            ],
            "keepalived": {"url": "http://host.docker.internal:6060",
                            "service": "npm", "token": "keepalived-token",
                            "allow_http": True},
            "portal": {"public_url": "", "trusted_proxies": "", "allow_http": True},
            "npm": {"container": "npm", "scheme": "http", "api_port": 81,
                    "https_port": 443, "allow_http": True},
        }

    def test_first_node_generates_persistent_secrets_and_join_code(self):
        code = arranque.guardar(self.payload())
        self.assertTrue(code)
        self.assertTrue(arranque.RUTA_NODO.is_file())
        self.assertEqual(stat.S_IMODE(arranque.RUTA_SESION.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(arranque.RUTA_CLUSTER.stat().st_mode), 0o600)
        session, cluster = arranque._decodificar_codigo(code)
        self.assertEqual(arranque.RUTA_SESION.read_text().strip(), session)
        self.assertEqual(arranque.RUTA_CLUSTER.read_text().strip(), cluster)
        self.assertNotIn("keepalived-token", arranque.RUTA_NODO.read_text())
        loaded = arranque._leer_configuracion()
        self.assertEqual(loaded["node"], "node-a")
        self.assertEqual(len(loaded["members"]), 2)

    def test_joining_node_uses_the_same_cluster_secrets(self):
        code = arranque.guardar(self.payload())
        first_session = arranque.RUTA_SESION.read_text()
        first_cluster = arranque.RUTA_CLUSTER.read_text()
        shutil.rmtree(self.temp)
        self.temp.mkdir()
        payload = self.payload(code)
        payload["node"] = "node-b"
        payload["members"][0]["guardian_url"] = "http://guardian-a.internal:6061"
        payload["members"][1]["guardian_url"] = ""
        self.assertEqual(arranque.guardar(payload), "")
        self.assertEqual(arranque.RUTA_SESION.read_text(), first_session)
        self.assertEqual(arranque.RUTA_CLUSTER.read_text(), first_cluster)

    def test_local_settings_are_editable_without_exposing_secrets(self):
        arranque.guardar(self.payload())
        entrada = self.payload()
        entrada.pop("enrollment_code")
        entrada["portal"].update({"public_port": 7443, "session_minutes": 30})
        entrada["keepalived"].update({
            "token": "new-keepalived-token", "ca_certificate": "",
            "clear_token": False, "clear_ca_certificate": False,
        })
        entrada["npm"].update({
            "ca_certificate": "", "clear_ca_certificate": False,
        })

        salida = arranque.actualizar(entrada)

        self.assertEqual(salida["portal"]["public_port"], 7443)
        self.assertEqual(salida["portal"]["session_minutes"], 30)
        self.assertTrue(salida["keepalived"]["token_configured"])
        self.assertNotIn("token", salida["keepalived"])
        self.assertEqual(
            arranque.RUTA_KEEPALIVED.read_text(encoding="utf-8").strip(),
            "new-keepalived-token")
        persisted = arranque.RUTA_NODO.read_text(encoding="utf-8")
        self.assertNotIn("new-keepalived-token", persisted)

    def test_local_settings_can_remove_the_keepalived_token(self):
        arranque.guardar(self.payload())
        entrada = self.payload()
        entrada.pop("enrollment_code")
        entrada["keepalived"].update({
            "token": "", "ca_certificate": "", "clear_token": True,
            "clear_ca_certificate": False,
        })
        entrada["npm"].update({
            "ca_certificate": "", "clear_ca_certificate": False,
        })

        salida = arranque.actualizar(entrada)

        self.assertFalse(salida["keepalived"]["token_configured"])
        self.assertFalse(arranque.RUTA_KEEPALIVED.exists())

    def test_portal_contains_all_local_settings_removed_from_unraid(self):
        html = (PANEL / "web" / "index.html").read_text(encoding="utf-8")
        javascript = (PANEL / "web" / "app.js").read_text(encoding="utf-8")
        for identifier in (
                "node-name", "node-address", "node-members", "node-standalone",
                "node-keepalived-url", "node-keepalived-service",
                "node-keepalived-token", "node-keepalived-ca",
                "node-public-url", "node-public-port", "node-session-minutes",
                "node-proxies", "node-npm-container", "node-npm-scheme",
                "node-npm-api-port", "node-npm-https-port", "node-npm-ca"):
            self.assertIn(f'id="{identifier}"', html)
            self.assertIn(f"#{identifier}", javascript)


class TestClusterProtocol(IsolatedData):
    def test_request_signature_binds_method_path_peers_time_and_body(self):
        body = b"encrypted-payload"
        headers = protocolo_cluster.firmar(
            "POST", "/api/internal/config", "node-a", "node-b", body, ahora=10_000)
        identity = protocolo_cluster.verificar(
            "POST", "/api/internal/config", headers, "node-b", body,
            origenes=["node-a"], ahora=10_000)
        self.assertEqual(identity["source"], "node-a")
        self.assertEqual(identity["target"], "node-b")
        self.assertNotIn(os.environ["NPMG_CLUSTER_TOKEN"], json.dumps(headers))

        mutations = (
            ("GET", "/api/internal/config", headers, "node-b", body, ["node-a"], 10_000),
            ("POST", "/api/internal/local", headers, "node-b", body, ["node-a"], 10_000),
            ("POST", "/api/internal/config", headers, "node-c", body, ["node-a"], 10_000),
            ("POST", "/api/internal/config", headers, "node-b", body + b"!", ["node-a"], 10_000),
            ("POST", "/api/internal/config", headers, "node-b", body, ["node-c"], 10_000),
            ("POST", "/api/internal/config", headers, "node-b", body, ["node-a"], 10_400),
        )
        for method, path, signed, target, candidate, sources, now in mutations:
            with self.subTest(method=method, path=path, target=target, now=now), \
                    self.assertRaises(protocolo_cluster.ErrorProtocolo):
                protocolo_cluster.verificar(
                    method, path, signed, target, candidate,
                    origenes=sources, ahora=now)

    def test_envelope_is_confidential_authenticated_and_context_bound(self):
        secret = b"database, private keys and credentials"
        envelope = protocolo_cluster.cifrar(
            secret, "replica", "node-a", "node-b", ahora=20_000,
            contexto="request-nonce")
        self.assertNotIn(secret, envelope)
        self.assertNotIn(os.environ["NPMG_CLUSTER_TOKEN"].encode(), envelope)
        self.assertEqual(protocolo_cluster.descifrar(
            envelope, "replica", "node-a", "node-b", ahora=20_000,
            contexto="request-nonce"), secret)

        for changed in (
                {"tipo": "config"}, {"origen": "node-c"}, {"destino": "node-c"},
                {"contexto": "another-request"}, {"ahora": 20_400}):
            args = {"tipo": "replica", "origen": "node-a", "destino": "node-b",
                    "ahora": 20_000, "contexto": "request-nonce"}
            args.update(changed)
            with self.subTest(changed=changed), \
                    self.assertRaises(protocolo_cluster.ErrorProtocolo):
                protocolo_cluster.descifrar(envelope, **args)

        altered = json.loads(envelope)
        ciphertext = altered["ciphertext"]
        altered["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        with self.assertRaises(protocolo_cluster.ErrorProtocolo):
            protocolo_cluster.descifrar(
                json.dumps(altered).encode(), "replica", "node-a", "node-b",
                ahora=20_000, contexto="request-nonce")

    def test_replay_nonce_is_persisted_and_consumed_once(self):
        nonce = "unique-nonce-for-a-mutating-request"
        self.assertTrue(protocolo_cluster.consumir_nonce(
            nonce, instante=30_000, ahora=30_000))
        self.assertFalse(protocolo_cluster.consumir_nonce(
            nonce, instante=30_000, ahora=30_001))
        replay_file = self.temp / "cluster-replay.json"
        self.assertIn(nonce, json.loads(replay_file.read_text(encoding="utf-8")))
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(replay_file.stat().st_mode), 0o600)

    def test_only_one_concurrent_consumer_can_claim_a_nonce(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                lambda _index: protocolo_cluster.consumir_nonce(
                    "same-concurrent-nonce", instante=40_000, ahora=40_000),
                range(2)))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 1)

    def test_corrupt_replay_store_fails_closed_without_overwriting_evidence(self):
        replay_file = self.temp / "cluster-replay.json"
        corrupt = b"{not-valid-json"
        replay_file.write_bytes(corrupt)
        with self.assertRaises(protocolo_cluster.ErrorProtocolo):
            protocolo_cluster.consumir_nonce(
                "captured-old-request", instante=50_000, ahora=50_000)
        self.assertEqual(replay_file.read_bytes(), corrupt)


class TestInventoryConflict(IsolatedData):
    @staticmethod
    def _element(fingerprint):
        return {
            "tipo": "certificado", "id": 7, "nombre": "tie.example.test",
            "modificado": "2026-08-28 10:00:00", "borrado": False,
            "huella": fingerprint,
        }

    def test_equal_modified_on_with_distinct_fingerprints_is_an_explicit_conflict(self):
        comparison = inventario.comparar({
            "node-a": {"elementos": {
                "certificate:7": self._element("fingerprint-a")}},
            "node-b": {"elementos": {
                "certificate:7": self._element("fingerprint-b")}},
            "node-c": {"elementos": {
                "certificate:7": self._element("fingerprint-c")}},
        })

        self.assertEqual(comparison["conflictos"], ["certificate:7"])
        self.assertIsNone(comparison["un_solo_ganador"])
        self.assertIsNone(comparison["diferencias"][0]["gana"])
        self.assertTrue(comparison["diferencias"][0]["conflicto"])

    def test_automatic_sync_never_publishes_an_ambiguous_tie(self):
        import servidor

        comparison = inventario.comparar({
            "node-a": {"elementos": {
                "certificate:7": self._element("fingerprint-a")}},
            "node-b": {"elementos": {
                "certificate:7": self._element("fingerprint-b")}},
        })
        original_node = servidor.NODO
        servidor.NODO = "node-a"
        try:
            with mock.patch.object(
                    servidor, "quien_manda",
                    return_value={"soy_yo": True, "activo": "node-a"}), \
                    mock.patch.object(servidor, "sincronia",
                                      return_value=comparison), \
                    mock.patch.object(servidor.replica, "empaquetar") as package:
                result = servidor._sincronizar(forzar=False)
        finally:
            servidor.NODO = original_node

        self.assertFalse(result["ok"], result)
        self.assertIn("misma marca temporal", result["motivo"])
        package.assert_not_called()

    def test_sync_heartbeat_hash_depends_only_on_keys_and_content_fingerprints(self):
        import servidor

        first = {"elementos": {
            "certificate:7": {
                **self._element("fingerprint-a"), "modificado": "2026-08-01"},
            "proxy_host:9": {
                "tipo": "dominio", "id": 9, "nombre": "one.example.test",
                "modificado": "2026-08-02", "borrado": False,
                "huella": "fingerprint-b",
            },
        }}
        same_content_other_metadata = {"elementos": {
            "proxy_host:9": {
                "tipo": "dominio", "id": 9, "nombre": "renamed-in-ui",
                "modificado": "2042-02-02", "borrado": True,
                "huella": "fingerprint-b",
            },
            "certificate:7": {
                **self._element("fingerprint-a"), "modificado": "2042-01-01"},
        }}
        changed = copy.deepcopy(same_content_other_metadata)
        changed["elementos"]["proxy_host:9"]["huella"] = "fingerprint-c"

        digest = servidor._huella_sincronia(first)
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest,
                         servidor._huella_sincronia(same_content_other_metadata))
        self.assertNotEqual(digest, servidor._huella_sincronia(changed))

    def test_regenerated_artifacts_do_not_override_the_logical_source(self):
        logical_a = self._element("logical-new")
        logical_a["modificado"] = "2026-09-01 22:25:58"
        logical_old = self._element("logical-old")
        logical_old["modificado"] = "2026-09-01 22:20:38"
        artifact_a = {
            "tipo": "artefactos_npm", "id": "estado", "nombre": "files",
            "modificado": "2026-09-07 05:03:52", "borrado": False,
            "huella": "artifact-from-a",
        }
        artifact_b = {
            **artifact_a, "modificado": "2026-09-09 04:43:29",
            "huella": "regenerated-on-b",
        }

        comparison = inventario.comparar({
            "node-a": {"elementos": {
                "proxy_host:52": logical_a,
                "artefactos:estado": artifact_a,
            }},
            "node-b": {"elementos": {
                "proxy_host:52": logical_old,
                "artefactos:estado": artifact_b,
            }},
        })

        self.assertEqual(comparison["nodos_con_algo_ganador"],
                         ["node-a", "node-b"])
        self.assertEqual(comparison["nodos_con_cambio_logico"], ["node-a"])
        self.assertEqual(comparison["un_solo_ganador_logico"], "node-a")


class TestThreeNodeQuorum(IsolatedData):
    def setUp(self):
        super().setUp()
        import servidor
        self.servidor = servidor
        self.original_peers = servidor.PARES
        self.original_node = servidor.NODO
        servidor.NODO = "node-a"
        servidor.PARES = [
            {"nombre": "node-b", "url": "https://node-b:6061"},
            {"nombre": "node-c", "url": "https://node-c:6061"},
        ]

    def tearDown(self):
        self.servidor.PARES = self.original_peers
        self.servidor.NODO = self.original_node
        super().tearDown()

    def _peer_state(self):
        return {
            "topology_fingerprint": self.servidor._huella_topologia(),
            "security_key_ids": configuracion.identificadores_secretos(),
            "configuration": configuracion.exportar(),
            "renewal_state": vigilante.exportar_estado_cluster(),
        }

    @staticmethod
    def _configuration(document, revision, cron):
        candidate = copy.deepcopy(document)
        candidate["revision"] = revision
        candidate["updated_at"] = f"2030-01-01T00:00:{revision:02d}+00:00"
        candidate["settings"]["sync"]["cron"] = cron
        return candidate

    def _state_with_configuration(self, document):
        state = self._peer_state()
        state["configuration"] = copy.deepcopy(document)
        return state

    def test_security_state_converges_with_one_peer_down_but_not_two(self):
        peer_state = self._peer_state()

        def one_available(peer, *_args):
            if peer["nombre"] == "node-b":
                return copy.deepcopy(peer_state)
            raise OSError("node-c is down")

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "_pedir_interno",
                                  side_effect=one_available), \
                mock.patch.object(
                    self.servidor, "_replicar_configuracion_sin_candado",
                    return_value={"ok": True, "acknowledged": 2,
                                  "quorum": 2}):
            quorum = self.servidor._reconciliar_guardian_desde_pares(
                True)
        self.assertTrue(quorum.get("ok"), quorum)
        self.assertIn("node-c", quorum.get("fallos", {}))

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "_pedir_interno",
                                  side_effect=OSError("both peers are down")):
            no_quorum = self.servidor._reconciliar_guardian_desde_pares(
                True)
        self.assertFalse(no_quorum.get("ok"), no_quorum)

    def test_single_higher_revision_never_wins_without_exact_majority(self):
        initial = configuracion.exportar()
        confirmed = self._configuration(initial, 10, "10 * * * *")
        orphan = self._configuration(initial, 11, "11 * * * *")
        configuracion.guardar(confirmed, incrementar=False)

        def one_orphan(peer, *_args):
            if peer["nombre"] == "node-b":
                return self._state_with_configuration(orphan)
            raise OSError("node-c is down")

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "_pedir_interno",
                                  side_effect=one_orphan), \
                mock.patch.object(self.servidor,
                                  "_replicar_configuracion_sin_candado") as replicate:
            result = self.servidor._reconciliar_guardian_desde_pares(True)

        self.assertFalse(result.get("ok"), result)
        self.assertIn("quórum", result.get("error", ""))
        self.assertEqual(configuracion.exportar(), confirmed)
        replicate.assert_not_called()

    def test_lower_exact_majority_rebases_over_a_local_orphan_and_replicates(self):
        initial = configuracion.exportar()
        confirmed = self._configuration(initial, 10, "10 * * * *")
        orphan = self._configuration(initial, 11, "11 * * * *")
        configuracion.guardar(orphan, incrementar=False)
        peer_state = self._state_with_configuration(confirmed)
        replication = {"ok": True, "acknowledged": 2, "quorum": 2}

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "_pedir_interno",
                                  return_value=peer_state), \
                mock.patch.object(
                    self.servidor, "_replicar_configuracion_sin_candado",
                    return_value=replication) as replicate:
            result = self.servidor._reconciliar_guardian_desde_pares(True)

        current = configuracion.exportar()
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(current["settings"], confirmed["settings"])
        self.assertEqual(current["account"], confirmed["account"])
        self.assertEqual(current["revision"], 12)
        self.assertEqual(result["configuration_majority_revision"], 10)
        self.assertEqual(result["configuration_support"], 2)
        replicate.assert_called_once_with()

    def test_logical_majority_with_distinct_metadata_rebases_deterministically(self):
        initial = configuracion.exportar()
        confirmed_old = self._configuration(initial, 10, "10 * * * *")
        confirmed_new = self._configuration(initial, 12, "10 * * * *")
        orphan = self._configuration(initial, 20, "20 * * * *")
        configuracion.guardar(orphan, incrementar=False)
        peer_states = {
            "node-b": self._state_with_configuration(confirmed_old),
            "node-c": self._state_with_configuration(confirmed_new),
        }

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(
                    self.servidor, "_pedir_interno",
                    side_effect=lambda peer, *_args: peer_states[peer["nombre"]]), \
                mock.patch.object(
                    self.servidor, "_replicar_configuracion_sin_candado",
                    return_value={"ok": True, "acknowledged": 2,
                                  "quorum": 2}) as replicate:
            result = self.servidor._reconciliar_guardian_desde_pares(True)

        current = configuracion.exportar()
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(current["settings"], confirmed_new["settings"])
        self.assertEqual(current["revision"], 21)
        self.assertEqual(result["configuration_majority_revision"], 12)
        replicate.assert_called_once_with()

    def test_legacy_peer_without_topology_fingerprint_is_not_quorum_evidence(self):
        local = self._configuration(configuracion.exportar(), 10, "10 * * * *")
        configuracion.guardar(local, incrementar=False)
        legacy = self._state_with_configuration(local)
        legacy.pop("topology_fingerprint")

        def one_legacy(peer, *_args):
            if peer["nombre"] == "node-b":
                return copy.deepcopy(legacy)
            raise OSError("node-c is down")

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "_pedir_interno",
                                  side_effect=one_legacy):
            result = self.servidor._reconciliar_guardian_desde_pares(True)

        self.assertFalse(result.get("ok"), result)
        self.assertIn("node-b", result.get("fallos", {}))

    def test_higher_exact_majority_is_applied(self):
        initial = configuracion.exportar()
        local = self._configuration(initial, 10, "10 * * * *")
        confirmed = self._configuration(initial, 11, "11 * * * *")
        configuracion.guardar(local, incrementar=False)
        peer_state = self._state_with_configuration(confirmed)

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "_pedir_interno",
                                  return_value=peer_state), \
                mock.patch.object(
                    self.servidor, "_replicar_configuracion_sin_candado",
                    return_value={"ok": True, "acknowledged": 2, "quorum": 2}):
            result = self.servidor._reconciliar_guardian_desde_pares(True)

        self.assertTrue(result.get("ok"), result)
        self.assertEqual(configuracion.exportar(), confirmed)
        self.assertEqual(result["configuration_revision"], 11)

    def test_exact_majority_equal_to_local_is_idempotent(self):
        initial = configuracion.exportar()
        confirmed = self._configuration(initial, 10, "10 * * * *")
        configuracion.guardar(confirmed, incrementar=False)

        def one_confirmed(peer, *_args):
            if peer["nombre"] == "node-b":
                return self._state_with_configuration(confirmed)
            raise OSError("node-c is down")

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "_pedir_interno",
                                  side_effect=one_confirmed), \
                mock.patch.object(self.servidor,
                                  "_replicar_configuracion_sin_candado") as replicate:
            result = self.servidor._reconciliar_guardian_desde_pares(True)

        self.assertTrue(result.get("ok"), result)
        self.assertEqual(configuracion.exportar(), confirmed)
        replicate.assert_not_called()

    def test_security_replication_acknowledges_a_majority_not_every_peer(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            @staticmethod
            def read():
                return b"encrypted-response"

        request = mock.Mock()
        request.full_url = "http://node-b:6061/api/internal/config"
        verified_response = json.dumps({
            "ok": True,
            "topology_verified": True,
            "topology_fingerprint": self.servidor._huella_topologia(),
        }).encode()
        common = (
            mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}),
            mock.patch.object(self.servidor.protocolo_cluster, "disponible",
                              return_value=True),
            mock.patch.object(self.servidor.protocolo_cluster, "cifrar",
                              return_value=b"encrypted-request"),
            mock.patch.object(self.servidor, "_peticion_interna",
                              return_value=(request, "request-nonce")),
            mock.patch.object(self.servidor.protocolo_cluster, "descifrar",
                              return_value=verified_response),
        )
        with common[0], common[1], common[2], common[3], common[4], \
                mock.patch.object(
                    self.servidor.urllib.request, "urlopen",
                    side_effect=[Response(), OSError("node-c is down")]):
            quorum = self.servidor._replicar_configuracion_sin_candado()
        self.assertTrue(quorum.get("ok"), quorum)
        self.assertTrue(quorum["resultados"]["node-b"]["ok"])
        self.assertFalse(quorum["resultados"]["node-c"]["ok"])

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor.protocolo_cluster, "disponible",
                                  return_value=True), \
                mock.patch.object(self.servidor.protocolo_cluster, "cifrar",
                                  return_value=b"encrypted-request"), \
                mock.patch.object(self.servidor, "_peticion_interna",
                                  return_value=(request, "request-nonce")), \
                mock.patch.object(
                    self.servidor.urllib.request, "urlopen",
                    side_effect=OSError("both peers are down")):
            no_quorum = self.servidor._replicar_configuracion_sin_candado()
        self.assertFalse(no_quorum.get("ok"), no_quorum)

    def test_npm_data_replication_uses_the_same_three_node_quorum(self):
        synchronization = {
            "en_sincronia": False,
            "comparacion_completa": True,
            "nodos_incompatibles": {},
            "conflictos": [],
            "nodos_con_algo_ganador": ["node-a"],
        }

        def one_available(peer, _package):
            if peer["nombre"] == "node-b":
                return {"ok": True}
            raise OSError("node-c is down")

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "sincronia",
                                  return_value=synchronization), \
                mock.patch.object(self.servidor.replica, "empaquetar",
                                  return_value=b"validated-package"), \
                mock.patch.object(self.servidor.protocolo_cluster, "disponible",
                                  return_value=True), \
                mock.patch.object(self.servidor, "_empujar_a",
                                  side_effect=one_available), \
                mock.patch.object(self.servidor.avisos, "avisar"):
            quorum = self.servidor._sincronizar()
        self.assertTrue(quorum["ok"], quorum)
        self.assertFalse(quorum["complete"])
        self.assertEqual(quorum["acknowledged"], 2)

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "sincronia",
                                  return_value=synchronization), \
                mock.patch.object(self.servidor.replica, "empaquetar",
                                  return_value=b"validated-package"), \
                mock.patch.object(self.servidor.protocolo_cluster, "disponible",
                                  return_value=True), \
                mock.patch.object(self.servidor, "_empujar_a",
                                  side_effect=OSError("both peers are down")), \
                mock.patch.object(self.servidor.avisos, "avisar"):
            no_quorum = self.servidor._sincronizar()
        self.assertFalse(no_quorum["ok"], no_quorum)
        self.assertEqual(no_quorum["acknowledged"], 1)

    def test_active_recovers_unique_logical_source_and_then_replicates_it(self):
        synchronization = {
            "en_sincronia": False,
            "comparacion_completa": True,
            "nodos_incompatibles": {},
            "conflictos": [],
            "nodos_con_algo_ganador": ["node-b", "node-c"],
            "nodos_con_cambio_logico": ["node-b"],
        }

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "sincronia",
                                  return_value=synchronization), \
                mock.patch.object(self.servidor, "_recuperar_activo_desde",
                                  return_value={"ok": True}) as recover, \
                mock.patch.object(self.servidor.replica, "empaquetar",
                                  return_value=b"recovered-package"), \
                mock.patch.object(self.servidor.protocolo_cluster, "disponible",
                                  return_value=True), \
                mock.patch.object(self.servidor, "_empujar_a",
                                  return_value={"ok": True}) as push:
            result = self.servidor._sincronizar()

        recover.assert_called_once_with(self.servidor.PARES[0])
        push.assert_called_once_with(self.servidor.PARES[1], b"recovered-package")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["recuperado_de"], "node-b")
        self.assertTrue(result["resultados"]["node-b"]["source_preserved"])

    def test_active_logical_change_is_not_blocked_by_regenerated_peer_files(self):
        synchronization = {
            "en_sincronia": False,
            "comparacion_completa": True,
            "nodos_incompatibles": {},
            "conflictos": [],
            "nodos_con_algo_ganador": ["node-a", "node-c"],
            "nodos_con_cambio_logico": ["node-a"],
        }

        with mock.patch.object(
                self.servidor, "quien_manda",
                return_value={"soy_yo": True, "activo": "node-a"}), \
                mock.patch.object(self.servidor, "sincronia",
                                  return_value=synchronization), \
                mock.patch.object(self.servidor, "_recuperar_activo_desde") as recover, \
                mock.patch.object(self.servidor.replica, "empaquetar",
                                  return_value=b"active-package"), \
                mock.patch.object(self.servidor.protocolo_cluster, "disponible",
                                  return_value=True), \
                mock.patch.object(self.servidor, "_empujar_a",
                                  return_value={"ok": True}) as push:
            result = self.servidor._sincronizar()

        recover.assert_not_called()
        self.assertEqual(push.call_count, 2)
        self.assertTrue(result["ok"], result)


class TestTopologyFence(IsolatedData):
    def setUp(self):
        super().setUp()
        import servidor
        self.servidor = servidor
        self.original_node = servidor.NODO
        self.original_peers = servidor.PARES
        servidor.NODO = "node-a"
        servidor.PARES = [
            {"nombre": "node-b", "url": "http://192.0.2.2:6061"},
            {"nombre": "node-c", "url": "http://192.0.2.3:6061"},
        ]

    def tearDown(self):
        self.servidor.NODO = self.original_node
        self.servidor.PARES = self.original_peers
        super().tearDown()

    def test_membership_fingerprint_is_stable_and_startup_requires_exact_set(self):
        with mock.patch.dict(os.environ, {
                "NPMG_NODES": "node-c:192.0.2.3,node-a:192.0.2.1,node-b:192.0.2.2",
        }):
            first = self.servidor._validar_topologia()
        with mock.patch.dict(os.environ, {
                "NPMG_NODES": "node-b:b.internal,node-c:c.internal,node-a:a.internal",
        }):
            second = self.servidor._validar_topologia()

        self.assertEqual(first["members"], ["node-a", "node-b", "node-c"])
        self.assertEqual(first["fingerprint"], second["fingerprint"])

    def test_missing_peer_and_self_peer_fail_closed(self):
        with mock.patch.dict(os.environ, {
                "NPMG_NODES": "node-a:192.0.2.1,node-b:192.0.2.2,node-c:192.0.2.3",
        }):
            self.servidor.PARES = [
                {"nombre": "node-b", "url": "http://192.0.2.2:6061"},
            ]
            with self.assertRaises(configuracion.ErrorConfiguracion):
                self.servidor._validar_topologia()

    def test_self_peer_fails_closed(self):
        with mock.patch.dict(os.environ, {
                "NPMG_NODES": "node-a:192.0.2.1,node-b:192.0.2.2,node-c:192.0.2.3",
        }):
            self.servidor.PARES = [
                {"nombre": "node-a", "url": "http://192.0.2.1:6061"},
                {"nombre": "node-c", "url": "http://192.0.2.3:6061"},
            ]
            with self.assertRaises(configuracion.ErrorConfiguracion):
                self.servidor._validar_topologia()

    def test_internal_write_context_fences_mismatched_topology_but_accepts_legacy(self):
        identity = {"source": "node-b"}
        fingerprint = self.servidor._huella_topologia()
        fenced = protocolo_cluster.cifrar(
            b"payload", "config", "node-b", "node-a",
            contexto=fingerprint)
        clear, verified = self.servidor._descifrar_escritura_interna(
            fenced, "config", identity)
        self.assertEqual(clear, b"payload")
        self.assertTrue(verified)

        legacy = protocolo_cluster.cifrar(
            b"legacy", "config", "node-b", "node-a")
        clear, verified = self.servidor._descifrar_escritura_interna(
            legacy, "config", identity)
        self.assertEqual(clear, b"legacy")
        self.assertFalse(verified)

        mismatched = protocolo_cluster.cifrar(
            b"payload", "config", "node-b", "node-a",
            contexto="f" * 64)
        with self.assertRaises(protocolo_cluster.ErrorProtocolo):
            self.servidor._descifrar_escritura_interna(
                mismatched, "config", identity)



class TestOperationalReadiness(IsolatedData):
    def setUp(self):
        super().setUp()
        import servidor
        self.servidor = servidor

    def _public_state(self, api_responds=True, now=1_000_001.0):
        with mock.patch.dict(os.environ, {"NPMG_SYNC_STALE_SECONDS": "900"}), \
                mock.patch.object(self.servidor.time, "time", return_value=now), \
                mock.patch.object(self.servidor.npm, "salud_base",
                                  return_value={"ok": True}), \
                mock.patch.object(self.servidor.dockerd, "estado",
                                  return_value={"existe": True, "corriendo": True}), \
                mock.patch.object(self.servidor.dockerd, "disponible",
                                  return_value=True), \
                mock.patch.object(self.servidor.npm_api, "api_responde",
                                  return_value=api_responds), \
                mock.patch.object(self.servidor, "quien_manda",
                                  return_value={"soy_yo": False, "activo": "node-a"}):
            return self.servidor.estado_publico()

    def test_recent_verified_sync_heartbeat_can_make_a_passive_ready(self):
        heartbeat = 1_000_000.0
        configuracion.guardar_estado_operativo({
            "last_verified_sync": heartbeat,
            "last_verified_sync_result": {
                "ok": True, "inventory_hash": "a" * 64,
                "topology_verified": True,
                "topology_fingerprint": self.servidor._huella_topologia(),
            },
        })

        public = self._public_state(api_responds=True)
        self.assertTrue(public["health"]["ready"], public["health"])
        self.assertTrue(public["health"]["npm_api"])
        self.assertEqual(public["last_sync"], heartbeat)

        unavailable = self._public_state(api_responds=False)
        self.assertFalse(unavailable["health"]["ready"])
        self.assertFalse(unavailable["health"]["npm_api"])

    def test_stale_sync_heartbeat_never_makes_a_passive_ready(self):
        configuracion.guardar_estado_operativo({
            "last_verified_sync": 1_000.0,
            "last_verified_sync_result": {
                "ok": True, "inventory_hash": "a" * 64,
                "topology_verified": True,
                "topology_fingerprint": self.servidor._huella_topologia(),
            },
        })
        public = self._public_state(api_responds=True, now=2_000.0)
        self.assertFalse(public["health"]["ready"], public["health"])

    def test_operational_updates_are_atomic_serialized_and_preserve_all_fields(self):
        real_write = configuracion._guardar_bytes_seguro
        activity_lock = threading.Lock()
        activity = {"current": 0, "maximum": 0}

        def observed_write(path, content):
            with activity_lock:
                activity["current"] += 1
                activity["maximum"] = max(activity["maximum"], activity["current"])
            try:
                time.sleep(0.01)
                return real_write(path, content)
            finally:
                with activity_lock:
                    activity["current"] -= 1

        with mock.patch.object(configuracion, "_guardar_bytes_seguro",
                               side_effect=observed_write) as safe_write, \
                ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(
                lambda index: configuracion.guardar_estado_operativo(
                    {f"field_{index}": index}),
                range(16)))

        stored = configuracion.estado_operativo()
        self.assertEqual(activity["maximum"], 1)
        self.assertEqual(safe_write.call_count, 16)
        for index in range(16):
            self.assertEqual(stored[f"field_{index}"], index)


class TestConfigMutationQuorum(IsolatedData):
    def setUp(self):
        super().setUp()
        import servidor
        self.servidor = servidor

    @staticmethod
    def _mutate_cron(value):
        def change(document):
            document["settings"]["sync"]["cron"] = value
        return configuracion.actualizar(change)

    def test_confirmed_mutation_is_kept_without_rollback(self):
        before = configuracion.exportar()
        self._mutate_cron("11 * * * *")
        confirmed = {"ok": True, "acknowledged": 2, "quorum": 2}
        with mock.patch.object(self.servidor, "_replicar_configuracion_sin_candado",
                               return_value=confirmed), \
                mock.patch.object(configuracion, "revertir_no_confirmada",
                                  wraps=configuracion.revertir_no_confirmada) as rollback:
            result = self.servidor._confirmar_mutacion_config(before)

        self.assertEqual(result, confirmed)
        rollback.assert_not_called()
        self.assertEqual(configuracion.leer()["settings"]["sync"]["cron"],
                         "11 * * * *")

    def test_unconfirmed_mutation_is_reverted_with_a_higher_revision(self):
        before = configuracion.exportar()
        changed = self._mutate_cron("12 * * * *")
        first = {"ok": False, "acknowledged": 1, "quorum": 2}
        rollback_replication = {"ok": True, "acknowledged": 2, "quorum": 2}
        replication = mock.Mock(side_effect=[first, rollback_replication])
        with mock.patch.object(self.servidor, "_replicar_configuracion_sin_candado", replication):
            result = self.servidor._confirmar_mutacion_config(before)

        after = configuracion.exportar()
        self.assertFalse(result["ok"])
        self.assertTrue(result["rollback"]["ok"])
        self.assertEqual(result["rollback"]["replication"], rollback_replication)
        self.assertEqual(result["rollback"]["revision"], after["revision"])
        self.assertEqual(after["settings"], before["settings"])
        self.assertEqual(after["account"], before["account"])
        self.assertGreater(after["revision"], changed["revision"])
        self.assertEqual(replication.call_count, 2)

    def test_local_rollback_survives_failure_to_replicate_the_rollback(self):
        before = configuracion.exportar()
        self._mutate_cron("13 * * * *")
        replication = mock.Mock(side_effect=[
            {"ok": False, "acknowledged": 1, "quorum": 2},
            {"ok": False, "acknowledged": 1, "quorum": 2},
        ])
        with mock.patch.object(self.servidor, "_replicar_configuracion_sin_candado", replication):
            result = self.servidor._confirmar_mutacion_config(before)

        after = configuracion.exportar()
        self.assertFalse(result["ok"])
        self.assertTrue(result["rollback"]["ok"])
        self.assertFalse(result["rollback"]["replication"]["ok"])
        self.assertEqual(after["settings"], before["settings"])
        self.assertGreater(after["revision"], before["revision"])


class TestStrictConfiguration(IsolatedData):
    @staticmethod
    def valid_payload():
        return {
            "sync": {"enabled": True, "cron": "*/15 * * * *"},
            "namecheap": {
                "enabled": False, "api_user": "", "api_key": None,
            },
            "renewal": {
                "days_before_expiry": 35, "warning_days": 15,
                "max_automatic_attempts": 4,
            },
            "npm_api": {
                "user": "", "password": None, "port": 81,
                "https_port": 443, "timeout_seconds": 720,
            },
        }

    def assert_rejected_without_write(self, payload):
        before = Path(configuracion.RUTA).read_bytes()
        revision = configuracion.leer()["revision"]
        with self.assertRaises(configuracion.ErrorConfiguracion):
            configuracion.guardar_ajustes(payload)
        configuracion._cache = None
        self.assertEqual(Path(configuracion.RUTA).read_bytes(), before)
        self.assertEqual(configuracion.leer()["revision"], revision)

    def test_enabled_fields_require_json_booleans(self):
        configuracion.guardar_ajustes(self.valid_payload())
        for section, value in (("sync", "false"), ("namecheap", "true"),
                               ("sync", 1), ("namecheap", 0)):
            payload = copy.deepcopy(self.valid_payload())
            payload[section]["enabled"] = value
            with self.subTest(section=section, value=value):
                self.assert_rejected_without_write(payload)

    def test_missing_or_unknown_sections_are_rejected_transactionally(self):
        configuracion.guardar_ajustes(self.valid_payload())
        cases = []
        missing_section = copy.deepcopy(self.valid_payload())
        missing_section.pop("renewal")
        cases.append(missing_section)
        missing_field = copy.deepcopy(self.valid_payload())
        missing_field["sync"].pop("cron")
        cases.append(missing_field)
        unknown_section = copy.deepcopy(self.valid_payload())
        unknown_section["private_installation"] = {"enabled": True}
        cases.append(unknown_section)
        unknown_field = copy.deepcopy(self.valid_payload())
        unknown_field["renewal"]["unsafe_unlimited_attempts"] = True
        cases.append(unknown_field)
        for payload in cases:
            with self.subTest(payload=payload):
                self.assert_rejected_without_write(payload)

    def test_incomplete_replicated_document_is_not_merged_with_defaults(self):
        valid = configuracion.leer()
        configuracion.guardar(valid)
        before = Path(configuracion.RUTA).read_bytes()
        incoming = copy.deepcopy(configuracion.exportar())
        incoming["settings"]["npm_api"].pop("timeout_seconds")
        with self.assertRaises(configuracion.ErrorConfiguracion):
            configuracion.aplicar_replica(incoming)
        self.assertEqual(Path(configuracion.RUTA).read_bytes(), before)

    def test_replica_revision_is_monotonic_idempotent_and_split_brain_safe(self):
        configuracion.guardar_ajustes(self.valid_payload())
        current = configuracion.exportar()
        same = configuracion.aplicar_replica(copy.deepcopy(current))
        self.assertTrue(same["idempotent"])

        before = Path(configuracion.RUTA).read_bytes()
        stale = copy.deepcopy(current)
        stale["revision"] -= 1
        with self.assertRaisesRegex(configuracion.ErrorConfiguracion, "obsoleta"):
            configuracion.aplicar_replica(stale)
        self.assertEqual(Path(configuracion.RUTA).read_bytes(), before)

        divergent = copy.deepcopy(current)
        divergent["settings"]["sync"]["cron"] = "7 * * * *"
        with self.assertRaisesRegex(configuracion.ErrorConfiguracion, "misma revisi"):
            configuracion.aplicar_replica(divergent)
        self.assertEqual(Path(configuracion.RUTA).read_bytes(), before)

        newer = copy.deepcopy(current)
        newer["revision"] += 1
        newer["updated_at"] = "2026-08-27T12:00:00+00:00"
        newer["settings"]["sync"]["cron"] = "7 * * * *"
        applied = configuracion.aplicar_replica(newer)
        self.assertFalse(applied["idempotent"])
        self.assertEqual(configuracion.leer()["settings"]["sync"]["cron"], "7 * * * *")

    def test_first_boot_is_persisted_and_a_pristine_peer_can_bootstrap_and_converge(self):
        """Dos nodos nuevos no pueden quedar en conflicto por su reloj local."""
        node_a = self.temp / "node-a"
        node_b = self.temp / "node-b"

        def select_node(directory):
            directory.mkdir(parents=True, exist_ok=True)
            configuracion.DATOS = str(directory)
            configuracion.RUTA = str(directory / "guardian.json")
            configuracion.RUTA_BACKUP = configuracion.RUTA + ".bak"
            configuracion._cache = None

        select_node(node_a)
        with mock.patch.object(configuracion, "_ahora",
                               return_value="2026-08-28T08:00:00+00:00"):
            first_a = configuracion.leer()
            promoted = configuracion.promover_bootstrap_activo()
        self.assertTrue(Path(configuracion.RUTA).is_file())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(Path(configuracion.RUTA).stat().st_mode), 0o600)
        self.assertEqual(first_a["updated_at"], configuracion.MARCA_CONFIG_INICIAL)
        self.assertTrue(promoted["changed"])
        self.assertGreater(promoted["revision"], first_a["revision"])
        exported_a = configuracion.exportar()
        self.assertFalse(configuracion.promover_bootstrap_activo()["changed"])

        select_node(node_b)
        with mock.patch.dict(os.environ, {"NPMG_SYNC_CRON": "7 * * * *"}), \
                mock.patch.object(configuracion, "_ahora",
                                  return_value="2031-01-01T00:00:00+00:00"):
            first_b = configuracion.leer()
        self.assertTrue(Path(configuracion.RUTA).is_file())
        self.assertEqual(first_b["updated_at"], configuracion.MARCA_CONFIG_INICIAL)
        self.assertNotEqual(first_b["settings"]["sync"],
                            exported_a["settings"]["sync"])

        # Sea idempotente por semilla determinista o una adopción bootstrap,
        # una réplica válida del primer nodo debe ganar en el segundo.
        result = configuracion.aplicar_replica(copy.deepcopy(exported_a))
        self.assertTrue(result["ok"])
        self.assertEqual(configuracion.exportar(), exported_a)

        # Un reinicio no reconstruye otra identidad inicial ni depende del reloj.
        configuracion._cache = None
        with mock.patch.object(configuracion, "_ahora",
                               return_value="2042-02-02T02:02:02+00:00"):
            self.assertEqual(configuracion.leer(), exported_a)
        self.assertEqual(first_a["schema"], first_b["schema"])

    def test_two_isolated_bootstrap_promotions_produce_identical_documents(self):
        promoted_documents = []
        promoted_bytes = []
        for name, clock in (("node-a", "2026-08-28T08:00:00+00:00"),
                            ("node-b", "2042-02-02T02:02:02+00:00")):
            directory = self.temp / name
            directory.mkdir()
            configuracion.DATOS = str(directory)
            configuracion.RUTA = str(directory / "guardian.json")
            configuracion.RUTA_BACKUP = configuracion.RUTA + ".bak"
            configuracion._cache = None
            with mock.patch.object(configuracion, "_ahora", return_value=clock):
                initial = configuracion.leer()
                promotion = configuracion.promover_bootstrap_activo()
            self.assertEqual(initial["updated_at"], configuracion.MARCA_CONFIG_INICIAL)
            self.assertTrue(promotion["changed"])
            promoted_documents.append(configuracion.exportar())
            promoted_bytes.append(Path(configuracion.RUTA).read_bytes())

        self.assertEqual(promoted_documents[0], promoted_documents[1])
        self.assertEqual(promoted_bytes[0], promoted_bytes[1])
        self.assertEqual(promoted_documents[0]["revision"], 2)
        self.assertEqual(promoted_documents[0]["updated_at"],
                         configuracion.MARCA_CONFIG_BOOTSTRAP)


class TestDurableStateFiles(IsolatedData):
    def _assert_parent_directory_fsync_after_replace(self, module, writer, target):
        events = []
        parent_descriptors = set()
        parent = os.path.abspath(os.path.dirname(target))
        real_open = os.open
        real_fsync = os.fsync
        real_replace = os.replace

        def tracked_open(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            if (os.path.abspath(os.fspath(path)) == parent and
                    not flags & (os.O_WRONLY | os.O_RDWR)):
                parent_descriptors.add(descriptor)
                events.append(("open-parent", descriptor))
            return descriptor

        def tracked_fsync(descriptor):
            if descriptor in parent_descriptors:
                events.append(("fsync-parent", descriptor))
            return real_fsync(descriptor)

        def tracked_replace(source, destination):
            result = real_replace(source, destination)
            if os.path.abspath(os.fspath(destination)) == os.path.abspath(target):
                events.append(("replace", destination))
            return result

        with mock.patch.object(module.os, "open", side_effect=tracked_open), \
                mock.patch.object(module.os, "fsync", side_effect=tracked_fsync), \
                mock.patch.object(module.os, "replace", side_effect=tracked_replace):
            writer()

        replace_index = next(
            index for index, event in enumerate(events) if event[0] == "replace")
        open_index = next(
            index for index, event in enumerate(events) if event[0] == "open-parent")
        fsync_index = next(
            index for index, event in enumerate(events) if event[0] == "fsync-parent")
        self.assertLess(replace_index, open_index)
        self.assertLess(open_index, fsync_index)

    def test_configuration_replace_is_followed_by_parent_directory_fsync(self):
        target = str(self.temp / "durable-guardian.json")
        payload = b'{"kind":"configuration"}\n'
        self._assert_parent_directory_fsync_after_replace(
            configuracion,
            lambda: configuracion._guardar_bytes_seguro(target, payload),
            target)
        self.assertEqual(Path(target).read_bytes(), payload)

    def test_ledger_replace_is_followed_by_parent_directory_fsync(self):
        target = str(self.temp / "durable-ledger.json")
        payload = b'{"kind":"ledger"}\n'
        self._assert_parent_directory_fsync_after_replace(
            vigilante,
            lambda: vigilante._escribir_bytes(target, payload),
            target)
        self.assertEqual(Path(target).read_bytes(), payload)


class TestSafeReplica(IsolatedData):
    def setUp(self):
        super().setUp()
        self.original_replica_paths = (
            replica.RUTA_DATOS, replica.RUTA_LE, replica.RUTA_RESPALDOS,
            replica.RUTA_JOURNAL)
        self.source_data = self.temp / "source-data"
        self.source_le = self.temp / "source-letsencrypt"
        self.backups = self.temp / "backups"
        self._create_npm_state(self.source_data, self.source_le, "source")
        replica.RUTA_DATOS = str(self.source_data)
        replica.RUTA_LE = str(self.source_le)
        replica.RUTA_RESPALDOS = str(self.backups)
        replica.RUTA_JOURNAL = str(self.backups / "replica-transaction.json")

    def tearDown(self):
        (replica.RUTA_DATOS, replica.RUTA_LE, replica.RUTA_RESPALDOS,
         replica.RUTA_JOURNAL) = \
            self.original_replica_paths
        super().tearDown()

    @staticmethod
    def _create_npm_state(data, le, marker):
        data.mkdir(parents=True, exist_ok=True)
        le.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(data / "database.sqlite")
        connection.execute("create table sample (value text not null)")
        connection.execute("insert into sample values (?)", (marker,))
        connection.commit()
        connection.close()
        (data / "nginx").mkdir()
        (data / "nginx" / "proxy.conf").write_text(marker, encoding="utf-8")
        (data / "access").mkdir()
        (data / "access" / "access.log").write_text(marker, encoding="utf-8")
        (le / "renewal-hooks" / "deploy").mkdir(parents=True)
        (le / "renewal-hooks" / "deploy" / "reload.sh").write_text(
            marker, encoding="utf-8")

    @staticmethod
    def _database_marker(data):
        connection = sqlite3.connect(data / "database.sqlite")
        try:
            return connection.execute("select value from sample").fetchone()[0]
        finally:
            connection.close()

    @contextmanager
    def _stateful_docker(self, running=True, on_stop=None, on_start=None,
                         stop_lost_after_effect=False,
                         start_lost_after_effect=False,
                         stop_fails_without_effect=False,
                         start_fails_without_effect=False):
        state = {"running": bool(running)}

        def status(_container):
            return {"existe": True, "corriendo": state["running"]}

        def stop(container):
            if stop_fails_without_effect:
                raise replica.dockerd.ErrorDocker("el stop no se aplico")
            state["running"] = False
            if on_stop:
                on_stop(container)
            if stop_lost_after_effect:
                raise replica.dockerd.ErrorDocker(
                    "la respuesta al stop se perdio despues de aplicarlo")

        def start(container):
            if start_fails_without_effect:
                raise replica.dockerd.ErrorDocker("el start no se aplico")
            state["running"] = True
            if on_start:
                on_start(container)
            if start_lost_after_effect:
                raise replica.dockerd.ErrorDocker(
                    "la respuesta al start se perdio despues de aplicarlo")

        with mock.patch.object(replica.dockerd, "estado", side_effect=status) as get, \
                mock.patch.object(replica.dockerd, "parar", side_effect=stop) as stop_mock, \
                mock.patch.object(replica.dockerd, "arrancar", side_effect=start) as start_mock:
            yield state, get, stop_mock, start_mock

    @staticmethod
    def _repack(directory):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.add(directory / "manifest.json", arcname="manifest.json")
            archive.add(directory / "data", arcname="data")
            archive.add(directory / "letsencrypt", arcname="letsencrypt")
        return buffer.getvalue()

    def test_package_contains_valid_sqlite_snapshot_and_manifest(self):
        package = replica.empaquetar()
        with tarfile.open(fileobj=io.BytesIO(package), mode="r:gz") as archive:
            names = set(archive.getnames())
        self.assertIn("manifest.json", names)
        self.assertIn("data/database.sqlite", names)
        self.assertIn("data/access/access.log", names)
        self.assertIn("letsencrypt/renewal-hooks/deploy/reload.sh", names)

        extracted = Path(replica._extraer_validado(package))
        try:
            self.assertEqual(self._database_marker(extracted / "data"), "source")
        finally:
            shutil.rmtree(extracted, ignore_errors=True)

    def test_tampered_content_does_not_match_manifest(self):
        package = replica.empaquetar()
        extracted = self.temp / "tamper"
        extracted.mkdir()
        with tarfile.open(fileobj=io.BytesIO(package), mode="r:gz") as archive:
            archive.extractall(extracted, filter="data")
        (extracted / "data" / "nginx" / "proxy.conf").write_text(
            "altered after manifest", encoding="utf-8")
        with self.assertRaisesRegex(replica.ErrorReplica, "huella"):
            replica._extraer_validado(self._repack(extracted))

    def test_traversal_absolute_links_and_unbounded_expansion_are_rejected(self):
        def validate_members(members):
            fake = mock.Mock()
            fake.getmembers.return_value = members
            replica._validar_paquete(fake)

        traversal = tarfile.TarInfo("data/../../outside")
        traversal.size = 1
        with self.assertRaisesRegex(replica.ErrorReplica, "se sale"):
            validate_members([traversal])

        absolute_link = tarfile.TarInfo("letsencrypt/live/npm-1/cert.pem")
        absolute_link.type = tarfile.SYMTYPE
        absolute_link.linkname = "/etc/shadow"
        with self.assertRaisesRegex(replica.ErrorReplica, "fuera"):
            validate_members([absolute_link])

        huge = tarfile.TarInfo("data/huge")
        huge.size = replica.MAX_DESEMPAQUETADO + 1
        with self.assertRaisesRegex(replica.ErrorReplica, "expandido"):
            validate_members([huge])

    def test_apply_replaces_all_parts_only_after_validation_and_keeps_backup(self):
        package = replica.empaquetar()
        target_data = self.temp / "target-data"
        target_le = self.temp / "target-letsencrypt"
        self._create_npm_state(target_data, target_le, "target")
        (target_data / "keys.json").write_text("stale", encoding="utf-8")
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        passive = mock.Mock()
        with self._stateful_docker() as (_state, _get, stop, start), \
                mock.patch.object(replica, "_esperar_salud", return_value=True):
            result = replica.aplicar(
                package, soy_el_activo=False, comprobar_pasivo=passive)
        self.assertTrue(result["ok"])
        self.assertEqual(self._database_marker(target_data), "source")
        self.assertEqual((target_data / "access" / "access.log").read_text(), "source")
        self.assertEqual((target_le / "renewal-hooks" / "deploy" / "reload.sh").read_text(),
                         "source")
        self.assertFalse((target_data / "keys.json").exists())
        self.assertGreaterEqual(passive.call_count, 3)
        stop.assert_called_once_with(replica.CONTENEDOR)
        start.assert_called_once_with(replica.CONTENEDOR)
        backup = self.backups / result["backup"]
        self.assertTrue(backup.is_file())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_lost_stop_response_after_effect_is_resolved_by_rechecking_docker(self):
        with self._stateful_docker(
                stop_lost_after_effect=True) as (state, get, stop, _start):
            result = replica._asegurar_contenedor(False)
        self.assertFalse(result["corriendo"])
        self.assertFalse(state["running"])
        stop.assert_called_once_with(replica.CONTENEDOR)
        self.assertGreaterEqual(get.call_count, 2)

    def test_lost_start_response_after_effect_is_resolved_by_rechecking_docker(self):
        with self._stateful_docker(
                running=False, start_lost_after_effect=True) as (
                state, get, _stop, start):
            result = replica._asegurar_contenedor(True)
        self.assertTrue(result["corriendo"])
        self.assertTrue(state["running"])
        start.assert_called_once_with(replica.CONTENEDOR)
        self.assertGreaterEqual(get.call_count, 2)

    def test_apply_never_rolls_back_while_npm_runs_and_keeps_journal_until_old_health(self):
        package = replica.empaquetar()
        target_data = self.temp / "ambiguous-runtime-data"
        target_le = self.temp / "ambiguous-runtime-letsencrypt"
        self._create_npm_state(target_data, target_le, "before")
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        events = []
        real_restore = replica._restaurar
        real_delete_journal = replica._borrar_journal
        state_ref = {}
        health_checks = iter((False, True))

        def restore(changes):
            events.append(("restore", state_ref["state"]["running"]))
            self.assertFalse(state_ref["state"]["running"])
            self.assertTrue(Path(replica.RUTA_JOURNAL).is_file())
            return real_restore(changes)

        def health():
            result = next(health_checks)
            events.append(("health", result))
            self.assertTrue(state_ref["state"]["running"])
            self.assertTrue(Path(replica.RUTA_JOURNAL).is_file())
            return result

        def delete_journal():
            events.append(("delete-journal", True))
            return real_delete_journal()

        with self._stateful_docker(
                stop_lost_after_effect=True,
                start_lost_after_effect=True) as (state, _get, stop, start), \
                mock.patch.object(replica, "_esperar_salud", side_effect=health), \
                mock.patch.object(replica, "_restaurar", side_effect=restore), \
                mock.patch.object(replica, "_borrar_journal",
                                  side_effect=delete_journal), \
                self.assertRaisesRegex(replica.ErrorReplica, "no recuper"):
            state_ref["state"] = state
            replica.aplicar(package, soy_el_activo=False)

        self.assertEqual(events[0], ("health", False))
        self.assertIn(("restore", False), events)
        self.assertLess(events.index(("health", True)),
                        events.index(("delete-journal", True)))
        self.assertEqual(self._database_marker(target_data), "before")
        self.assertFalse(Path(replica.RUTA_JOURNAL).exists())
        self.assertGreaterEqual(stop.call_count, 2)
        self.assertGreaterEqual(start.call_count, 2)

    def test_prepared_recovery_keeps_journal_when_start_cannot_be_confirmed(self):
        replica._escribir_journal(
            "prepared", [], was_running=True, keep_new_on_recovery=False)
        with self._stateful_docker(
                running=False, start_fails_without_effect=True) as (
                state, _get, _stop, start), \
                self.assertRaisesRegex(replica.ErrorReplica, "conserva el journal"):
            replica.recuperar_transaccion()
        self.assertFalse(state["running"])
        start.assert_called_once_with(replica.CONTENEDOR)
        self.assertTrue(Path(replica.RUTA_JOURNAL).is_file())

    def test_prepared_recovery_keeps_journal_when_npm_does_not_recover_health(self):
        replica._escribir_journal(
            "prepared", [], was_running=True, keep_new_on_recovery=False)
        with self._stateful_docker(running=False) as (state, _get, _stop, start), \
                mock.patch.object(replica, "_esperar_salud", return_value=False), \
                self.assertRaisesRegex(replica.ErrorReplica, "salud"):
            replica.recuperar_transaccion()
        self.assertTrue(state["running"])
        start.assert_called_once_with(replica.CONTENEDOR)
        self.assertTrue(Path(replica.RUTA_JOURNAL).is_file())

    def test_promoted_swap_recovery_keeps_the_new_state_when_it_is_healthy(self):
        target_data = self.temp / "forward-recovery-data"
        target_le = self.temp / "forward-recovery-letsencrypt"
        target_data.mkdir()
        target_le.mkdir()
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        destination = target_data / "keys.json"
        old = target_data / ".npmg-old-forward-keys.json"
        new = target_data / ".npmg-new-forward-keys.json"
        destination.write_text("new-active-state", encoding="utf-8")
        old.write_text("old-passive-state", encoding="utf-8")
        changes = [{
            "label": "data/keys.json", "dest": str(destination),
            "new": str(new), "old": str(old), "had_old": True,
        }]
        replica._escribir_journal(
            "swapped", changes, was_running=True, keep_new_on_recovery=True)

        with self._stateful_docker(running=False), \
                mock.patch.object(replica, "_esperar_salud", return_value=True):
            result = replica.recuperar_transaccion()

        self.assertEqual(result["action"], "promoted-swap-completed")
        self.assertEqual(destination.read_text(encoding="utf-8"),
                         "new-active-state")
        self.assertFalse(old.exists())
        self.assertFalse(Path(replica.RUTA_JOURNAL).exists())

    def test_promoted_swap_recovery_rolls_back_when_the_new_state_is_unhealthy(self):
        target_data = self.temp / "forward-rollback-data"
        target_le = self.temp / "forward-rollback-letsencrypt"
        target_data.mkdir()
        target_le.mkdir()
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        destination = target_data / "keys.json"
        old = target_data / ".npmg-old-forward-rollback-keys.json"
        new = target_data / ".npmg-new-forward-rollback-keys.json"
        destination.write_text("unhealthy-new-state", encoding="utf-8")
        old.write_text("healthy-old-state", encoding="utf-8")
        changes = [{
            "label": "data/keys.json", "dest": str(destination),
            "new": str(new), "old": str(old), "had_old": True,
        }]
        replica._escribir_journal(
            "swapped", changes, was_running=True, keep_new_on_recovery=True)

        with self._stateful_docker(running=False) as (state, _get, stop, start), \
                mock.patch.object(replica, "_esperar_salud",
                                  side_effect=[False, True]):
            result = replica.recuperar_transaccion()

        self.assertEqual(result["action"], "promoted-swap-rolled-back")
        self.assertEqual(destination.read_text(encoding="utf-8"),
                         "healthy-old-state")
        self.assertTrue(state["running"])
        self.assertGreaterEqual(stop.call_count, 1)
        self.assertGreaterEqual(start.call_count, 2)
        self.assertFalse(Path(replica.RUTA_JOURNAL).exists())

    def test_prepared_journal_is_durable_before_npm_is_stopped(self):
        package = replica.empaquetar()
        target_data = self.temp / "journal-order-data"
        target_le = self.temp / "journal-order-letsencrypt"
        self._create_npm_state(target_data, target_le, "before")
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        events = []
        real_write_journal = replica._escribir_journal

        def write_journal(state, changes, was_running=True,
                          keep_new_on_recovery=False):
            result = real_write_journal(
                state, changes, was_running, keep_new_on_recovery)
            events.append(f"journal:{state}")
            return result

        def stop(container):
            events.append("docker:stop")
            document = json.loads(Path(replica.RUTA_JOURNAL).read_text(
                encoding="utf-8"))
            self.assertEqual(document["state"], "prepared")
            self.assertTrue(document["was_running"])
            self.assertFalse(document["keep_new_on_recovery"])
            self.assertEqual(container, replica.CONTENEDOR)

        with self._stateful_docker(on_stop=stop), \
                mock.patch.object(replica, "_esperar_salud", return_value=True), \
                mock.patch.object(replica, "_escribir_journal",
                                  side_effect=write_journal):
            result = replica.aplicar(package, soy_el_activo=False)

        self.assertTrue(result["ok"], result)
        self.assertLess(events.index("journal:prepared"),
                        events.index("docker:stop"))

    def test_prepared_recovery_restarts_npm_without_touching_destinations(self):
        target_data = self.temp / "prepared-recovery-data"
        target_le = self.temp / "prepared-recovery-letsencrypt"
        target_data.mkdir()
        target_le.mkdir()
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        destination = target_data / "keys.json"
        new = target_data / ".npmg-new-prepared-keys.json"
        old = target_data / ".npmg-old-prepared-keys.json"
        destination.write_text("original", encoding="utf-8")
        new.write_text("staged-but-unpublished", encoding="utf-8")
        changes = [{
            "label": "data/keys.json", "dest": str(destination),
            "new": str(new), "old": str(old), "had_old": True,
        }]
        replica._escribir_journal("prepared", changes, was_running=True)

        with self._stateful_docker(running=False) as (_state, _get, stop, start), \
                mock.patch.object(replica, "_esperar_salud", return_value=True), \
                mock.patch.object(replica, "_recuperar_cambios") as rollback:
            result = replica.recuperar_transaccion()

        self.assertEqual(result["action"], "prepared-cleaned")
        self.assertEqual(destination.read_text(encoding="utf-8"), "original")
        self.assertFalse(new.exists())
        self.assertFalse(Path(replica.RUTA_JOURNAL).exists())
        stop.assert_not_called()
        rollback.assert_not_called()
        start.assert_called_once_with(replica.CONTENEDOR)

    def test_swap_rollback_fsyncs_restored_directories_before_deleting_journal(self):
        target_data = self.temp / "rollback-durable-data"
        target_le = self.temp / "rollback-durable-letsencrypt"
        target_data.mkdir()
        target_le.mkdir()
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        destination = target_data / "keys.json"
        new = target_data / ".npmg-new-durable-keys.json"
        old = target_data / ".npmg-old-durable-keys.json"
        destination.write_text("original", encoding="utf-8")
        new.write_text("candidate", encoding="utf-8")
        changes = [{
            "label": "data/keys.json", "dest": str(destination),
            "new": str(new), "old": str(old), "had_old": True,
        }]
        events = []
        real_replace = replica.os.replace
        real_fsync_directory = replica._fsync_directorio
        real_delete_journal = replica._borrar_journal

        def fail_publication(source, target):
            if (os.path.abspath(source) == os.path.abspath(new) and
                    os.path.abspath(target) == os.path.abspath(destination)):
                raise OSError("simulated publication failure")
            return real_replace(source, target)

        def fsync_directory(path):
            events.append(("fsync", os.path.abspath(path)))
            return real_fsync_directory(path)

        def delete_journal():
            events.append(("delete-journal", ""))
            return real_delete_journal()

        with mock.patch.object(replica.os, "replace", side_effect=fail_publication), \
                mock.patch.object(replica, "_fsync_directorio",
                                  side_effect=fsync_directory), \
                mock.patch.object(replica, "_borrar_journal",
                                  side_effect=delete_journal):
            with self.assertRaises(replica.SwapRevertido):
                replica._intercambiar(changes, was_running=True)
            self.assertTrue(Path(replica.RUTA_JOURNAL).is_file())
            replica._borrar_journal()

        target_fsync = events.index(("fsync", os.path.abspath(target_data)))
        journal_delete = events.index(("delete-journal", ""))
        self.assertLess(target_fsync, journal_delete)
        self.assertEqual(destination.read_text(encoding="utf-8"), "original")
        self.assertFalse(Path(replica.RUTA_JOURNAL).exists())

    def test_swap_rollback_fsync_failure_propagates_and_preserves_journal(self):
        target_data = self.temp / "rollback-fsync-failure-data"
        target_le = self.temp / "rollback-fsync-failure-letsencrypt"
        target_data.mkdir()
        target_le.mkdir()
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        destination = target_data / "keys.json"
        new = target_data / ".npmg-new-fsync-failure-keys.json"
        old = target_data / ".npmg-old-fsync-failure-keys.json"
        destination.write_text("original", encoding="utf-8")
        new.write_text("candidate", encoding="utf-8")
        changes = [{
            "label": "data/keys.json", "dest": str(destination),
            "new": str(new), "old": str(old), "had_old": True,
        }]
        real_replace = replica.os.replace
        real_fsync_directory = replica._fsync_directorio

        def fail_publication(source, target):
            if (os.path.abspath(source) == os.path.abspath(new) and
                    os.path.abspath(target) == os.path.abspath(destination)):
                raise OSError("simulated publication failure")
            return real_replace(source, target)

        def fail_rollback_fsync(path):
            if os.path.abspath(path) == os.path.abspath(target_data):
                raise OSError("simulated fsync failure")
            return real_fsync_directory(path)

        with mock.patch.object(replica.os, "replace", side_effect=fail_publication), \
                mock.patch.object(replica, "_fsync_directorio",
                                  side_effect=fail_rollback_fsync), \
                self.assertRaises(replica.ErrorRollback):
            replica._intercambiar(changes, was_running=True)

        self.assertEqual(destination.read_text(encoding="utf-8"), "original")
        self.assertTrue(Path(replica.RUTA_JOURNAL).is_file())

    def test_restart_recovery_propagates_fsync_failure_and_keeps_journal(self):
        target_data = self.temp / "recovery-fsync-failure-data"
        target_le = self.temp / "recovery-fsync-failure-letsencrypt"
        target_data.mkdir()
        target_le.mkdir()
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        destination = target_data / "keys.json"
        new = target_data / ".npmg-new-recovery-failure-keys.json"
        old = target_data / ".npmg-old-recovery-failure-keys.json"
        destination.write_text("partially-applied", encoding="utf-8")
        old.write_text("original", encoding="utf-8")
        changes = [{
            "label": "data/keys.json", "dest": str(destination),
            "new": str(new), "old": str(old), "had_old": True,
        }]
        replica._escribir_journal("swapping", changes, was_running=True)
        real_fsync_directory = replica._fsync_directorio

        def fail_recovery_fsync(path):
            if os.path.abspath(path) == os.path.abspath(target_data):
                raise OSError("simulated fsync failure")
            return real_fsync_directory(path)

        with self._stateful_docker(running=False) as (_state, _get, stop, start), \
                mock.patch.object(replica, "_fsync_directorio",
                                  side_effect=fail_recovery_fsync), \
                self.assertRaisesRegex(replica.ErrorReplica, "recuperar"):
            replica.recuperar_transaccion()

        self.assertEqual(destination.read_text(encoding="utf-8"), "original")
        self.assertTrue(Path(replica.RUTA_JOURNAL).is_file())
        stop.assert_not_called()
        start.assert_not_called()

    def test_every_staging_tree_is_fsynced_before_the_first_swap(self):
        package = replica.empaquetar()
        target_data = self.temp / "fsync-order-data"
        target_le = self.temp / "fsync-order-letsencrypt"
        self._create_npm_state(target_data, target_le, "before")
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        events = []
        real_fsync_tree = replica._fsync_arbol
        real_swap = replica._intercambiar

        def fsync_tree(path):
            events.append(("fsync", os.path.abspath(path)))
            return real_fsync_tree(path)

        def swap(changes, *args, **kwargs):
            staged = {
                os.path.abspath(change["new"]) for change in changes
                if change.get("new") is not None
            }
            durable = {path for event, path in events if event == "fsync"}
            self.assertTrue(staged)
            self.assertEqual(staged, durable)
            events.append(("swap", ""))
            return real_swap(changes, *args, **kwargs)

        with self._stateful_docker(), \
                mock.patch.object(replica, "_esperar_salud", return_value=True), \
                mock.patch.object(replica, "_fsync_arbol", side_effect=fsync_tree), \
                mock.patch.object(replica, "_intercambiar", side_effect=swap):
            result = replica.aplicar(package, soy_el_activo=False)

        self.assertTrue(result["ok"], result)
        self.assertEqual(sum(1 for event, _path in events if event == "swap"), 1)

    def test_replica_health_delegates_to_the_shared_npm_api_tls_probe(self):
        with mock.patch.dict(os.environ, {
                "NPMG_NODE_NAME": "node-a",
                "NPMG_NODE_ADDRESS": "192.0.2.10",
        }), mock.patch.object(npm_api, "api_responde", return_value=True) as probe:
            self.assertTrue(replica._npm_responde())
        probe.assert_called_once_with("node-a", timeout=3)

    def test_failed_health_check_rolls_back_previous_state(self):
        package = replica.empaquetar()
        target_data = self.temp / "rollback-data"
        target_le = self.temp / "rollback-letsencrypt"
        self._create_npm_state(target_data, target_le, "before")
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        with self._stateful_docker(), \
                mock.patch.object(replica, "_esperar_salud", side_effect=[False, True]), \
                self.assertRaisesRegex(replica.ErrorReplica, "no recuper"):
            replica.aplicar(package, soy_el_activo=False)
        self.assertEqual(self._database_marker(target_data), "before")
        self.assertEqual((target_data / "nginx" / "proxy.conf").read_text(), "before")

    def test_post_replica_http_503_never_reaches_committed_state(self):
        package = replica.empaquetar()
        target_data = self.temp / "http-503-data"
        target_le = self.temp / "http-503-letsencrypt"
        self._create_npm_state(target_data, target_le, "before")
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        journal_states = []
        real_write_journal = replica._escribir_journal

        def write_journal(state, changes, was_running=True,
                          keep_new_on_recovery=False):
            journal_states.append(state)
            return real_write_journal(
                state, changes, was_running, keep_new_on_recovery)

        class HealthyResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        unavailable = npm_api.urllib.error.HTTPError(
            "https://node-a/api/", 503, "upstream unavailable", {},
            io.BytesIO(b"unavailable"))
        with self._stateful_docker(), \
                mock.patch.object(replica.time, "monotonic",
                                  side_effect=[0, 0, 61, 100, 100]), \
                mock.patch.object(replica.time, "sleep"), \
                mock.patch.object(npm_api, "_base_del_activo",
                                  return_value="https://node-a:81"), \
                mock.patch.object(npm_api, "_abrir",
                                  side_effect=[unavailable, HealthyResponse()]), \
                mock.patch.object(replica, "_escribir_journal",
                                  side_effect=write_journal), \
                self.assertRaisesRegex(replica.ErrorReplica, "no recuper"):
            replica.aplicar(package, soy_el_activo=False)

        self.assertNotIn("committed", journal_states)
        self.assertEqual(self._database_marker(target_data), "before")
        self.assertFalse(Path(replica.RUTA_JOURNAL).exists())

    def test_restart_recovery_rolls_back_and_restarts_npm_even_if_crash_left_it_stopped(self):
        target_data = self.temp / "crash-data"
        target_le = self.temp / "crash-letsencrypt"
        target_data.mkdir()
        target_le.mkdir()
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        destination = target_data / "keys.json"
        old = target_data / ".npmg-old-crash-keys.json"
        new = target_data / ".npmg-new-crash-keys.json"
        destination.write_text("partially applied", encoding="utf-8")
        old.write_text("original", encoding="utf-8")
        journal = {
            "version": 1,
            "state": "swapping",
            "was_running": True,
            "keep_new_on_recovery": False,
            "changes": [{
                "label": "data/keys.json", "dest": str(destination),
                "new": str(new), "old": str(old), "had_old": True,
            }],
        }
        Path(replica.RUTA_JOURNAL).parent.mkdir(parents=True, exist_ok=True)
        Path(replica.RUTA_JOURNAL).write_text(
            json.dumps(journal), encoding="utf-8")
        with self._stateful_docker(running=False) as (_state, _get, stop, start), \
                mock.patch.object(replica, "_esperar_salud", return_value=True):
            result = replica.recuperar_transaccion()
        self.assertTrue(result["recovered"])
        self.assertEqual(result["action"], "rolled-back")
        self.assertEqual(destination.read_text(encoding="utf-8"), "original")
        self.assertFalse(Path(replica.RUTA_JOURNAL).exists())
        stop.assert_not_called()
        start.assert_called_once_with(replica.CONTENEDOR)

    def test_apply_refuses_a_passive_whose_npm_was_already_stopped(self):
        package = replica.empaquetar()
        target_data = self.temp / "stopped-data"
        target_le = self.temp / "stopped-letsencrypt"
        self._create_npm_state(target_data, target_le, "must-stay")
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        with mock.patch.object(
                replica.dockerd, "estado",
                return_value={"existe": True, "corriendo": False}), \
                mock.patch.object(replica.dockerd, "parar") as stop, \
                mock.patch.object(replica.dockerd, "arrancar") as start, \
                self.assertRaisesRegex(replica.ErrorReplica, "no est.*marcha"):
            replica.aplicar(package, soy_el_activo=False)
        self.assertEqual(self._database_marker(target_data), "must-stay")
        stop.assert_not_called()
        start.assert_not_called()

    def test_role_change_after_swap_never_rolls_back_over_the_new_active(self):
        """Al convertirse en activo, el receptor queda cercado frente al rollback."""
        package = replica.empaquetar()
        target_data = self.temp / "promoted-data"
        target_le = self.temp / "promoted-letsencrypt"
        self._create_npm_state(target_data, target_le, "before-promotion")
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        npm_started = {"value": False}
        promotion_observed = {"value": False}

        def start(_container):
            npm_started["value"] = True

        def still_passive():
            # La promoción sucede después de aplicar y arrancar la réplica,
            # justo antes de la última comprobación de rol.
            if npm_started["value"]:
                promotion_observed["value"] = True
                raise replica.ErrorReplica("este nodo acaba de convertirse en activo")

        real_restore = replica._restaurar
        with self._stateful_docker(on_start=start) as (
                _state, _get, stop, restart), \
                mock.patch.object(replica, "_esperar_salud", return_value=True), \
                mock.patch.object(replica, "_restaurar", wraps=real_restore) as rollback:
            result = replica.aplicar(
                package, soy_el_activo=False,
                comprobar_pasivo=still_passive)

        rollback.assert_not_called()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["promoted_during_apply"], result)
        self.assertTrue(promotion_observed["value"])
        self.assertEqual(self._database_marker(target_data), "source")
        stop.assert_called_once_with(replica.CONTENEDOR)
        restart.assert_called_once_with(replica.CONTENEDOR)

    def test_active_node_and_oversized_body_are_rejected_before_docker(self):
        package = replica.empaquetar()
        with mock.patch.object(replica.dockerd, "estado") as docker_state, \
                self.assertRaisesRegex(replica.ErrorReplica, "activo"):
            replica.aplicar(package, soy_el_activo=True)
        docker_state.assert_not_called()
        with mock.patch.object(replica, "_extraer_validado") as extract, \
                self.assertRaisesRegex(replica.ErrorReplica, "comprimido"):
            replica.aplicar(b"x" * (replica.MAX_TAMANO + 1), soy_el_activo=False)
        extract.assert_not_called()

    def test_fenced_active_can_recover_a_validated_newer_snapshot(self):
        package = replica.empaquetar()
        target_data = self.temp / "active-recovery-data"
        target_le = self.temp / "active-recovery-letsencrypt"
        self._create_npm_state(target_data, target_le, "stale-active")
        replica.RUTA_DATOS = str(target_data)
        replica.RUTA_LE = str(target_le)
        checks = []

        def still_active():
            checks.append("active")

        with self._stateful_docker(), \
                mock.patch.object(replica, "_esperar_salud", return_value=True):
            result = replica.aplicar(
                package, soy_el_activo=True,
                comprobar_activo=still_active)

        self.assertTrue(result["ok"], result)
        self.assertFalse(result["role_changed_during_apply"], result)
        self.assertGreaterEqual(len(checks), 4)
        self.assertEqual(self._database_marker(target_data), "source")


class _SocketContext:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _TlsSocket(_SocketContext):
    def __init__(self, der):
        self.der = der

    def getpeercert(self, binary_form=False):
        return self.der if binary_form else {}


class _TlsContext:
    def __init__(self, by_sni, seen):
        self.by_sni = by_sni
        self.seen = seen
        self.check_hostname = True
        self.verify_mode = None

    def wrap_socket(self, _raw, server_hostname=None):
        self.seen.append(server_hostname)
        return _TlsSocket(self.by_sni[server_hostname])


class TestExactTlsActivation(IsolatedData):
    def setUp(self):
        super().setUp()
        self.original_npm_paths = npm.RUTA_DB, npm.RUTA_LE
        self.npm_data = self.temp / "npm"
        self.npm_le = self.temp / "letsencrypt"
        self.npm_data.mkdir()
        self.npm_le.mkdir()
        npm.RUTA_DB = str(self.npm_data / "database.sqlite")
        npm.RUTA_LE = str(self.npm_le)

    def tearDown(self):
        npm.RUTA_DB, npm.RUTA_LE = self.original_npm_paths
        super().tearDown()

    @staticmethod
    def _certificate(common_name):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), False)
            .sign(key, hashes.SHA256())
        )
        return (certificate.public_bytes(serialization.Encoding.PEM),
                certificate.public_bytes(serialization.Encoding.DER))

    def _database(self, domains, redirect_domains=None, dead_domains=None):
        connection = sqlite3.connect(npm.RUTA_DB)
        connection.execute("create table certificate (id integer, expires_on text)")
        connection.execute(
            "create table proxy_host (domain_names text, is_deleted integer, "
            "enabled integer, certificate_id integer)")
        connection.execute(
            "create table redirection_host (domain_names text, is_deleted integer, "
            "enabled integer, certificate_id integer)")
        connection.execute(
            "create table dead_host (domain_names text, is_deleted integer, "
            "enabled integer, certificate_id integer)")
        connection.execute("insert into certificate values (7, '2026-12-01 00:00:00')")
        for domain in domains:
            connection.execute(
                "insert into proxy_host values (?, 0, 1, 7)",
                (json.dumps([domain]),))
        for domain in redirect_domains or []:
            connection.execute(
                "insert into redirection_host values (?, 0, 1, 7)",
                (json.dumps([domain]),))
        for domain in dead_domains or []:
            connection.execute(
                "insert into dead_host values (?, 0, 1, 7)",
                (json.dumps([domain]),))
        connection.commit()
        connection.close()

    def test_every_active_sni_must_serve_the_exact_saved_der_certificate(self):
        domains = ["one.example.test", "two.example.test"]
        self._database(domains)
        saved_pem, saved_der = self._certificate(domains[0])
        _, other_der = self._certificate(domains[1])
        live = self.npm_le / "live" / "npm-7"
        live.mkdir(parents=True)
        (live / "fullchain.pem").write_bytes(saved_pem)

        seen = []
        tls = _TlsContext({domains[0]: saved_der, domains[1]: saved_der}, seen)
        with mock.patch.object(npm.socket, "create_connection",
                               return_value=_SocketContext()), \
                mock.patch.object(npm.ssl, "create_default_context", return_value=tls):
            result = npm.comprobar_certificado_servido(7, "192.0.2.10")
        self.assertTrue(result["ok"])
        self.assertEqual(seen, domains)
        self.assertTrue(all(item["ok"] for item in result["dominios"]))

        seen.clear()
        tls = _TlsContext({domains[0]: saved_der, domains[1]: other_der}, seen)
        with mock.patch.object(npm.socket, "create_connection",
                               return_value=_SocketContext()), \
                mock.patch.object(npm.ssl, "create_default_context", return_value=tls):
            result = npm.comprobar_certificado_servido(7, "192.0.2.10")
        self.assertFalse(result["ok"])
        self.assertEqual(seen, domains)
        self.assertFalse(result["dominios"][1]["ok"])

    def test_certificate_without_active_consumer_is_not_claimed_as_served(self):
        self._database([])
        with mock.patch.object(npm.socket, "create_connection") as connect:
            result = npm.comprobar_certificado_servido(7, "192.0.2.10")
        self.assertFalse(result["ok"])
        self.assertFalse(result["verificable"])
        connect.assert_not_called()

    def test_redirection_host_is_an_active_tls_consumer_too(self):
        domain = "redirect.example.test"
        self._database([], redirect_domains=[domain])
        saved_pem, saved_der = self._certificate(domain)
        live = self.npm_le / "live" / "npm-7"
        live.mkdir(parents=True)
        (live / "fullchain.pem").write_bytes(saved_pem)

        seen = []
        tls = _TlsContext({domain: saved_der}, seen)
        with mock.patch.object(npm.socket, "create_connection",
                               return_value=_SocketContext()), \
                mock.patch.object(npm.ssl, "create_default_context", return_value=tls):
            result = npm.comprobar_certificado_servido(7, "192.0.2.10")
        self.assertTrue(result["ok"], result)
        self.assertEqual(seen, [domain])

    def test_dead_host_is_an_active_tls_consumer_too(self):
        domain = "dead.example.test"
        self._database([], dead_domains=[domain])
        saved_pem, saved_der = self._certificate(domain)
        live = self.npm_le / "live" / "npm-7"
        live.mkdir(parents=True)
        (live / "fullchain.pem").write_bytes(saved_pem)

        seen = []
        tls = _TlsContext({domain: saved_der}, seen)
        with mock.patch.object(npm.socket, "create_connection",
                               return_value=_SocketContext()), \
                mock.patch.object(npm.ssl, "create_default_context", return_value=tls):
            result = npm.comprobar_certificado_servido(7, "192.0.2.10")
        self.assertTrue(result["ok"], result)
        self.assertEqual(seen, [domain])


class TestRenewalLedgerAndTimeout(IsolatedData):
    DOMAINS = ["example.test"]

    @classmethod
    def quota_key(cls):
        return reintentos.clave_san(cls.DOMAINS)

    def tearDown(self):
        vigilante.usar_autoridad(None)
        vigilante.usar_replicador(None)
        vigilante.usar_replicador_estado(None)
        super().tearDown()

    @staticmethod
    def _authority():
        return {"soy_yo": True, "activo": "node-a"}

    def _assert_reconciliation_locks(self, observations, phase):
        def contend():
            renewal = vigilante._candado_renovacion.acquire(blocking=False)
            npm_write = vigilante.coordinacion.escritura_npm.acquire(blocking=False)
            if renewal:
                vigilante._candado_renovacion.release()
            if npm_write:
                vigilante.coordinacion.escritura_npm.release()
            return renewal, npm_write

        with ThreadPoolExecutor(max_workers=1) as pool:
            acquired = pool.submit(contend).result(timeout=5)
        self.assertEqual(acquired, (False, False), phase)
        observations.append(phase)

    def _seed_indeterminate(self, since=100.0):
        state = {}
        reintentos.registrar_en_curso(
            state, self.quota_key(), "2026-10-01 00:00:00", ahora=since,
            id_cert=7, dominios=self.DOMAINS)
        reintentos.marcar_indeterminado(state, self.quota_key())
        vigilante.guardar_estado(state)

    def test_successful_indeterminate_reconciliation_holds_both_locks_and_replicates(self):
        self._seed_indeterminate()
        observations = []
        vigilante.usar_autoridad(self._authority)

        def certificate_state(_certificate_id):
            self._assert_reconciliation_locks(observations, "npm-state")
            return {"caduca": "2026-12-01 00:00:00", "fingerprint": "new"}

        def replicate_npm():
            self._assert_reconciliation_locks(observations, "npm-data")
            return {"ok": True, "complete": True, "resultados": {}}

        def replicate_ledger():
            self._assert_reconciliation_locks(observations, "ledger")
            return {"ok": True, "complete": True, "resultados": {}}

        vigilante.usar_replicador(replicate_npm)
        vigilante.usar_replicador_estado(replicate_ledger)
        served = {"ok": True, "verificable": True,
                  "caduca_guardado": "2026-12-01T00:00:00+00:00",
                  "caduca_servido": "2026-12-01T00:00:00+00:00"}
        activation = {"ok": True, "reload_attempted": False,
                      "reload_ok": True, "checks": 1}
        certificates = {7: {
            "id": 7, "nombre": "example.test", "dominios": self.DOMAINS}}
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               side_effect=certificate_state), \
                mock.patch.object(vigilante, "_activar_certificado",
                                  return_value=(served, activation)), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}):
            results = vigilante._reconciliar_indeterminados("node-a", certificates)

        self.assertEqual(len(results), 1, results)
        self.assertTrue(results[0]["ok"], results[0])
        self.assertEqual(observations, ["npm-state", "npm-data", "ledger"])
        entry = vigilante.leer_estado()["reintentos"][self.quota_key()]
        self.assertFalse(entry["agotado"])
        self.assertIn("completed_at", entry)
        self.assertNotIn("reconciliacion", entry)

    def test_expired_indeterminate_reconciliation_holds_both_locks_and_replicates(self):
        self._seed_indeterminate()
        observations = []
        vigilante.usar_autoridad(self._authority)

        def unchanged_state(_certificate_id):
            self._assert_reconciliation_locks(observations, "npm-state")
            return {"caduca": "2026-10-01 00:00:00", "fingerprint": "old"}

        def replicate_ledger():
            self._assert_reconciliation_locks(observations, "ledger")
            return {"ok": True, "complete": True, "resultados": {}}

        vigilante.usar_replicador_estado(replicate_ledger)
        certificates = {7: {
            "id": 7, "nombre": "example.test", "dominios": self.DOMAINS}}
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               side_effect=unchanged_state), \
                mock.patch.object(vigilante.time, "time", return_value=10_000.0), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}):
            results = vigilante._reconciliar_indeterminados("node-a", certificates)

        self.assertEqual(results, [])
        self.assertEqual(observations, ["npm-state", "ledger"])
        entry = vigilante.leer_estado()["reintentos"][self.quota_key()]
        self.assertEqual(entry["reconciliacion"]["estado"], "fallo_confirmado")
        self.assertEqual(entry["reconciliacion"]["confirmado_en"], 10_000.0)

    def test_issuance_is_not_sent_until_ledger_reaches_quorum(self):
        client_factory = mock.Mock()
        vigilante.usar_autoridad(self._authority)
        replication = mock.Mock(return_value={
            "ok": False, "resultados": {"node-b": {"ok": False}}})
        vigilante.usar_replicador_estado(replication)
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               return_value={"caduca": "2026-10-01 00:00:00"}), \
                mock.patch.object(vigilante.npm_api, "cliente_del_activo", client_factory):
            result = vigilante.renovar(
                7, "example.test", "node-a", dominios=self.DOMAINS)
        self.assertEqual(result["code"], "RENEWAL_LEDGER_NOT_REPLICATED")
        self.assertFalse(result["hecho"])
        client_factory.assert_not_called()
        self.assertNotIn(
            self.quota_key(), vigilante.leer_estado().get("reintentos", {}))
        self.assertGreaterEqual(replication.call_count, 2)

    def test_success_uses_last_moment_authority_check_and_clears_ledger(self):
        authority = mock.Mock(side_effect=self._authority)
        replication = mock.Mock(return_value={"ok": True, "resultados": {}})
        vigilante.usar_autoridad(authority)
        vigilante.usar_replicador_estado(replication)
        client = mock.Mock()

        def issue(cert_id, validar_envio=None):
            self.assertEqual(cert_id, 7)
            self.assertTrue(callable(validar_envio))
            validar_envio()
            return {"id": cert_id}

        client.renovar.side_effect = issue
        served = {"ok": True, "verificable": True,
                  "caduca_guardado": "2026-12-01T00:00:00+00:00",
                  "caduca_servido": "2026-12-01T00:00:00+00:00"}
        activation = {"ok": True, "reload_attempted": False,
                      "reload_ok": True, "checks": 1}
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               return_value={"caduca": "2026-10-01 00:00:00"}), \
                mock.patch.object(vigilante.npm_api, "cliente_del_activo",
                                  return_value=client), \
                mock.patch.object(vigilante, "_esperar_resultado",
                                  return_value={"caduca": "2026-12-01 00:00:00"}), \
                mock.patch.object(vigilante, "_activar_certificado",
                                  return_value=(served, activation)), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}):
            result = vigilante.renovar(
                7, "example.test", "node-a", dominios=self.DOMAINS)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(authority.call_count, 2)
        self.assertGreaterEqual(replication.call_count, 2)
        entry = vigilante.leer_estado()["reintentos"][self.quota_key()]
        self.assertEqual(entry["certificate_id"], 7)
        self.assertEqual(entry["domains"], self.DOMAINS)
        self.assertEqual(len(entry["intentos"]), 1)
        self.assertIn("completed_at", entry)
        self.assertNotIn("reconciliacion", entry)

    def test_successful_renewal_can_replicate_under_the_reentrant_npm_lock(self):
        """Finalizar la emision sincroniza datos sin auto-bloquear la operacion."""
        import servidor

        vigilante.usar_autoridad(self._authority)
        vigilante.usar_replicador_estado(
            lambda: {"ok": True, "complete": True, "resultados": {}})
        vigilante.usar_replicador(servidor.sincronizar)
        client = mock.Mock()

        def issue(cert_id, validar_envio=None):
            validar_envio()
            return {"id": cert_id}

        client.renovar.side_effect = issue
        served = {"ok": True, "verificable": True,
                  "caduca_guardado": "2026-12-01T00:00:00+00:00",
                  "caduca_servido": "2026-12-01T00:00:00+00:00"}
        activation = {"ok": True, "reload_attempted": False,
                      "reload_ok": True, "checks": 1}
        sync_result = {"ok": True, "complete": True, "hecho": True,
                       "resultados": {}}
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               return_value={"caduca": "2026-10-01 00:00:00"}), \
                mock.patch.object(vigilante.npm_api, "cliente_del_activo",
                                  return_value=client), \
                mock.patch.object(vigilante, "_esperar_resultado",
                                  return_value={"caduca": "2026-12-01 00:00:00"}), \
                mock.patch.object(vigilante, "_activar_certificado",
                                  return_value=(served, activation)), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}), \
                mock.patch.object(servidor, "_sincronizar",
                                  return_value=sync_result) as inner_sync:
            result = vigilante.renovar(
                7, "example.test", "node-a", dominios=self.DOMAINS)

        self.assertTrue(result["ok"], result)
        self.assertNotEqual(result.get("code"), "NPM_OPERATION_BUSY")
        self.assertEqual(result["replication"], sync_result)
        inner_sync.assert_called_once_with(False)

    def test_timeout_becomes_indeterminate_and_never_issues_twice(self):
        vigilante.usar_autoridad(self._authority)
        vigilante.usar_replicador_estado(
            lambda: {"ok": True, "resultados": {}})
        client = mock.Mock()
        client.renovar.side_effect = npm_api.ErrorNPM(
            "request timed out", "timeout", resultado_indeterminado=True)
        factory = mock.Mock(return_value=client)
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               return_value={"caduca": "2026-10-01 00:00:00"}), \
                mock.patch.object(vigilante.npm_api, "cliente_del_activo", factory), \
                mock.patch.object(vigilante, "_esperar_resultado", return_value=None), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}):
            first = vigilante.renovar(
                7, "example.test", "node-a", dominios=self.DOMAINS)
            second = vigilante.renovar(
                7, "example.test", "node-a", dominios=self.DOMAINS)
        self.assertTrue(first["indeterminado"])
        self.assertEqual(second["code"], "RENEWAL_QUOTA_BLOCKED")
        self.assertIn("pendiente", second["error"])
        client.renovar.assert_called_once()
        ledger = vigilante.leer_estado()["reintentos"][self.quota_key()][
            "reconciliacion"]
        self.assertEqual(ledger["estado"], "indeterminado")

    def test_timeout_reconciled_in_npm_finishes_without_another_issuance(self):
        vigilante.usar_autoridad(self._authority)
        vigilante.usar_replicador_estado(
            lambda: {"ok": True, "resultados": {}})
        client = mock.Mock()
        client.renovar.side_effect = npm_api.ErrorNPM(
            "timeout", "timeout", resultado_indeterminado=True)
        served = {"ok": True, "verificable": True,
                  "caduca_guardado": "2026-12-01T00:00:00+00:00",
                  "caduca_servido": "2026-12-01T00:00:00+00:00"}
        activation = {"ok": True, "reload_attempted": False,
                      "reload_ok": True, "checks": 1}
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               return_value={"caduca": "2026-10-01 00:00:00"}), \
                mock.patch.object(vigilante.npm_api, "cliente_del_activo",
                                  return_value=client), \
                mock.patch.object(vigilante, "_esperar_resultado",
                                  return_value={"caduca": "2026-12-01 00:00:00"}), \
                mock.patch.object(vigilante, "_activar_certificado",
                                  return_value=(served, activation)), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}):
            result = vigilante.renovar(
                7, "example.test", "node-a", dominios=self.DOMAINS)
        self.assertTrue(result["ok"])
        self.assertTrue(result["reconciliada"])
        client.renovar.assert_called_once()
        entry = vigilante.leer_estado()["reintentos"][self.quota_key()]
        self.assertEqual(len(entry["intentos"]), 1)
        self.assertIn("completed_at", entry)
        self.assertNotIn("reconciliacion", entry)

    def test_overlapping_san_sets_share_the_per_identifier_failure_budget(self):
        """El límite por hostname no se puede eludir cambiando el resto del SAN."""
        now = time.time()
        domains_a = ["shared.example.test", "first.example.test"]
        domains_b = ["shared.example.test", "second.example.test"]
        key_a = reintentos.clave_san(domains_a)
        state = {}
        for offset in range(reintentos.MAX_FALLOS_HORA):
            reintentos.registrar_intento(
                state, key_a, ok=False, ahora=now - offset,
                id_cert=7, dominios=domains_a)
        vigilante.guardar_estado(state)

        vigilante.usar_autoridad(self._authority)
        vigilante.usar_replicador_estado(
            lambda: {"ok": True, "resultados": {}})
        factory = mock.Mock()
        factory.return_value.renovar.return_value = {"id": 8}
        served = {"ok": True, "verificable": True}
        activation = {"ok": True, "reload_attempted": False,
                      "reload_ok": True, "checks": 1}
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               return_value={"caduca": "2026-10-01 00:00:00"}), \
                mock.patch.object(vigilante.npm_api, "cliente_del_activo", factory), \
                mock.patch.object(vigilante, "_esperar_resultado", return_value=None), \
                mock.patch.object(vigilante, "_activar_certificado",
                                  return_value=(served, activation)), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}):
            result = vigilante.renovar(
                8, "shared.example.test", "node-a", dominios=domains_b)
        self.assertEqual(result.get("code"), "RENEWAL_QUOTA_BLOCKED", result)
        factory.assert_not_called()

        # El agregado es por identificador ACME; un SAN totalmente separado no
        # hereda los fallos de shared.example.test.
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               return_value={"caduca": "2026-10-01 00:00:00"}), \
                mock.patch.object(vigilante.npm_api, "cliente_del_activo", factory), \
                mock.patch.object(vigilante, "_esperar_resultado", return_value=None), \
                mock.patch.object(vigilante, "_activar_certificado",
                                  return_value=(served, activation)), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}):
            unrelated = vigilante.renovar(
                9, "unrelated.example.test", "node-a",
                dominios=["unrelated.example.test"])
        self.assertNotEqual(unrelated.get("code"), "RENEWAL_QUOTA_BLOCKED",
                            unrelated)
        factory.assert_called_once()

    def test_http_200_without_a_saved_certificate_change_is_not_success(self):
        vigilante.usar_autoridad(self._authority)
        vigilante.usar_replicador_estado(
            lambda: {"ok": True, "resultados": {}})
        client = mock.Mock()
        client.renovar.return_value = {"id": 7, "status": 200}
        unchanged = {"caduca": "2026-10-01 00:00:00",
                     "fingerprint": "old-pem"}
        served = {"ok": True, "verificable": True,
                  "fingerprint_guardado": "old-pem",
                  "caduca_guardado": "2026-10-01T00:00:00+00:00",
                  "caduca_servido": "2026-10-01T00:00:00+00:00"}
        activation_result = {"ok": True, "reload_attempted": False,
                             "reload_ok": True, "checks": 1}
        activation = mock.Mock(return_value=(served, activation_result))
        with mock.patch.object(vigilante.npm, "estado_certificado",
                               return_value=unchanged), \
                mock.patch.object(vigilante.npm_api, "cliente_del_activo",
                                  return_value=client), \
                mock.patch.object(vigilante, "_esperar_resultado", return_value=None), \
                mock.patch.object(vigilante, "_activar_certificado", activation), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}):
            result = vigilante.renovar(
                7, "example.test", "node-a", dominios=self.DOMAINS)

        self.assertFalse(result.get("ok", False), result)
        self.assertIsNot(result.get("emision_ok"), True)
        entry = vigilante.leer_estado()["reintentos"][self.quota_key()]
        self.assertNotIn("completed_at", entry)
        self.assertIn((entry.get("reconciliacion") or {}).get("estado"),
                      ("en_curso", "indeterminado"))

    def test_losing_authority_after_issuance_never_marks_the_ledger_completed(self):
        role = {"active": True}

        def current_role():
            return ({"soy_yo": True, "activo": "node-a"} if role["active"] else
                    {"soy_yo": False, "activo": "node-b"})

        authority = mock.Mock(side_effect=current_role)
        vigilante.usar_autoridad(authority)
        vigilante.usar_replicador_estado(
            lambda: {"ok": True, "resultados": {}})
        client = mock.Mock()

        def issue(cert_id, validar_envio=None):
            validar_envio()
            role["active"] = False
            return {"id": cert_id, "status": 200}

        client.renovar.side_effect = issue
        old = {"caduca": "2026-10-01 00:00:00", "fingerprint": "old"}
        new = {"caduca": "2026-12-01 00:00:00", "fingerprint": "new"}
        with mock.patch.object(vigilante.npm, "estado_certificado", return_value=old), \
                mock.patch.object(vigilante.npm_api, "cliente_del_activo",
                                  return_value=client), \
                mock.patch.object(vigilante, "_esperar_resultado", return_value=new), \
                mock.patch.object(vigilante, "_activar_certificado"), \
                mock.patch.object(vigilante.avisos, "avisar", return_value={"ok": True}):
            result = vigilante.renovar(
                7, "example.test", "node-a", dominios=self.DOMAINS)

        self.assertGreaterEqual(authority.call_count, 3, result)
        entry = vigilante.leer_estado()["reintentos"][self.quota_key()]
        self.assertNotIn("completed_at", entry)
        self.assertIn("reconciliacion", entry)

    def test_corrupt_ledger_without_valid_backup_fails_closed(self):
        Path(vigilante.RUTA_ESTADO).write_text("{broken", encoding="utf-8")
        Path(vigilante.RUTA_ESTADO_BACKUP).write_text("[]", encoding="utf-8")
        with self.assertRaises(vigilante.ErrorEstado):
            vigilante.leer_estado()

    def test_ledger_revision_rejects_stale_and_divergent_writes(self):
        quota_key = self.quota_key()
        state = {"reintentos": {
            quota_key: {"intentos": [1_000_000], "fallos": [],
                        "agotado": False, "certificate_id": 7,
                        "domains": self.DOMAINS,
                        "completed_at": 1_000_000}}}
        vigilante.guardar_estado(state)
        current = vigilante.exportar_estado_cluster()
        self.assertGreater(current["revision"], 0)
        same = vigilante.aplicar_estado_cluster(copy.deepcopy(current))
        self.assertTrue(same["idempotent"])
        before = Path(vigilante.RUTA_ESTADO).read_bytes()

        stale = copy.deepcopy(current)
        stale["revision"] -= 1
        with self.assertRaisesRegex(vigilante.ErrorEstado, "obsoleto"):
            vigilante.aplicar_estado_cluster(stale)
        self.assertEqual(Path(vigilante.RUTA_ESTADO).read_bytes(), before)

        divergent = copy.deepcopy(current)
        divergent["reintentos"] = {
            quota_key: {"intentos": [], "fallos": [], "agotado": False,
                        "certificate_id": 99, "domains": self.DOMAINS}}
        with self.assertRaisesRegex(vigilante.ErrorEstado, "misma revisi"):
            vigilante.aplicar_estado_cluster(divergent)
        self.assertEqual(Path(vigilante.RUTA_ESTADO).read_bytes(), before)

        newer = copy.deepcopy(divergent)
        newer["revision"] += 1
        applied = vigilante.aplicar_estado_cluster(newer)
        self.assertFalse(applied["idempotent"])
        self.assertIn(quota_key, vigilante.exportar_estado_cluster()["reintentos"])

    def test_cluster_merge_prefers_a_later_success_over_an_old_exhausted_node(self):
        quota_key = self.quota_key()
        exhausted = {
            "revision": 8,
            "reintentos": {quota_key: {
                "intentos": [100.0], "fallos": [100.0], "agotado": True,
                "certificate_id": 7, "domains": self.DOMAINS,
            }},
        }
        successful = {
            "revision": 3,
            "reintentos": {quota_key: {
                "intentos": [100.0, 200.0], "fallos": [], "agotado": False,
                "certificate_id": 7, "domains": self.DOMAINS,
                "completed_at": 200.0,
            }},
        }

        merged = vigilante.fusionar_estados_cluster(
            [copy.deepcopy(exhausted), copy.deepcopy(successful)])
        reverse = vigilante.fusionar_estados_cluster(
            [copy.deepcopy(successful), copy.deepcopy(exhausted)])
        self.assertEqual(merged, reverse)
        entry = merged["reintentos"][quota_key]
        self.assertFalse(entry["agotado"])
        self.assertEqual(entry["completed_at"], 200.0)
        self.assertEqual(entry["intentos"], [100.0, 200.0])
        self.assertNotIn("siguiente", entry)
        self.assertNotIn("reconciliacion", entry)

    def test_cluster_merge_keeps_metadata_from_the_newest_event_not_global_revision(self):
        old_domains = ["WWW.Example.Test.", "*.Example.Test"]
        newest_domains = ["*.example.test", "www.example.test"]
        quota_key = reintentos.clave_san(old_domains)
        self.assertEqual(quota_key, reintentos.clave_san(newest_domains))
        globally_newer_but_old_event = {
            "revision": 20,
            "reintentos": {quota_key: {
                "intentos": [100.0], "fallos": [100.0], "agotado": True,
                "certificate_id": 7, "domains": old_domains,
                "reconciliacion": {
                    "estado": "fallo_confirmado", "desde": 80.0,
                    "confirmado_en": 100.0,
                    "caducidad_anterior": "2026-10-01 00:00:00",
                },
            }},
        }
        newer_event_on_lower_revision = {
            "revision": 3,
            "reintentos": {quota_key: {
                "intentos": [200.0], "fallos": [], "agotado": False,
                "certificate_id": 99, "domains": newest_domains,
                "reconciliacion": {
                    "estado": "indeterminado", "desde": 200.0,
                    "caducidad_anterior": "2026-11-01 00:00:00",
                },
            }},
        }

        merged = vigilante.fusionar_estados_cluster([
            globally_newer_but_old_event, newer_event_on_lower_revision])
        entry = merged["reintentos"][quota_key]
        self.assertEqual(entry["certificate_id"], 99)
        self.assertEqual(entry["domains"], newest_domains)
        self.assertEqual(entry["reconciliacion"],
                         newer_event_on_lower_revision["reintentos"][quota_key][
                             "reconciliacion"])

    def test_second_concurrent_renewal_is_rejected_by_process_lock(self):
        self.assertTrue(vigilante._candado_renovacion.acquire(blocking=False))
        try:
            with mock.patch.object(vigilante.npm, "estado_certificado") as state:
                result = vigilante.renovar(
                    7, "example.test", "node-a", manual=True)
        finally:
            vigilante._candado_renovacion.release()
        self.assertEqual(result["code"], "RENEWAL_BUSY")
        self.assertFalse(result["hecho"])
        state.assert_not_called()

    def test_risk_notification_is_constructed_without_runtime_error(self):
        certificate = {
            "id": 7, "nombre": "expiring.example.test", "dias": 5,
            "caduca": "2026-09-01 00:00:00", "reto_dns": False,
            "proveedor_dns": None,
        }
        with mock.patch.object(vigilante.namecheap, "comprobar",
                               return_value={"estado": "desactivado", "ip": None}), \
                mock.patch.object(vigilante, "_certificados_en_riesgo",
                                  return_value=[certificate]), \
                mock.patch.object(vigilante, "_renovar_los_que_tocan", return_value=[]), \
                mock.patch.object(vigilante.avisos, "avisar",
                                  return_value={"ok": True}) as notify:
            result = vigilante.revisar(
                mando={"soy_yo": True, "activo": "node-a"})
        self.assertEqual(len(result["avisos"]), 1)
        self.assertIn("expiring.example.test", notify.call_args.args[1])
        self.assertIn("Revisa el reto ACME", notify.call_args.args[4])


class TestRenewalQuota(IsolatedData):
    def test_automatic_path_stops_at_four_but_manual_may_use_fifth_only(self):
        now = 1_000_000
        quota_key = reintentos.clave_san(["quota.example.test"])
        entry = {
            "intentos": [now - 10_000, now - 20_000, now - 30_000, now - 40_000],
            "fallos": [], "agotado": True, "siguiente": None,
            "reconciliacion": {"estado": "fallo_confirmado", "desde": now - 10_000,
                               "caducidad_anterior": "2026-10-01"},
        }
        state = {"reintentos": {quota_key: entry}}
        automatic, auto_reason = reintentos.puede_intentar(
            state, quota_key, manual=False, ahora=now)
        manual, manual_reason = reintentos.puede_intentar(
            state, quota_key, manual=True, ahora=now)
        self.assertFalse(automatic, auto_reason)
        self.assertTrue(manual, manual_reason)

        entry["intentos"].append(now - 50_000)
        sixth, sixth_reason = reintentos.puede_intentar(
            state, quota_key, manual=True, ahora=now)
        self.assertFalse(sixth)
        self.assertIn("5 intentos", sixth_reason)

    def test_manual_path_never_overrides_an_indeterminate_issuance(self):
        quota_key = reintentos.clave_san(["pending.example.test"])
        state = {"reintentos": {quota_key: {
            "intentos": [100], "fallos": [], "agotado": False,
            "siguiente": None,
            "reconciliacion": {"estado": "indeterminado", "desde": 100,
                               "caducidad_anterior": "2026-10-01"},
        }}}
        allowed, reason = reintentos.puede_intentar(
            state, quota_key, manual=True, ahora=200)
        self.assertFalse(allowed)
        self.assertIn("pendiente", reason)

    def test_successes_remain_in_the_weekly_quota_window(self):
        now = 1_000_000
        key = reintentos.clave_san(["www.example.test", "*.example.test"])
        state = {}
        for index in range(4):
            result = reintentos.registrar_intento(
                state, key, ok=True, ahora=now + index,
                id_cert=7, dominios=["*.example.test", "www.example.test"])
            self.assertFalse(result["agotado"])
        entry = state["reintentos"][key]
        self.assertEqual(len(entry["intentos"]), 4)
        self.assertEqual(entry["fallos"], [])
        allowed, reason = reintentos.puede_intentar(
            state, key, manual=False, ahora=now + 10)
        self.assertFalse(allowed, reason)
        self.assertEqual(reintentos.cuota(
            state, key, ahora=now + 10)["intentos_esta_semana"], 4)

    def test_different_certificate_ids_share_quota_for_the_same_san_set(self):
        domains_a = ["WWW.Example.Test.", "*.Example.Test"]
        domains_b = ["*.example.test", "www.example.test"]
        key_a = reintentos.clave_san(domains_a)
        key_b = reintentos.clave_san(domains_b)
        self.assertEqual(key_a, key_b)

        state = {}
        reintentos.registrar_intento(
            state, key_a, ok=True, ahora=1_000_000,
            id_cert=7, dominios=domains_a)
        reintentos.registrar_intento(
            state, key_b, ok=True, ahora=1_000_001,
            id_cert=99, dominios=domains_b)
        self.assertEqual(list(state["reintentos"]), [key_a])
        self.assertEqual(len(state["reintentos"][key_a]["intentos"]), 2)
        self.assertEqual(state["reintentos"][key_a]["certificate_id"], 99)


class TestNpmAvailability(IsolatedData):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    @staticmethod
    def _http_error(code):
        return npm_api.urllib.error.HTTPError(
            "https://node-a/api/", code, f"HTTP {code}", {}, io.BytesIO(b""))

    def test_health_and_auth_availability_accept_only_explicit_client_responses(self):
        probes = (
            ("api_responde", lambda: npm_api.api_responde("node-a", timeout=3)),
            ("autenticacion_disponible",
             lambda: npm_api.autenticacion_disponible("node-a")),
        )
        allowed = (400, 401, 403, 404, 405, 409, 422, 429)
        rejected = (418, 499, 500, 502, 503)
        for name, probe in probes:
            with self.subTest(probe=name, status=200), \
                    mock.patch.object(npm_api, "_base_del_activo",
                                      return_value="https://node-a:81"), \
                    mock.patch.object(npm_api, "_abrir",
                                      return_value=self.Response()):
                self.assertTrue(probe())
            for status in allowed:
                with self.subTest(probe=name, status=status), \
                        mock.patch.object(npm_api, "_base_del_activo",
                                          return_value="https://node-a:81"), \
                        mock.patch.object(npm_api, "_abrir",
                                          side_effect=self._http_error(status)):
                    self.assertTrue(probe())
            for status in rejected:
                with self.subTest(probe=name, status=status), \
                        mock.patch.object(npm_api, "_base_del_activo",
                                          return_value="https://node-a:81"), \
                        mock.patch.object(npm_api, "_abrir",
                                          side_effect=self._http_error(status)):
                    self.assertFalse(probe())


class TestNpmMutationAmbiguity(IsolatedData):
    @staticmethod
    def _http_error(method):
        import urllib.error
        return urllib.error.HTTPError(
            f"http://npm/api/{method}", 500, "server error", {},
            io.BytesIO(b'{"error":{"message":"late failure"}}'))

    def _client(self):
        client = npm_api.Cliente("http://npm:81")
        client._token = "already-authenticated"
        client._vence = 10**20
        return client

    def test_any_post_transport_or_http_failure_is_ambiguous(self):
        for failure in (
                self._http_error("post"),
                npm_api.urllib.error.URLError(ConnectionResetError("reset")),
                TimeoutError("timed out"),
        ):
            try:
                client = self._client()
                with self.subTest(failure=type(failure).__name__), \
                        mock.patch.object(npm_api.urllib.request, "urlopen",
                                          side_effect=failure), \
                        self.assertRaises(npm_api.ErrorNPM) as raised:
                    client._llamar("/api/mutation", metodo="POST", cuerpo={})
                self.assertTrue(raised.exception.resultado_indeterminado)
            finally:
                cerrar = getattr(failure, "close", None)
                if cerrar:
                    cerrar()

    def test_get_failure_is_never_marked_as_an_ambiguous_mutation(self):
        client = self._client()
        failure = self._http_error("get")
        try:
            with mock.patch.object(npm_api.urllib.request, "urlopen",
                                   side_effect=failure), \
                    self.assertRaises(npm_api.ErrorNPM) as raised:
                client._llamar("/api/read", metodo="GET")
        finally:
            failure.close()
        self.assertFalse(raised.exception.resultado_indeterminado)


class TestNotificationSecretIsolation(IsolatedData):
    def test_agents_receive_only_notification_contract_not_guardian_secrets(self):
        queue = self.temp / "notify" / "unread"
        agents = self.temp / "notify" / "agents"
        queue.mkdir(parents=True)
        agents.mkdir(parents=True)
        (agents / "operator.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        old_queue, old_agents = avisos.COLA, avisos.AGENTES
        avisos.COLA, avisos.AGENTES = str(queue), str(agents)
        captured = []

        def run(_command, **kwargs):
            captured.append(kwargs["env"])
            return mock.Mock(returncode=0)

        secret_environment = {
            "NPMG_SESSION_SECRET": "must-not-reach-agent",
            "NPMG_CLUSTER_TOKEN": "must-not-reach-agent-either",
            "NPMG_NPM_API_PASSWORD": "npm-password-must-not-leak",
            "NPMG_NAMECHEAP_API_KEY": "namecheap-key-must-not-leak",
        }
        try:
            with mock.patch.dict(os.environ, secret_environment, clear=False), \
                    mock.patch.object(avisos.subprocess, "run", side_effect=run):
                first = avisos.avisar(
                    "NPM certificates", "Renewed", "Certificate is active",
                    "normal", "No secrets in this operator message")
                second = avisos.avisar(
                    "NPM certificates", "Renewed again", "Certificate is active",
                    "normal", "Second message")
        finally:
            avisos.COLA, avisos.AGENTES = old_queue, old_agents

        self.assertTrue(first["interfaz_unraid"]["ok"])
        self.assertTrue(second["interfaz_unraid"]["ok"])
        self.assertEqual(len(captured), 2)
        for environment in captured:
            self.assertTrue({"EVENT", "SUBJECT", "DESCRIPTION", "IMPORTANCE",
                             "CONTENT", "HOSTNAME"}.issubset(environment))
            for key, value in secret_environment.items():
                self.assertNotIn(key, environment)
                self.assertNotIn(value, json.dumps(environment))
        files = list(queue.glob("*.notify"))
        self.assertEqual(len(files), 2)
        self.assertNotEqual(files[0].name, files[1].name)
        combined = "\n".join(path.read_text(encoding="utf-8") for path in files)
        for value in secret_environment.values():
            self.assertNotIn(value, combined)
        if os.name != "nt":
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600
                                for path in files))


if __name__ == "__main__":
    unittest.main()
