from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "docker" / "guardian" / "panel"
sys.path.insert(0, str(PANEL))

import replica  # noqa: E402


class TestReplicaRecoveryJournal(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="npmg-replica-recovery-"))
        self.original_paths = (
            replica.RUTA_DATOS,
            replica.RUTA_LE,
            replica.RUTA_RESPALDOS,
            replica.RUTA_JOURNAL,
        )
        self.data = self.temp / "data"
        self.letsencrypt = self.temp / "letsencrypt"
        self.backups = self.temp / "backups"
        self.data.mkdir()
        self.letsencrypt.mkdir()
        replica.RUTA_DATOS = str(self.data)
        replica.RUTA_LE = str(self.letsencrypt)
        replica.RUTA_RESPALDOS = str(self.backups)
        replica.RUTA_JOURNAL = str(
            self.backups / "replica-transaction.json")

    def tearDown(self):
        (
            replica.RUTA_DATOS,
            replica.RUTA_LE,
            replica.RUTA_RESPALDOS,
            replica.RUTA_JOURNAL,
        ) = self.original_paths
        shutil.rmtree(self.temp, ignore_errors=True)

    def _partial_swap(self):
        destination = self.data / "keys.json"
        old = self.data / ".npmg-old-recovery-keys.json"
        new = self.data / ".npmg-new-recovery-keys.json"
        destination.write_text("partially-published-new", encoding="utf-8")
        old.write_text("durable-old", encoding="utf-8")
        return destination, {
            "label": "data/keys.json",
            "dest": str(destination),
            "new": str(new),
            "old": str(old),
            "had_old": True,
        }

    def _journal(self):
        return json.loads(Path(replica.RUTA_JOURNAL).read_text(encoding="utf-8"))

    def test_swap_marks_forward_recovery_before_the_first_rename(self):
        change = {
            "label": "data/keys.json",
            "dest": str(self.data / "keys.json"),
            "new": str(self.data / ".npmg-new-keys.json"),
            "old": str(self.data / ".npmg-old-keys.json"),
            "had_old": True,
        }
        events = []

        def write_journal(state, _changes, was_running=True,
                          keep_new_on_recovery=False):
            events.append(("journal", state, keep_new_on_recovery, was_running))

        def replace(source, destination):
            events.append(("rename", str(source), str(destination)))

        with mock.patch.object(
                replica, "_escribir_journal", side_effect=write_journal), \
                mock.patch.object(replica.os, "replace", side_effect=replace), \
                mock.patch.object(replica, "_fsync_directorio"):
            replica._intercambiar(
                [change], was_running=True, conservar_nuevo=lambda: False)

        self.assertEqual(events[0], ("journal", "swapping", True, True))
        first_rename = next(
            index for index, event in enumerate(events)
            if event[0] == "rename")
        self.assertLess(0, first_rename)
        self.assertEqual(events[-1], ("journal", "swapped", False, True))

    def test_failed_forward_durably_selects_rollback_before_touching_old(self):
        destination, change = self._partial_swap()
        replica._escribir_journal(
            "swapping", [change], was_running=True,
            keep_new_on_recovery=True)
        events = []
        runtime = {"running": True}
        real_write = replica._escribir_journal
        real_recover = replica._recuperar_cambios
        real_delete = replica._borrar_journal

        def ensure(running):
            events.append(("runtime", bool(running)))
            runtime["running"] = bool(running)
            return {"existe": True, "corriendo": bool(running)}

        def complete(_changes):
            events.append(("forward",))
            raise replica.ErrorReplica("forward incompleto")

        def write(state, changes, was_running=True,
                  keep_new_on_recovery=False):
            events.append(("journal", state, keep_new_on_recovery))
            return real_write(
                state, changes, was_running, keep_new_on_recovery)

        def recover(changes):
            events.append(("rollback",))
            self.assertFalse(runtime["running"])
            self.assertFalse(self._journal()["keep_new_on_recovery"])
            return real_recover(changes)

        def health():
            events.append(("health",))
            self.assertTrue(runtime["running"])
            self.assertTrue(Path(replica.RUTA_JOURNAL).is_file())
            return True

        def delete():
            events.append(("delete",))
            return real_delete()

        with mock.patch.object(replica, "_asegurar_contenedor",
                               side_effect=ensure), \
                mock.patch.object(replica, "_completar_cambios",
                                  side_effect=complete), \
                mock.patch.object(replica, "_escribir_journal",
                                  side_effect=write), \
                mock.patch.object(replica, "_recuperar_cambios",
                                  side_effect=recover), \
                mock.patch.object(replica, "_esperar_salud",
                                  side_effect=health), \
                mock.patch.object(replica, "_borrar_journal",
                                  side_effect=delete):
            result = replica.recuperar_transaccion()

        fallback = events.index(("journal", "swapped", False))
        confirmed_stopped = events.index(("runtime", False), fallback)
        rollback = events.index(("rollback",))
        health = events.index(("health",))
        deleted = events.index(("delete",))
        self.assertLess(fallback, confirmed_stopped)
        self.assertLess(confirmed_stopped, rollback)
        self.assertLess(rollback, health)
        self.assertLess(health, deleted)
        self.assertEqual(result["action"], "promoted-swap-rolled-back")
        self.assertEqual(destination.read_text(encoding="utf-8"), "durable-old")
        self.assertFalse(Path(replica.RUTA_JOURNAL).exists())

    def test_failed_forward_keeps_rollback_journal_if_restore_fails(self):
        _destination, change = self._partial_swap()
        replica._escribir_journal(
            "swapping", [change], was_running=True,
            keep_new_on_recovery=True)

        with mock.patch.object(
                replica, "_asegurar_contenedor",
                return_value={"existe": True, "corriendo": False}), \
                mock.patch.object(
                    replica, "_completar_cambios",
                    side_effect=replica.ErrorReplica("forward incompleto")), \
                mock.patch.object(
                    replica, "_recuperar_cambios",
                    side_effect=replica.ErrorReplica("rollback incompleto")), \
                mock.patch.object(replica, "_borrar_journal") as delete, \
                self.assertRaisesRegex(replica.ErrorReplica, "conserva el journal"):
            replica.recuperar_transaccion()

        self.assertFalse(self._journal()["keep_new_on_recovery"])
        delete.assert_not_called()

    def test_failed_forward_keeps_journal_if_old_state_is_not_healthy(self):
        destination, change = self._partial_swap()
        replica._escribir_journal(
            "swapping", [change], was_running=True,
            keep_new_on_recovery=True)
        runtime = {"running": True}

        def ensure(running):
            runtime["running"] = bool(running)
            return {"existe": True, "corriendo": bool(running)}

        with mock.patch.object(replica, "_asegurar_contenedor",
                               side_effect=ensure), \
                mock.patch.object(
                    replica, "_completar_cambios",
                    side_effect=replica.ErrorReplica("forward incompleto")), \
                mock.patch.object(replica, "_esperar_salud",
                                  return_value=False), \
                mock.patch.object(replica, "_borrar_journal") as delete, \
                self.assertRaisesRegex(replica.ErrorReplica, "conserva el journal"):
            replica.recuperar_transaccion()

        self.assertTrue(runtime["running"])
        self.assertEqual(destination.read_text(encoding="utf-8"), "durable-old")
        self.assertFalse(self._journal()["keep_new_on_recovery"])
        delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
