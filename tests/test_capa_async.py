"""Regression tests for P1-6: run_capa_analysis becomes a non-blocking background job with
get_capa_status polling, instead of silently continuing to run past a client-side timeout.

No real capa/Rizin analysis is executed here - `_run_capa_analysis_job` is monkeypatched to a
fast fake so the test only exercises the job bookkeeping (start/dedupe/poll/error) added by this
change, not capa itself (already covered indirectly by real usage).
"""

import json
import os
import tempfile
import time
import unittest

import rizin_mcp.server as server_mod
from rizin_mcp.server import run_capa_analysis, get_capa_status


class TestCapaAsyncJobs(unittest.TestCase):
    def setUp(self):
        self._orig_rz = server_mod.CURRENT_RZ
        self._orig_path = server_mod.CURRENT_FILE_PATH
        self._orig_job_fn = server_mod._run_capa_analysis_job
        self._orig_jobs = dict(server_mod.CAPA_JOBS)
        server_mod.CAPA_JOBS.clear()

        self._tmp = tempfile.NamedTemporaryFile(delete=False)
        self._tmp.write(b"fake binary contents for hashing")
        self._tmp.close()

        server_mod.CURRENT_RZ = object()  # only needs to be non-None
        server_mod.CURRENT_FILE_PATH = self._tmp.name

        self._cache_file = server_mod.get_cache_file_path(self._tmp.name)

    def tearDown(self):
        server_mod.CURRENT_RZ = self._orig_rz
        server_mod.CURRENT_FILE_PATH = self._orig_path
        server_mod._run_capa_analysis_job = self._orig_job_fn
        server_mod.CAPA_JOBS.clear()
        server_mod.CAPA_JOBS.update(self._orig_jobs)
        os.unlink(self._tmp.name)
        if os.path.exists(self._cache_file):
            os.unlink(self._cache_file)

    def test_no_file_open_returns_error(self):
        server_mod.CURRENT_RZ = None
        result = json.loads(run_capa_analysis())
        self.assertEqual(result["status"], "error")

    def test_cache_hit_returns_synchronously_without_starting_a_job(self):
        cached_payload = {
            "status": "success",
            "cached": False,
            "mode": "test",
            "file_path": self._tmp.name,
            "total_capabilities": 1,
            "capabilities": [{"rule": "existing-cached-rule"}]
        }
        with open(self._cache_file, "w", encoding="utf-8") as f:
            json.dump(cached_payload, f)

        result = json.loads(run_capa_analysis())
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["cached"])
        self.assertEqual(result["capabilities"][0]["rule"], "existing-cached-rule")
        self.assertEqual(len(server_mod.CAPA_JOBS), 0)

    def test_no_cache_starts_background_job_and_returns_immediately(self):
        def slow_fake_job(rz, target_path, cache_file, cache_name):
            time.sleep(0.3)
            return {
                "status": "success",
                "cached": False,
                "mode": "test",
                "file_path": target_path,
                "total_capabilities": 1,
                "capabilities": [{"rule": "behavioral-test-rule"}]
            }

        server_mod._run_capa_analysis_job = slow_fake_job

        started = json.loads(run_capa_analysis())
        self.assertEqual(started["status"], "started")
        job_id = started["job_id"]
        self.assertTrue(job_id)

        # Job hasn't had time to finish yet - status should report "running", never silently
        # nothing (this is exactly the case the improvement plan flags: a client-side timeout
        # must not leave the caller with no way to tell "failed" from "still going").
        status = json.loads(get_capa_status(job_id))
        self.assertEqual(status["status"], "running")

        # calling run_capa_analysis again while the job is still in flight should NOT start a
        # second job for the same file - it should report the existing one.
        second_call = json.loads(run_capa_analysis())
        self.assertEqual(second_call["status"], "started")
        self.assertEqual(second_call["job_id"], job_id)

        time.sleep(0.5)
        final_status = json.loads(get_capa_status(job_id))
        self.assertEqual(final_status["status"], "success")
        self.assertEqual(final_status["capabilities"][0]["rule"], "behavioral-test-rule")
        self.assertEqual(final_status["job_id"], job_id)

    def test_job_failure_is_reported_via_get_capa_status(self):
        def failing_job(rz, target_path, cache_file, cache_name):
            raise RuntimeError("boom: capa blew up")

        server_mod._run_capa_analysis_job = failing_job

        started = json.loads(run_capa_analysis())
        job_id = started["job_id"]

        deadline = time.time() + 5
        status = {"status": "running"}
        while status["status"] == "running" and time.time() < deadline:
            time.sleep(0.05)
            status = json.loads(get_capa_status(job_id))

        self.assertEqual(status["status"], "error")
        self.assertIn("boom", status["message"])

    def test_unknown_job_id_returns_error(self):
        result = json.loads(get_capa_status("does-not-exist"))
        self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main()
