"""Tests of static findings and preparation gates, not untrusted execution."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import decryption_finder
import run_tracer


class FinderTests(unittest.TestCase):
    def test_mask_recurrence(self):
        words, states = decryption_finder.mask_tables(61, 123)
        self.assertEqual(len(words), 256)
        self.assertEqual(words[0], 0xE49DCA7B)
        self.assertEqual(states[0], 228)
        self.assertEqual(words[0].to_bytes(4, "little"), bytes([123, 202, 157, 228]))
        for seed, word in enumerate(words):
            value, sequence = seed, []
            for _ in range(4):
                value = (61 * value + 123) % 256
                sequence.append(value)
            self.assertEqual(word.to_bytes(4, "little"), bytes(sequence))

    def test_unknown_source_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "g").write_text("print('unknown')")
            with self.assertRaises(ValueError): decryption_finder.find(root / "g", root / "out")
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(Path("output/stage1-vm-source.lua.txt").exists(), "Local snapshot required")
    def test_known_source_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            report = decryption_finder.find(Path("output/stage1-vm-source.lua.txt"), Path(temp))
            self.assertFalse(report["payload_executed"])
            self.assertFalse(report["trace_gate"]["full_source_execution_allowed"])
            self.assertEqual(len(report["anchors"]), 8)
            self.assertEqual(report["confirmed_arithmetic"]["multiplier"], 61)


class TracerPreparationTests(unittest.TestCase):
    def test_literal_byte_roundtrip(self):
        data = bytes(range(256)) + b'"\\\nend)() --'
        encoded = run_tracer.literal(data)
        self.assertEqual(encoded[0], '"')
        self.assertEqual(encoded[-1], '"')
        body = encoded[1:-1]
        self.assertEqual(len(body), len(data) * 4)
        decoded = bytes(int(body[index + 1:index + 4]) for index in range(0, len(body), 4))
        self.assertEqual(decoded, data)

    def test_prepare_does_not_execute(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(run_tracer.subprocess, "Popen") as launch:
            root = Path(temp)
            adapter = b'error("synthetic")'
            result = run_tracer.prepare(root, adapter, b"synthetic")
            launch.assert_not_called()
            self.assertFalse(result["payload_executed"])
            self.assertEqual(result["adapter_sha256"], hashlib.sha256(adapter).hexdigest())
            json.loads((root / "bundle-manifest.json").read_text())

    def test_large_adapter_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "out"
            with self.assertRaises(ValueError): run_tracer.prepare(root, b"x" * 65537, b"")
            self.assertFalse(root.exists())

    def test_container_arguments(self):
        args = run_tracer.command("docker", "sha256:" + "a" * 64, Path("output/demo"), "fixture")
        for option in ("--network=none", "--pull=never", "--read-only", "--cap-drop=ALL", "--memory=256m", "--pids-limit=32", "--user=65534:65534"):
            self.assertIn(option, args)
        self.assertNotIn("--privileged", args)
        self.assertIn("readonly", args[args.index("--mount") + 1])
        with self.assertRaises(ValueError): run_tracer.command("docker", "latest", Path("output"), "fixture")

    def test_remote_endpoint_denied(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote:2375"}), patch.object(run_tracer.shutil, "which", return_value="docker"), patch.object(run_tracer.subprocess, "run") as run:
            with self.assertRaises(ValueError): run_tracer.local_docker()
            run.assert_not_called()


if __name__ == "__main__": unittest.main()
