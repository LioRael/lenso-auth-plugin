#!/usr/bin/env python3
"""Independent arithmetic/redaction checks; no simulated runtime claims."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('check_profile', Path(__file__).with_name('check-profile.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class EvidenceChecks(unittest.TestCase):
    def test_nearest_rank(self):
        values = list(range(1, 101))
        self.assertEqual(checker.distribution(values), dict(n=100, min=1, max=100, p50=50, p95=95, p99=99))
        self.assertEqual(checker.distribution([7])['p99'], 7)

    def test_invalid_samples(self):
        for values in [[], [-1], [float('nan')], [float('inf')]]:
            with self.assertRaises(AssertionError):
                checker.distribution(values)

    def test_nested_credential_redaction(self):
        for value in [{'samples': [{'credential': 'secret'}]}, {'value': '-----BEGIN PRIVATE KEY-----'}, {'value': '$argon2id$v=19'}]:
            with self.assertRaises(AssertionError):
                checker.redacted(value)
        checker.redacted({'failure_counts': {'unexpected': 0}})
        checker.redacted({'d1': {'password': {'calls': 1}}, 'd1_distributions': {'oauth': {'calls': {'p50': 1}}}})


if __name__ == '__main__':
    unittest.main()
