#!/usr/bin/env python3
"""Validate D01 receipts; incomplete evidence never passes the default gate."""
import argparse
import gzip
import json
import math
from pathlib import Path

SCENARIOS = {
    'cold_ready_1', 'cold_ready_7', 'warm_ready_1', 'warm_ready_7',
    'password_valid', 'password_invalid', 'password_absent', 'api_issue', 'api_verify',
    'oidc_activation_probe', 'storage_failure', 'storage_recovery',
    'abandonment', 'abandonment_recovery',
}
EXPECTED_FAILURES = {'password_invalid', 'password_absent', 'storage_failure', 'abandonment'}
FORBIDDEN_KEYS = {'password', 'credential', 'privateKey', 'providerSigning', 'signing', 'pepper', 'oauth', 'otp', 'proof'}


def distribution(values):
    assert values and all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in values)
    values = sorted(values)
    return dict(n=len(values), min=values[0], max=values[-1], **{
        name: values[math.ceil(p * len(values)) - 1]
        for name, p in [('p50', .5), ('p95', .95), ('p99', .99)]
    })


def redacted(value, parent=None):
    if isinstance(value, dict):
        # D1 observations are keyed by public owner names, including the
        # `password` and `oauth` owners. Those names identify counters rather
        # than credential-shaped fields; every other object stays denylisted.
        if parent not in {'d1', 'd1_distributions'}:
            assert not FORBIDDEN_KEYS.intersection(value), 'Credential-shaped field in evidence'
        for key, child in value.items():
            redacted(child, key)
    elif isinstance(value, list):
        for child in value:
            redacted(child, parent)
    elif isinstance(value, str):
        assert 'PRIVATE KEY-----' not in value and '$argon2id$' not in value


def validate(document, allow_incomplete=False):
    redacted(document)
    assert document['schema_version'] == 1 and document['task'] == 'D01'
    assert document['status'] in ('passed', 'failed', 'blocked')
    assert document['cleanup'] == dict(resources_removed=True, processes_disposed=True)
    identities = document['identities']
    assert len(identities['git_head']) == 40
    for artifact in identities['artifacts'].values():
        assert len(artifact['sha256']) == 64 and artifact['bytes'] > 0
    assert identities['tools']['workerd'] == '1.20260701.1'
    assert identities['tools']['miniflare'] == '4.20260701.0'
    assert identities['tools']['@lenso/workers-runtime'] == '0.1.2'
    assert identities['source_files_sha256']
    assert document['environment']['node'] == 'v26.8.2'
    assert document['configuration']['samples'] == 30
    assert document['configuration']['cold_samples'] == 5
    assert document['configuration']['concurrency'] == 1
    assert document['configuration']['argon2'] == dict(
        algorithm='argon2id', version=19, memory_kib=19456, iterations=2, lanes=1, output_bytes=32)
    assert set(document['scenarios']) == SCENARIOS
    for name, row in document['scenarios'].items():
        samples = row['samples']
        assert row['sample_count'] == len(samples)
        assert row['wall_ms'] == (distribution([s['wall_ms'] for s in samples]) if samples else None)
        assert row['failure_counts']['unexpected'] == sum(not s['passed'] for s in samples)
        assert row['failure_counts']['runtime'] == sum(s['http_status'] != 200 for s in samples)
        assert row['generation_changes'] == sum(s['generation_after'] != s['generation_before'] for s in samples)
        for sample in samples:
            assert sample['memory']
            assert all(m['bytes'] > 0 and m['bytes'] % 65536 == 0 for m in sample['memory'])
            for counter in sample['d1'].values():
                assert counter['calls'] >= counter['failures'] >= 0
                assert counter['statements'] >= counter['calls']
                assert all(v is None or (type(v) is int and v >= 0) for v in counter.values())
        maximum = max(m['bytes'] for s in samples for m in s['memory']) if samples else None
        assert row['wasm_observed_max_bytes'] == maximum
        for owner, metrics in row['d1_distributions'].items():
            observed = [s['d1'][owner] for s in samples if owner in s['d1']]
            for key, summary in metrics.items():
                values = [c[key] for c in observed]
                assert summary == (None if None in values else distribution(values))
        if document['status'] == 'passed':
            n = 5 if name.startswith('cold_') else 30
            assert len(samples) == n and row['failure_counts']['unexpected'] == 0
            if name in {'password_invalid', 'password_absent'}:
                assert row['failure_counts']['domain'] == n
            elif name in {'storage_failure', 'abandonment'}:
                assert row['failure_counts']['runtime'] == n
                assert row['generation_changes'] == n
            else:
                assert row['failure_counts'] == dict(unexpected=0, domain=0, runtime=0)
            if name.startswith('cold_'):
                assert len({s['process'] for s in samples}) == n
            owner_count = 1 if name.endswith('_1') else 7
            assert all(len(s['d1']) == owner_count for s in samples)
    if document['status'] != 'passed':
        assert document['unresolved']['stage']
        assert allow_incomplete, 'D01 is incomplete; runtime acceptance has not passed'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--allow-incomplete', action='store_true', help='Audit incomplete receipt structure only; not an acceptance pass')
    args = parser.parse_args()
    raw = gzip.decompress(args.evidence.read_bytes()).decode() if args.evidence.suffix == '.gz' else args.evidence.read_text()
    validate(json.loads(raw), args.allow_incomplete)
    print('D01 receipt structure valid' if args.allow_incomplete else 'D01 matrix passed')
