"""Verify every reviewed vendor hash offline, with bounded read-timing diagnostics."""
import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import hashlib
import heapq
import json
from pathlib import Path
import threading
import time

READ_WORKERS = 4


def bounded_results(function, values):
    """Consume in manifest order, with at most four submitted/read/hash operations."""
    values = iter(values)
    end = object()
    with ThreadPoolExecutor(max_workers=READ_WORKERS, thread_name_prefix='aether-vendor-read') as pool:
        pending = deque()
        for _ in range(READ_WORKERS):
            value = next(values, end)
            if value is not end:
                pending.append(pool.submit(function, value))
        while pending:
            yield pending.popleft().result()
            value = next(values, end)
            if value is not end:
                pending.append(pool.submit(function, value))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, help='Final build-artifact path for this run')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    started = time.perf_counter()
    lock, stopped = threading.Lock(), threading.Event()
    state = dict(operation='starting', path='', checkedFiles=0, readBytes=0, operationStarted=started)
    slowest, checked, active = [], set(), {}
    report = dict(schemaVersion=1, passed=False, scope='offline-reviewed-dependency-integrity',
                  manifestSha256={}, retryCount=0, hashChecksSkipped=0,
                  readWorkers=READ_WORKERS, maximumInFlightFiles=READ_WORKERS, peakConcurrentReads=0)

    def snapshot():
        with lock:
            value = dict(state)
            now = time.perf_counter()
            value['activeReads'] = [dict(path=p, operationSeconds=round(now - begin, 6))
                                    for p, begin in sorted(active.values())]
        value['operationSeconds'] = round(now - value.pop('operationStarted'), 6)
        value['elapsedSeconds'] = round(now - started, 6)
        return value

    def stage(operation, path):
        with lock:
            state.update(operation=operation, path=path, operationStarted=time.perf_counter())

    def heartbeat():
        # CTest retains this flushed context if its unchanged 90-second deadline kills us.
        # Only reviewed repository-relative paths are logged; no external process inspection.
        while not stopped.wait(5):
            print('Dependency progress: ' + json.dumps(snapshot(), sort_keys=True), flush=True)

    def read(path):
        begin = time.perf_counter()
        identity = threading.get_ident()
        with lock:
            active[identity] = (path, begin)
            report['peakConcurrentReads'] = max(report['peakConcurrentReads'], len(active))
        try:
            data = (root / path).read_bytes()
            seconds = time.perf_counter() - begin
            with lock:
                state['readBytes'] += len(data)
                heapq.heappush(slowest, (seconds, path, len(data)))
                if len(slowest) > 8:
                    heapq.heappop(slowest)
            return data
        finally:
            with lock:
                active.pop(identity)

    def manifest(path):
        data = read(path)
        report['manifestSha256'][path] = hashlib.sha256(data).hexdigest()
        return json.loads(data.decode('utf-8'))

    # Mark this run failed before reading sources/manifests; a later timeout retains that marker.
    if args.evidence:
        args.evidence.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    monitor = threading.Thread(target=heartbeat, name='aether-dependency-progress', daemon=True)
    monitor.start()
    try:
        report['verifierSha256'] = hashlib.sha256(read('tools/verify-dependencies.py')).hexdigest()
        patches = manifest('third_party/dynarmic-patches.json')['patches']
        by_path = {item['path']: item for item in patches}
        dependencies = []
        for name in ('dependencies.json', 'dynarmic-dependencies.json', 'angle-dependencies.json'):
            dependencies.extend(manifest('third_party/' + name)['dependencies'])
        def verify(item):
            path, expected = item['path'], item['sha256']
            if path in by_path:
                assert by_path[path]['upstreamSha256'] == expected, f'Patch base differs: {path}'
                expected = by_path[path]['patchedSha256']
            data = read(path)
            actual = hashlib.sha256(data).hexdigest()
            assert actual == expected, f'Vendor source differs from reviewed record: {path}'
            return path

        stage('read-hash-verify', '')
        items = (item for dependency in dependencies for item in dependency['files'])
        for path in bounded_results(verify, items):
            checked.add(path)
            with lock:
                state['checkedFiles'] = len(checked)
        assert set(by_path).issubset(checked), 'Untracked patch record'
        stage('complete', '')
        report.update(passed=True, dependencies=len(dependencies), files=len(checked), patches=len(by_path))
        print(f'Verified {len(dependencies)} dependencies, {len(checked)} files and '
              f'{len(by_path)} explicit Dynarmic integration patches.', flush=True)
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        stopped.set()
        monitor.join(timeout=2)
        if monitor.is_alive():
            report.update(passed=False, monitorCleanupFailed=True)
        report.update(progress=snapshot(), slowestReads=[dict(seconds=round(seconds, 6), path=path, bytes=size)
                      for seconds, path, size in sorted(slowest, reverse=True)])
        print('Dependency result: ' + json.dumps(report, sort_keys=True), flush=True)
        if args.evidence:
            args.evidence.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    assert report['passed'], report


if __name__ == '__main__':
    main()
