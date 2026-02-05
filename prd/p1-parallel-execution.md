# P1: Parallel Host Execution

## Status: Not Started

## Problem
V0 executes hosts sequentially. A 35-rule scan across 50 hosts takes ~50x the time of a single host. Most time is spent waiting for SSH command responses — this is I/O-bound and parallelizable.

## Solution
Use `concurrent.futures.ThreadPoolExecutor` to run hosts in parallel. Each thread gets its own `SSHSession`. Results are collected and printed after all hosts complete.

## Technical Approach

### Thread Pool
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def _check_host(hi, password, sudo, rule_list):
    """Run all checks on a single host. Returns (HostInfo, results_list)."""
    with _connect(hi, password, sudo=sudo) as ssh:
        caps = detect_capabilities(ssh)
        results = [evaluate_rule(ssh, r, caps) for r in rule_list]
    return hi, results

with ThreadPoolExecutor(max_workers=workers) as pool:
    futures = {pool.submit(_check_host, hi, password, sudo, rule_list): hi for hi in hosts}
    for future in as_completed(futures):
        hi, results = future.result()
        _print_host_results(hi, results)
```

### CLI Flag
- `--workers` / `-w`: Number of parallel SSH connections (default: 10, max: 50)

### Output Ordering
Two options:
1. **As-completed** (default): print results as each host finishes, fastest overall
2. **Ordered** (`--ordered`): buffer results, print in original host order

### Error Isolation
One host's connection failure or timeout must not affect other hosts. Each future is independent. Failed hosts are reported at the end.

### Connection Limits
SSH connections consume file descriptors and remote sshd slots. The `--workers` flag caps parallelism. Default of 10 is conservative.

## Acceptance Criteria
- [ ] `--workers 1` behaves identically to V0 sequential execution
- [ ] `--workers 10` runs 10 hosts concurrently
- [ ] One host timing out doesn't block or cancel other hosts
- [ ] One host connection failure is reported, others continue
- [ ] Output is complete (no interleaved partial lines)
- [ ] Per-host sections are atomic (all results for one host printed together)
- [ ] Summary totals are correct across all hosts
- [ ] `--ordered` flag prints hosts in input order
- [ ] Thread count doesn't exceed `--workers` value
- [ ] No shared mutable state between threads (each has own SSHSession)

## Test Plan
- Unit test: mock multiple hosts, verify all are checked
- Unit test: simulate one host failure, verify others complete
- Unit test: verify summary counts aggregate correctly
- Integration test: 3 hosts with --workers 2, verify 2 run concurrently
