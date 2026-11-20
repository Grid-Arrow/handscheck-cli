"""Capture command output from the lab hosts for the offline tests (synthetic lab data only, never a
real host).

    docker compose up -d lab-db lab-wp1 lab-wp2 lab-locked
    docker compose run --rm worker python -m tests.agents.capture lab-wp1 lab-wp2 lab-locked

Writes tests/agents/captured/<host>.json.gz (gzip: checksum and md5 lists are large). Re-capture when a
check's commands, a fixture or the lab images change.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import sys

from handscheck.agents._framework.registry import get_agents
from handscheck.agents._framework.services import HttpxProber, Services, WordPressOrgChecksums
from handscheck.pipeline.run import run_host
from handscheck.ssh.runner import SSHRunner, SSHTarget
from tests.agents.replay import CAPTURED, RecordingChecksums, RecordingHttp, RecordingRunner
from tests.lab.test_lab_hosts import _lab_key

LAB_HOSTS = {"lab-wp1", "lab-wp2", "lab-locked"}


async def capture(host: str) -> None:
    if host not in LAB_HOSTS:
        raise SystemExit(
            f"refusing to capture from {host!r}: lab hosts only ({', '.join(sorted(LAB_HOSTS))})"
        )
    target = SSHTarget(name=host, address=host, user="handscheck", key_path=_lab_key())
    http, checksums = HttpxProber(), WordPressOrgChecksums()
    rec_http, rec_sums = RecordingHttp(http), RecordingChecksums(checksums)
    async with SSHRunner(target) as ssh:
        recorder = RecordingRunner(ssh)
        services = Services(http=rec_http, checksums=rec_sums)
        await run_host(recorder, host, get_agents(), services=services)
        fingerprint = ssh.host_key_fingerprint
    await http.close()
    await checksums.close()
    # Each command once (the pipeline memoizes, but keep the file stable if it ever repeats one).
    unique = {r["command"]: r for r in recorder.records}
    data = {
        "host": host,
        "host_key_fingerprint": fingerprint,
        "commands": list(unique.values()),
        "http": rec_http.responses,
        "checksums": rec_sums.data,
    }
    path = CAPTURED / f"{host}.json.gz"
    text = json.dumps(data, indent=1, sort_keys=True) + "\n"
    path.write_bytes(gzip.compress(text.encode(), mtime=0))
    print(f"wrote {path} ({len(unique)} commands)")


if __name__ == "__main__":
    for name in sys.argv[1:]:
        asyncio.run(capture(name))
