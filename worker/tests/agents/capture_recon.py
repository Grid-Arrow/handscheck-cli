"""Add recon's commands (M7c) to the lab captures without re-recording the rest (lab state drifts):

docker compose run --rm worker python -m tests.agents.capture_recon lab-wp1 lab-wp2
"""

from __future__ import annotations

import asyncio
import gzip
import json
import sys

from handscheck.agents._framework.check import CheckContext
from handscheck.roles.recon.inventory import CHECK as RECON
from handscheck.sites.discovery import DISCOVERY
from handscheck.ssh.probe import SUDO_PROBE
from handscheck.ssh.runner import SSHRunner, SSHTarget
from tests.agents.capture import LAB_HOSTS
from tests.agents.replay import CAPTURED, RecordingRunner
from tests.lab.test_lab_hosts import _lab_key


async def capture(host: str) -> None:
    if host not in LAB_HOSTS:
        raise SystemExit(f"refusing to capture from {host!r}: lab hosts only")
    target = SSHTarget(name=host, address=host, user="handscheck", key_path=_lab_key())
    async with SSHRunner(target) as ssh:
        recorder = RecordingRunner(ssh)
        ctx = CheckContext(runner=recorder, host=host, address=host)
        ctx.sudo_ok = (await ctx.run(SUDO_PROBE, sudo=True)).ok
        ctx.sites = DISCOVERY.parse(await DISCOVERY.collect(ctx, {}), {}).sites
        await RECON.collect(ctx, {})
    path = CAPTURED / f"{host}.json.gz"
    data = json.loads(gzip.decompress(path.read_bytes()))
    have = {r["command"] for r in data["commands"]}
    new = {r["command"]: r for r in recorder.records if r["command"] not in have}
    data["commands"].extend(new.values())
    text = json.dumps(data, indent=1, sort_keys=True) + "\n"
    path.write_bytes(gzip.compress(text.encode(), mtime=0))
    print(f"{host}: added {len(new)} commands")


if __name__ == "__main__":
    for name in sys.argv[1:]:
        asyncio.run(capture(name))
