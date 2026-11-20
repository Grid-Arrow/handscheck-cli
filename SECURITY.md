# Security

Please report vulnerabilities in the CLI, the command policy, the installer or the sudoers file privately to
security@gridandarrow.com, not in a public issue. We'll confirm receipt within two working days.

The command policy (`worker/src/handscheck/ssh/policy.py`) is the boundary we care most about: a way to make
`hc` write, delete, execute or reach the network on the host it checks is a security bug.
