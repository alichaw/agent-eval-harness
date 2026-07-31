# T3 operator readiness

No command in this procedure contacts the Windows asset.

## Sanitized privileged verification

Run from the Harness repository:

```bash
sudo .venv/bin/python scripts/verify_t3_operator_readiness.py
```

Return the JSON output. It contains no target address, credential material,
private-key path, agent contents, permit secret, or approval token.

## Protected permit secret

Generate one random secret directly into root-controlled files without printing
it. Use the same secret value for both services. Run this as an interactive
root shell (the commands print no secret):

```bash
sudo -i
set -eu
umask 077
install -d -o root -g root -m 0700 /etc/agent-eval-harness
install -d -o root -g hexstrike -m 0750 /etc/hexstrike
openssl rand -hex 32 > /run/t3-permit-secret
{ printf 'HARNESS_EXECUTION_PERMIT_SECRET='; tr -d '\n' < /run/t3-permit-secret; printf '\n'; } \
  > /etc/agent-eval-harness/t3-permit.env
{ printf 'HEXSTRIKE_EXECUTION_PERMIT_SECRET='; tr -d '\n' < /run/t3-permit-secret; printf '\n'; } \
  > /etc/hexstrike/t3-permit.env
chown root:root /etc/agent-eval-harness/t3-permit.env
chmod 0600 /etc/agent-eval-harness/t3-permit.env
chown root:hexstrike /etc/hexstrike/t3-permit.env
chmod 0640 /etc/hexstrike/t3-permit.env
shred -u /run/t3-permit-secret
exit
```

Use the equivalent secret-manager operation instead where available. Never put
the value in terminal arguments, output, shell history, source control, or run
artifacts.

Configure the Harness launcher to load the Harness file. Configure the
HexStrike service unit with:

```text
EnvironmentFile=/etc/hexstrike/t3-permit.env
```

The files must contain the same secret value. Compatibility is verified with a
synthetic loopback permit; do not compare or display the values.

## Loopback binding and restart

The existing sandbox bootstrap also rebuilds and probes unrelated targets, so
do not use it for this acceptance test. Install this dedicated service unit:

```bash
sudo install -o root -g root -m 0644 \
  /home/kali/agent-eval-harness/config/systemd/hexstrike-t3.service \
  /etc/systemd/system/hexstrike-t3.service
sudo systemctl daemon-reload
sudo systemctl enable --now hexstrike-t3
sudo .venv/bin/python scripts/verify_t3_operator_readiness.py
```

The unit fixes `HEXSTRIKE_HOST=127.0.0.1`, runs as `hexstrike`, and reads the
protected secret file. The verifier submits only deliberately invalid synthetic
permits to both loopback endpoints. It also signs a deliberately incomplete
synthetic claim with the protected Harness secret; the specific
`permit_claims_invalid` response proves that the running HexStrike verifier used
a compatible secret without consuming a nonce or reaching target, credential,
or SSH handling. For a manual invalid-signature repeat:

```bash
curl --noproxy '*' --max-time 3 \
  -X POST -H 'Content-Type: application/json' \
  -d '{"permit":"invalid-synthetic-permit"}' \
  http://127.0.0.1:8888/api/v1/t3a/executions
```

Expected: HTTP 401 with a stable permit error and no credential, SSH, or target
activity. Do not use a valid permit for this check.
