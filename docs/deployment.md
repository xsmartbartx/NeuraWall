# Deployment

NeuraWall has two runtime roles, both in the same image and Python package:

- **Control plane**: `neurawall server`. API, console, inference, policy, audit.
  One instance; PostgreSQL in production.
- **Node agent**: `neurawall agent run`. Runs where traffic is: a gateway, a server, or
  every Kubernetes node. Needs a flow source and, to enforce, `CAP_NET_ADMIN` for nftables.

Requirements: Linux x86-64 or arm64; Python 3.12 (source installs); PostgreSQL 14+;
nftables 1.0+ on enforcing nodes; Zeek 5+ as the recommended flow sensor.

---

## Docker Compose

Single host, with automatic HTTPS via Caddy.

```bash
git clone https://github.com/MiejskiSurfer/NeuraWall && cd NeuraWall
cp deploy/compose/.env.example .env
# edit .env: NEURAWALL_DOMAIN, NEURAWALL_SECRET_KEY, POSTGRES_PASSWORD, NEURAWALL_ADMIN_EMAIL
docker compose up -d
docker compose exec control-plane cat /data/initial-admin-password.txt
```

Sign in at `https://$NEURAWALL_DOMAIN` with that password. You will be asked to choose a new
one, after which the bootstrap file is deleted.

To try it with synthetic traffic, create an enrollment token in **Fleet → Enroll a node**, put it
in `.env` as `NEURAWALL_DEMO_ENROLLMENT_TOKEN`, then run:

```bash
docker compose --profile demo up -d
```

**Back up** the `cpdata` volume (bundle-signing key) and PostgreSQL (`pgdata`). See the
[runbook](operations-runbook.md#backup-and-restore).

## Kubernetes (Helm)

```bash
kubectl create namespace neurawall
kubectl -n neurawall create secret generic neurawall-secrets \
  --from-literal=secretKey="$(openssl rand -base64 48)" \
  --from-literal=databaseUrl="postgresql+psycopg://neurawall:…@postgres:5432/neurawall" \
  --from-literal=anthropicApiKey="$ANTHROPIC_API_KEY"

helm install nw deploy/helm/neurawall -n neurawall \
  --set controlPlane.existingSecret=neurawall-secrets \
  --set controlPlane.publicUrl=https://neurawall.example.com \
  --set ingress.enabled=true --set ingress.host=neurawall.example.com
```

To deploy agents on every node, create a **multi-use** enrollment token (API:
`POST /api/v1/nodes/enrollment-tokens` with `{"max_uses": 100, "ttl_seconds": 86400}`), then:

```bash
kubectl -n neurawall create secret generic neurawall-enrollment --from-literal=token=nwe_…
helm upgrade nw deploy/helm/neurawall -n neurawall --reuse-values \
  --set agent.enabled=true --set agent.backend=dry-run
```

Start with `agent.backend=dry-run`. Switch to `nftables` once you are satisfied with the verdicts;
the DaemonSet then uses `hostNetwork` and `NET_ADMIN`. The agent reads Zeek logs from
`agent.hostZeekLogDir` on each node.

The control plane runs as a single replica (`Recreate` strategy): see
[architecture](architecture.md#state-and-scaling).

## systemd

Control plane on a VM:

```bash
sudo useradd --system --home /var/lib/neurawall --shell /usr/sbin/nologin neurawall
# neurawall-<version>-py3-none-any.whl from the GitHub release (includes the console)
sudo python3.12 -m venv /opt/neurawall && sudo /opt/neurawall/bin/pip install "./neurawall-1.0.0-py3-none-any.whl[postgres]"
sudo install -m 0600 -o neurawall /dev/stdin /etc/neurawall/server.env <<'EOF'
NEURAWALL_ENVIRONMENT=production
NEURAWALL_DATABASE_URL=postgresql+psycopg://neurawall:…@localhost/neurawall
NEURAWALL_AUTH__SECRET_KEY=…
NEURAWALL_PUBLIC_URL=https://neurawall.example.com
ANTHROPIC_API_KEY=…
EOF
sudo cp deploy/systemd/neurawall-server.service /etc/systemd/system/
sudo systemctl enable --now neurawall-server
```

Put a TLS reverse proxy (nginx, Caddy, HAProxy) in front of port 8080 and set
`FORWARDED_ALLOW_IPS` to the proxy's address.

Enforcement node:

```bash
sudo python3.12 -m venv /opt/neurawall && sudo /opt/neurawall/bin/pip install ./neurawall-1.0.0-py3-none-any.whl
sudo install -D -m 0644 deploy/agent.example.yaml /etc/neurawall/agent.yaml   # edit it
sudo -u neurawall /opt/neurawall/bin/neurawall agent enroll \
  --config /etc/neurawall/agent.yaml --token nwe_…
sudo cp deploy/systemd/neurawall-agent.service /etc/systemd/system/
sudo systemctl enable --now neurawall-agent
```

`enroll` prints the pinned **bundle-signing key id**. Confirm it matches **Settings → Bundle
signing key** in the console before trusting the node.

### Flow sensor: Zeek

Enable JSON logs and JA3 (in `local.zeek`):

```zeek
@load policy/tuning/json-logs.zeek
@load ja3   # zkg install ja3
```

Point the agent at the live log directory (`source: zeek`, `source_path: /opt/zeek/logs/current`).
The agent joins `conn.log` with `dns.log`, `ssl.log` and `http.log` by connection uid. It
handles rotation and never reads payloads.

Other sensors can write NeuraWall `FlowRecord` JSON lines to a file (`source: jsonl`) or POST
batches directly to `/api/v1/agent/flows` with a node API key.

## Enabling enforcement safely

1. Run nodes with `backend: dry-run` and let Tier 1 warm up (default 200 flows; watch
   **Overview**).
2. Review alerts and drafted rules for a few days, and tune or disable noisy starter rules.
3. Switch a canary node to `backend: nftables`.
4. Promote rules from alert-only to enforce one at a time. Each change rolls out 5% → 25% →
   100% with automatic rollback on a block-rate regression.

## Upgrades

Database migrations run automatically at startup (Alembic) and are forward-only within a
major version. Upgrade the control plane first, then agents. Agents are compatible with
control planes of the same major version.

```bash
docker compose pull && docker compose up -d            # Compose
helm upgrade nw deploy/helm/neurawall --reuse-values   # Kubernetes
```
