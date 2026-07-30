# certforge-connector

An open-source on-premises agent that automates certificate renewal for network devices managed by [CertForge](https://app.certgovernance.app).

## Why this exists

Network devices — SBCs, voice gateways, load balancers — live on private management VLANs that CertForge cannot reach directly. certforge-connector runs inside your network, polls CertForge for pending renewal jobs, pulls the CSR from the device, sends it to CertForge to be signed, and installs the signed certificate back on the device. No inbound firewall rules required.

```
[CertForge cloud] ←── poll every 30s ──── [certforge-connector]
                                                     │
                                          reaches private VLAN
                                                     │
                                         [AudioCodes SBC / device]
```

The connector is stateless. It holds no certificates and no CA credentials — those stay in CertForge. If the connector stops, devices simply do not renew until it resumes.

## Supported device types

| Type | Driver |
|------|--------|
| AudioCodes Mediant (VE/E/SW/HW) | `audiocodes` |

Additional drivers can be added by implementing the [`Device` interface](#adding-a-device-type).

## Prerequisites

- A CertForge account with at least one CA connector configured
- The device registered under **Network Devices** in CertForge
- A **connector token** from CertForge → Settings → API Keys → Connector Tokens (prefix `ct_`)
- The connector host must have TCP access to the device management IP on the configured port (default 443)

## Installation

### Binary (recommended)

Download the pre-built binary for your platform from the [latest release](https://github.com/CertForge-LLC/certforge-connector/releases/latest):

| Platform | File |
|----------|------|
| Linux x86-64 | `certforge-connector-linux-amd64` |
| Linux ARM64 | `certforge-connector-linux-arm64` |
| macOS x86-64 | `certforge-connector-darwin-amd64` |
| macOS Apple Silicon | `certforge-connector-darwin-arm64` |
| Windows x86-64 | `certforge-connector-windows-amd64.exe` |

```sh
# Linux example
curl -LO https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/certforge-connector-linux-amd64
chmod +x certforge-connector-linux-amd64
mv certforge-connector-linux-amd64 /usr/local/bin/certforge-connector
```

### Windows

Download `certforge-connector-windows-amd64.exe` from the [latest release](https://github.com/CertForge-LLC/certforge-connector/releases/latest) and place it wherever you want to run it from, for example `C:\certforge-connector\`.

```powershell
# PowerShell — download to C:\certforge-connector\
New-Item -ItemType Directory -Force -Path C:\certforge-connector
Invoke-WebRequest -Uri https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/certforge-connector-windows-amd64.exe `
    -OutFile C:\certforge-connector\certforge-connector.exe
```

Copy `connector.yaml.example` to `C:\certforge-connector\connector.yaml` and fill in your values.

**Run manually (for testing):**

```powershell
$env:CERTFORGE_API_KEY = "ct_..."
$env:DEVICE_PASSWORD   = "hunter2"
C:\certforge-connector\certforge-connector.exe -config C:\certforge-connector\connector.yaml
```

**Run as a Windows service using [NSSM](https://nssm.cc):**

NSSM wraps any executable as a proper Windows service with automatic restart and event log integration. Download it from [nssm.cc](https://nssm.cc/download), then from an elevated command prompt:

```cmd
nssm install CertForgeConnector "C:\certforge-connector\certforge-connector.exe"
nssm set CertForgeConnector AppParameters "-config C:\certforge-connector\connector.yaml"
nssm set CertForgeConnector AppDirectory "C:\certforge-connector"
nssm set CertForgeConnector AppEnvironmentExtra "CERTFORGE_API_KEY=ct_..." "DEVICE_PASSWORD=hunter2"
nssm set CertForgeConnector Start SERVICE_AUTO_START
nssm start CertForgeConnector
```

To update the service after downloading a new binary, stop the service, replace the `.exe`, and start it again:

```cmd
nssm stop CertForgeConnector
:: replace the .exe
nssm start CertForgeConnector
```

### Docker

```sh
docker run -d --restart unless-stopped \
  --network host \
  -v /etc/certforge-connector/connector.yaml:/etc/certforge-connector/connector.yaml:ro \
  ghcr.io/certforge/certforge-connector:latest
```

`--network host` is required so the connector can reach devices on private management VLANs.

### Docker Compose

```sh
cp connector.yaml.example connector.yaml
# edit connector.yaml, then:
docker compose up -d
```

### Build from source

Requires Go 1.21+.

```sh
git clone https://github.com/CertForge-LLC/certforge-connector.git
cd certforge-connector
go build -o certforge-connector .
```

## Configuration

Copy `connector.yaml.example` to `connector.yaml` and fill in your values. Environment variables are expanded, so secrets can be kept out of the file.

```yaml
# URL of your CertForge instance.
certforge_url: https://app.certgovernance.app

# Connector token from CertForge → Settings → API Keys → Connector Tokens.
api_key: $CERTFORGE_API_KEY

# How often to poll CertForge for pending renewal jobs (default 30s).
poll_interval: 30s

devices:
  - id: "00000000-0000-0000-0000-000000000000"  # from CertForge → Network Devices
    type: audiocodes
    host: 192.168.1.100   # management IP — must be reachable from this host
    port: 443             # default 443
    username: Admin
    password: $DEVICE_PASSWORD
    tls_context: 0        # TLS context index on the device (default 0)
    skip_verify: false    # set true only for self-signed device management certs
```

The `id` for each device is the UUID shown on the CertForge Network Devices page. The connector ignores jobs for devices not listed in its config, so you can run multiple connector instances covering different VLANs.

### Environment variables

Any value in `connector.yaml` can reference an environment variable with the standard `$VAR` or `${VAR}` syntax. The file is expanded before parsing. Useful for secrets:

```sh
# Linux / macOS
export CERTFORGE_API_KEY=ct_...
export DEVICE_PASSWORD=hunter2
certforge-connector -config /etc/certforge-connector/connector.yaml
```

```powershell
# Windows (PowerShell)
$env:CERTFORGE_API_KEY = "ct_..."
$env:DEVICE_PASSWORD   = "hunter2"
.\certforge-connector.exe -config .\connector.yaml
```

When running as a Windows service, set secrets via `nssm set CertForgeConnector AppEnvironmentExtra` (see [Windows installation](#windows)) rather than in the YAML file.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `connector.yaml` | Path to the config file |

## How it works

1. **Poll** — every `poll_interval`, the connector calls `GET /api/v1/connector/jobs` and receives any pending renewal jobs for its devices.
2. **Pull CSR** — for each job, the connector connects to the device management API and retrieves the pending Certificate Signing Request.
3. **Sign** — the CSR is posted to `POST /api/v1/connector/jobs/{id}/csr`. CertForge signs it using the CA connector configured for that device and returns the signed certificate.
4. **Install** — the connector pushes the signed certificate to the device via the device management API.
5. **Mark done** — the connector posts to `POST /api/v1/connector/jobs/{id}/done`. CertForge records the completion and updates the next expected check-in.

If any step fails, the job is marked failed in CertForge and an alert fires (if configured). The connector then moves on to the next job.

## Monitoring

CertForge tracks connector activity automatically — no extra configuration needed. Under **Settings → Integrations & Sources**, each device shows:

- **Last touch** — the last time the connector successfully contacted CertForge (success or failure)
- **Cert expiry** — the expiry date of the last issued certificate
- **Next expected** — estimated date of the next renewal attempt (cert expiry minus 30-day renewal lead)
- **Status** — green (on track), amber (renewal window approaching), red (job failed or overdue)

Alert rules for connector failures and missed check-ins can be configured under **Settings → Alerts**.

## Security

- The connector authenticates to CertForge with a scoped `ct_` connector token. These tokens can only reach the `/api/v1/connector/` endpoints — they cannot read certificates, manage CA connectors, or perform any other CertForge operations.
- Tokens are hashed (SHA-256) at rest in CertForge. The raw token is shown only at creation.
- The connector holds no CA credentials. Private keys never leave the device.
- CertForge rejects connector polls from suspended or offboarded organizations and logs the attempt as a security event visible to platform administrators.

## Adding a device type

Implement the `Device` interface in `internal/device/`:

```go
type Device interface {
    PullCSR(ctx context.Context) (csrPEM string, err error)
    InstallCert(ctx context.Context, certPEM string) error
}
```

Then register the new type in the factory in `internal/connector/config.go`:

```go
case "myvendor":
    return &myvendor.Client{...}, nil
```

Pull requests for new device drivers are welcome. See the [AudioCodes driver](internal/device/audiocodes/client.go) as a reference implementation.

## License

Apache 2.0 — see [LICENSE](LICENSE).
