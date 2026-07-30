# certforge-connector

An open-source on-premises agent that automates certificate renewal for network devices managed by [CertForge](https://cloak.certgovernance.app).

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

Additional drivers can be added by implementing the [`Device` interface](#adding-a-device-type). The type name you register in the factory is what you enter in CertForge's device registration form — CertForge does not need to know about your driver; it just passes the type string back to the connector.

## Prerequisites

- A CertForge account with at least one CA connector configured
- The device registered under **Network Devices** in CertForge (credentials are stored there, encrypted)
- A connector token (created below)
- The connector host must have TCP access to the device management IP on the configured port (default 443)

## Creating a connector token

The connector authenticates to CertForge using a scoped token. These are separate from general API keys and are restricted to the connector endpoints only.

1. Sign in to CertForge and go to **Settings → Integrations & Sources**
2. Scroll to **Connector Tokens** and click **New Connector Token**
3. Give it a descriptive name (e.g. `office-connector`) and click **Create**
4. Copy the token — it starts with `ct_` and is shown **once only**

Set it as an environment variable on the host running the connector:

```sh
# Linux / macOS
export CERTFORGE_API_KEY=ct_...
```

```powershell
# Windows (PowerShell)
$env:CERTFORGE_API_KEY = "ct_..."
```

Reference `$CERTFORGE_API_KEY` in `connector.yaml` rather than pasting the token directly into the file.

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
# Force TLS 1.2 first (required; older PowerShell defaults to TLS 1.0 which GitHub rejects)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path C:\certforge-connector
Invoke-WebRequest -Uri https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/certforge-connector-windows-amd64.exe `
    -OutFile C:\certforge-connector\certforge-connector.exe
Invoke-WebRequest -Uri https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/connector.yaml.example `
    -OutFile C:\certforge-connector\connector.yaml.example
```

Or use `curl.exe` (built into Windows 10/11), which handles TLS automatically:

```cmd
mkdir C:\certforge-connector
curl.exe -L -o C:\certforge-connector\certforge-connector.exe ^
  https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/certforge-connector-windows-amd64.exe
curl.exe -L -o C:\certforge-connector\connector.yaml.example ^
  https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/connector.yaml.example
```

> **Administrator privileges** are not required to download these files. You do need an elevated prompt to install it as a Windows service (the NSSM steps below).

Copy `connector.yaml.example` to `connector.yaml` and fill in your values:

```cmd
copy C:\certforge-connector\connector.yaml.example C:\certforge-connector\connector.yaml
```

**Run manually (for testing):**

```powershell
$env:CERTFORGE_API_KEY = "ct_..."
C:\certforge-connector\certforge-connector.exe -config C:\certforge-connector\connector.yaml
```

**Run as a Windows service using [NSSM](https://nssm.cc):**

NSSM wraps any executable as a proper Windows service with automatic restart and event log integration. Download it from [nssm.cc](https://nssm.cc/download), then from an elevated command prompt:

```cmd
nssm install CertForgeConnector "C:\certforge-connector\certforge-connector.exe"
nssm set CertForgeConnector AppParameters "-config C:\certforge-connector\connector.yaml"
nssm set CertForgeConnector AppDirectory "C:\certforge-connector"
nssm set CertForgeConnector AppEnvironmentExtra "CERTFORGE_API_KEY=ct_..."
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
  -e CERTFORGE_API_KEY=ct_... \
  -v /etc/certforge-connector/connector.yaml:/etc/certforge-connector/connector.yaml:ro \
  ghcr.io/certforge-llc/certforge-connector:latest
```

`--network host` is required so the connector can reach devices on private management VLANs.

### Docker Compose

```sh
cp connector.yaml.example connector.yaml
# Set CERTFORGE_API_KEY in your environment or a .env file, then:
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

Copy `connector.yaml.example` to `connector.yaml` and fill in your values.

```yaml
# URL of your CertForge instance.
certforge_url: https://cloak.certgovernance.app

# Connector token from CertForge → Settings → API Keys → Connector Tokens.
# Always load from an environment variable — never paste the token directly here.
api_key: $CERTFORGE_API_KEY

# How often to poll CertForge for pending jobs (default 30s).
poll_interval: 30s

devices:
  - id: "00000000-0000-0000-0000-000000000000"  # from CertForge → Network Devices
    type: audiocodes
    host: 192.168.1.100   # management IP — must be reachable from this host
    port: 443             # default 443
    tls_context: 0        # TLS context index on the device (default 0)
    skip_verify: false    # set true only for self-signed device management certs
```

**Device credentials are not stored here.** Username and password are entered in CertForge under **Network Devices → Register Device** and stored encrypted (AES-256-GCM) in CertForge. The connector receives them automatically with each renewal job. If you prefer to keep credentials local, you can still set them in `connector.yaml` as a fallback:

```yaml
# Optional — only needed if you are not storing credentials in CertForge
    username: Admin
    password: $DEVICE_PASSWORD
```

The `id` for each device is the UUID shown on the CertForge Network Devices page. The connector ignores jobs for devices not listed in its config, so you can run multiple connector instances covering different VLANs.

### Environment variables

Only one secret is typically needed:

```sh
# Linux / macOS
export CERTFORGE_API_KEY=ct_...
certforge-connector -config /etc/certforge-connector/connector.yaml
```

```powershell
# Windows (PowerShell)
$env:CERTFORGE_API_KEY = "ct_..."
.\certforge-connector.exe -config .\connector.yaml
```

When running as a Windows service, set secrets via `nssm set CertForgeConnector AppEnvironmentExtra` rather than in the YAML file.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `connector.yaml` | Path to the config file |

## How it works

### Certificate renewal

1. **Poll** — every `poll_interval`, the connector calls `GET /api/v1/connector/jobs` and receives any pending jobs for its devices. Jobs include the device connection details and decrypted credentials from CertForge.
2. **Pull CSR** — for each renewal job, the connector authenticates to the device management API (using credentials from CertForge) and retrieves the pending Certificate Signing Request.
3. **Sign** — the CSR is posted to `POST /api/v1/connector/jobs/{id}/csr`. CertForge signs it using the CA configured for that device and returns the signed certificate.
4. **Install** — the connector pushes the signed certificate to the device.
5. **Mark done** — the connector posts to `POST /api/v1/connector/jobs/{id}/done`. CertForge records completion and schedules the next renewal window.

### Cert discovery (baseline visibility)

On startup and every 6 hours, the connector TLS-dials each configured device on its management port and reads the leaf certificate from the handshake — without needing device credentials. It reports the certificate's expiry date, Common Name, and DNS SANs back to CertForge.

CertForge uses this to:
- Populate **cert expiry** and **renewal lead** on the Network Devices page before any renewal job has run
- Match the cert's CN/SANs against your Domain Trust Policies (DTPs) to identify which policy governs each device

### Cert query (on-demand)

From the Network Devices page, clicking **Query Cert** on a device creates a `pending_query` job. The connector picks it up on its next poll, performs the same TLS read as the background discovery, and reports the result immediately. The job appears in the Jobs table until it completes.

If any step fails, the job is marked failed in CertForge and an alert fires (if configured).

## Monitoring

CertForge tracks connector activity automatically. Under **Network Devices**, each device shows:

- **Cert CN** — the Common Name from the device's current certificate
- **DTP** — the Domain Trust Policy that governs this certificate (matched from the CN)
- **Expires** — the certificate expiry date and days remaining
- **Renewal in** — days until the renewal window opens (expiry minus 30-day lead)
- **Status** — green (on track), amber (renewal window approaching), red (job failed or overdue)

Alert rules for connector failures and missed check-ins can be configured under **Settings → Alerts**.

## Security

- The connector authenticates to CertForge with a scoped `ct_` connector token. These tokens can only reach the `/api/v1/connector/` endpoints — they cannot read certificates, manage CA connectors, or perform any other CertForge operations.
- Tokens are hashed (SHA-256) at rest in CertForge. The raw token is shown only at creation.
- **Device credentials are not stored on the connector host.** They are entered in the CertForge UI, stored AES-256-GCM encrypted in the CertForge database, and delivered to the connector only at job execution time — in memory, never written to disk.
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
    return &myvendor.Client{
        Host:       d.Host,
        Port:       d.Port,
        Username:   d.Username,  // delivered from CertForge at job time
        Password:   d.Password,
        TLSContext: d.TLSContext,
        SkipVerify: d.SkipVerify,
    }, nil
```

The type string (e.g. `myvendor`) is what operators enter in CertForge's **Device Type** field when registering a device. CertForge stores it as an opaque string and passes it back to the connector — no CertForge-side changes are needed to support a new driver.

Pull requests for new device drivers are welcome. See the [AudioCodes driver](internal/device/audiocodes/client.go) as a reference implementation.

## License

Apache 2.0 — see [LICENSE](LICENSE).
