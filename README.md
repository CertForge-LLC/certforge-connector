# certforge-connector

An open-source on-premises agent that automates certificate renewal for network devices managed by [CertForge](https://app.certgovernance.app).

## Why this exists

Network devices — SBCs, voice gateways, load balancers — live on private management VLANs that CertForge cannot reach directly. certforge-connector runs inside your network, polls CertForge for pending renewal jobs, pulls the CSR from the device, has it signed, and installs the certificate back on the device. No inbound firewall rules required.

```
[CertForge cloud] ←── poll every 30s ──── [certforge-connector]
                                                     │
                                          reaches private VLAN
                                                     │
                                     [network device (SBC / F5 / gateway)]
```

The connector handles two signing paths:

**Cloud signing (default):** CSRs are submitted to CertForge and signed by a cloud or public CA. CertForge enforces your Domain Trust Policy before issuing.

**On-prem CA signing:** If your CA is internal and CSRs must not leave the network, the connector signs locally using your CA's private key. CertForge is still called to authorize every signing request — validating the domain against your Domain Trust Policy, enforcing key strength and wildcard rules, and recording the approval — before the connector signs. If CertForge is unreachable, the connector does not sign (fail-closed).

The connector is stateless between jobs. If it stops, devices simply do not renew until it resumes.

## Supported device types

| Type | Driver |
|------|--------|
| AudioCodes Mediant (VE/E/SW/HW) | `audiocodes` |
| F5 BIG-IP (iControl REST, TMOS 11.6+) | `f5` |

Additional drivers can be added by implementing the [`Device` interface](#adding-a-device-type).

On startup the connector calls `POST /api/v1/connector/capabilities` to register its list of supported driver types with CertForge. CertForge uses this list to populate the **Device Type** dropdown on the Network Devices registration form — operators pick from whatever types the running connector reports rather than typing a value by hand. No CertForge update is required to support a new driver type.

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

Reference `$CERTFORGE_API_KEY` in `certforge-connector.yaml` rather than pasting the token directly into the file.

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

# Optional: download the example config to use as a starting point
curl -LO https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/certforge-connector.yaml.example
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
Invoke-WebRequest -Uri https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/certforge-connector.yaml.example `
    -OutFile C:\certforge-connector\certforge-connector.yaml.example
```

Or use `curl.exe` (built into Windows 10/11), which handles TLS automatically:

```cmd
mkdir C:\certforge-connector
curl.exe -L -o C:\certforge-connector\certforge-connector.exe ^
  https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/certforge-connector-windows-amd64.exe
curl.exe -L -o C:\certforge-connector\certforge-connector.yaml.example ^
  https://github.com/CertForge-LLC/certforge-connector/releases/latest/download/certforge-connector.yaml.example
```

> **Administrator privileges** are not required to download these files. You do need an elevated prompt to install it as a Windows service (the NSSM steps below).

Copy `certforge-connector.yaml.example` to `certforge-connector.yaml` and fill in your values:

```cmd
copy C:\certforge-connector\certforge-connector.yaml.example C:\certforge-connector\certforge-connector.yaml
```

**Run manually (for testing):**

```powershell
$env:CERTFORGE_API_KEY = "ct_..."
C:\certforge-connector\certforge-connector.exe -config C:\certforge-connector\certforge-connector.yaml
```

**Run as a Windows service using [NSSM](https://nssm.cc):**

NSSM wraps any executable as a proper Windows service with automatic restart and event log integration. Download it from [nssm.cc](https://nssm.cc/download), then from an elevated command prompt:

```cmd
nssm install CertForgeConnector "C:\certforge-connector\certforge-connector.exe"
nssm set CertForgeConnector AppParameters "-config C:\certforge-connector\certforge-connector.yaml"
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
  -v /etc/certforge-connector/certforge-connector.yaml:/etc/certforge-connector/certforge-connector.yaml:ro \
  ghcr.io/certforge-llc/certforge-connector:latest
```

`--network host` is required so the connector can reach devices on private management VLANs.

### Docker Compose

```sh
cp certforge-connector.yaml.example certforge-connector.yaml
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

Copy `certforge-connector.yaml.example` to `certforge-connector.yaml` and fill in your values.

```yaml
# URL of your CertForge instance.
certforge_url: https://app.certgovernance.app

# Connector token from CertForge → Settings → API Keys → Connector Tokens.
# Always load from an environment variable — never paste the token directly here.
api_key: $CERTFORGE_API_KEY

# How often to poll CertForge for pending jobs (default 30s).
poll_interval: 30s
```

Device registration, connection details, and credentials are all managed in CertForge under **Network Devices** — there is no device list in the connector config. The connector receives everything it needs with each renewal job.

> **Credential override (advanced):** If you need to keep credentials local rather than storing them in CertForge — for example, injecting passwords from a secrets manager via environment variables — add a `devices:` block. List one entry per device with the CertForge device UUID, username, and password. All other device details (host, port, type, TLS context) still come from CertForge automatically.
>
> ```yaml
> devices:
>   - id: "00000000-0000-0000-0000-000000000000"  # UUID from CertForge → Network Devices
>     username: admin
>     password: $SBC1_PASSWORD
>   - id: "11111111-1111-1111-1111-111111111111"
>     username: admin
>     password: $SBC2_PASSWORD
>   - id: "22222222-2222-2222-2222-222222222222"
>     username: readonly
>     password: $F5_PASSWORD
> ```
>
> Most deployments do not need this — store credentials in CertForge and let the connector receive them with each job.

### Private CA — local signing

If your signing CA is on-prem and you do not want CSRs leaving the network, add a `private_ca` block. The connector signs device CSRs locally and notifies CertForge for audit purposes:

```yaml
private_ca:
  cert: /etc/certforge-connector/ca.crt   # PEM CA certificate
  key:  /etc/certforge-connector/ca.key   # PEM CA private key (RSA or ECDSA)
  validity_days: 365
```

### Private CA — inventory sync

To push the full inventory of certs your CA has issued into CertForge (so they appear in Discovery as tracked), first create a **CA connector** record in CertForge → Settings → CA Connectors → Add → "Private / Internal CA (On-Prem Agent)". Then add `ca_connector_id` and an inventory source to `private_ca`:

**File-based CAs** (OpenSSL `openssl ca`, Easy-RSA, cfssl — anything that writes PEM files to a directory):

```yaml
private_ca:
  cert: /etc/certforge-connector/ca.crt
  key:  /etc/certforge-connector/ca.key
  ca_connector_id: 00000000-0000-0000-0000-000000000000  # from CertForge UI
  issued_certs_dir: /etc/pki/CA/newcerts  # OpenSSL default; Easy-RSA: pki/issued/
  crl_file: /etc/pki/CA/crl.pem          # optional — revoked certs excluded from push
```

**HashiCorp Vault PKI** (revocation read inline — no CRL file needed):

```yaml
private_ca:
  cert: /etc/certforge-connector/ca.crt
  key:  /etc/certforge-connector/ca.key
  ca_connector_id: 00000000-0000-0000-0000-000000000000
  vault_pki:
    addr: https://vault.example.com
    token: $VAULT_TOKEN   # or set the VAULT_TOKEN environment variable
    mount: pki            # PKI secrets engine mount path (default: pki)
```

The connector syncs inventory on startup and every 6 hours. Scope (which domains, EKU, date range to include) is configured in CertForge on the CA connector record and fetched by the agent at each sync.

### Environment variables

Only one secret is typically needed:

```sh
# Linux / macOS
export CERTFORGE_API_KEY=ct_...
certforge-connector -config /etc/certforge-connector/certforge-connector.yaml
```

```powershell
# Windows (PowerShell)
$env:CERTFORGE_API_KEY = "ct_..."
.\certforge-connector.exe -config .\certforge-connector.yaml
```

When running as a Windows service, set secrets via `nssm set CertForgeConnector AppEnvironmentExtra` rather than in the YAML file.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `certforge-connector.yaml` | Path to the config file |

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

### Private CA inventory sync

On startup and every 6 hours, when `ca_connector_id` and an inventory source (`issued_certs_dir` or `vault_pki`) are configured, the connector:

1. Fetches the sync scope from CertForge (domains, EKU, date range, include-expired flag)
2. Reads the issued cert inventory — either walking the PEM file directory or calling the Vault PKI list API
3. Applies scope filters and excludes revoked certs (from the CRL file or Vault revocation_time)
4. Pushes the filtered batch to CertForge via `POST /api/v1/connector/ca-connectors/{id}/inventory`

Pushed certs land in Discovery with `governance_status=tracked` — they are immediately under CertForge management, not in the unreviewed queue.

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

**1. Implement the `Device` interface** in `internal/device/`:

```go
type Device interface {
    PullCSR(ctx context.Context) (csrPEM string, err error)
    InstallCert(ctx context.Context, certPEM string) error
}
```

See the [AudioCodes driver](internal/device/audiocodes/client.go) as a reference implementation.

**2. Register it in the factory** in `internal/connector/config.go` (`NewDevice`):

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

**3. Add it to `SupportedDeviceTypes()`** in the same file:

```go
func SupportedDeviceTypes() []string {
    return []string{"audiocodes", "myvendor"}
}
```

This list is posted to CertForge on startup. CertForge shows it as a dropdown on the **Network Devices** registration form — once a connector with your new driver connects, `myvendor` appears as a selectable option automatically. No CertForge update is required.

Pull requests for new device drivers are welcome.

## License

Apache 2.0 — see [LICENSE](LICENSE).
