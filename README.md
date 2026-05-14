# Smartbox Sentinel PoC, real-connectors-only build

A hackathon-ready security/infrastructure dashboard with an Apple-ish dark cockpit UI, live telemetry cards, event correlation, connector setup, and no simulated telemetry.

## Run locally

```powershell
python sentinel.py
```

The app opens in real-connector-only mode. If no connector is enabled, the dashboard shows zeros and a “Waiting for live connector data” event.

## Build a Windows EXE locally

On a Windows build machine:

```powershell
cd smartbox_sentinel_poc
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install pyinstaller
pyinstaller --onefile --windowed --name SmartboxSentinel sentinel.py
```

Your executable appears here:

```text
dist\SmartboxSentinel.exe
```

## Build a Windows EXE with GitHub Actions

Yes, you can do this via Git.

1. Create a new private GitHub repo.
2. Upload or push this folder to the repo.
3. Go to **Actions**.
4. Run the workflow named **Build Windows EXE**, or just push to `main`.
5. Download the artifact named **SmartboxSentinel-Windows**.
6. Inside it, open `SmartboxSentinel.exe`.

## Connector setup

Open **Setup connectors** in the app and enable only the systems you want.

### Microsoft Graph / Intune / Defender alerts

Create an Entra ID app registration and grant application permissions such as:

- `DeviceManagementManagedDevices.Read.All`
- `SecurityAlert.Read.All`

Enter Tenant ID, Client ID, and Client Secret in the Microsoft tab.

### UniFi

Enter the official UniFi API base URL and API key.

### Datto RMM

Enter your Datto RMM API URL and bearer token.

### RocketCyber

Enter the RocketCyber API hostname and API key or bearer token.

## Security posture

- Read-only connector design.
- No simulated operational telemetry.
- Secrets are stored with Windows DPAPI when running on Windows.
- Each connector degrades independently instead of killing the dashboard.

## Suggested hackathon demo line

“This is a read-only live correlation cockpit. It normalizes Microsoft compliance, security alerts, RMM/EDR state, and network health into a single operational view. No fake telemetry in this build: if a connector is not live, it says so.”
