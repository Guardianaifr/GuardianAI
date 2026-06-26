# GuardianAI Production Launch Runbook

## 1) Prepare fixed secrets

1. Copy `deploy/production/.env.production.example` to `deploy/production/.env.production`.
2. Replace all `REPLACE_WITH_*` values with strong random values.
3. Set `GUARDIAN_LICENSE_KEY` for the target machine before first start.

Fast path (auto-generate + install + launch):

```powershell
.\deploy\production\setup_production.ps1 -TargetUrl http://127.0.0.1:8080
```

## 2) Install/update dependencies

```bash
pip install -r requirements.txt
```

## 3) Start production stack with fixed env

### Windows (PowerShell)

```powershell
Get-Content .\deploy\production\.env.production | ForEach-Object {
  if ($_ -match '^\s*#' -or $_ -match '^\s*$') { return }
  $k,$v = $_ -split '=',2
  [System.Environment]::SetEnvironmentVariable($k,$v,'Process')
}
.\.venv312\Scripts\python.exe guardianctl.py one-click --target-url http://127.0.0.1:8080
```

### Linux (systemd)

1. Copy `deploy/production/guardianai.service.example` to `/etc/systemd/system/guardianai.service`.
2. Update paths/user in the file.
3. Run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable guardianai
sudo systemctl restart guardianai
sudo systemctl status guardianai
```

## 4) Verify live health

```bash
python guardianctl.py status --config guardian/config/one_click_runtime.yaml
```

PowerShell auth check:

```powershell
.\deploy\production\verify_production.ps1 -Pass "<your-admin-password>"
```

## 5) Put behind HTTPS

1. Copy `deploy/production/Caddyfile.example` to your Caddy config.
2. Replace `guardian.example.com` and `guardian-admin.example.com` with real domains.
3. Point DNS A/AAAA records to your server.
4. Reload Caddy.

## 6) Customer routing

- Customer app traffic should use your HTTPS Guardian endpoint (proxy).
- Admin/security team should use your HTTPS admin endpoint (dashboard/backend).

## 7) Important notes

- The proxy now uses `waitress` by default (production-safe WSGI path).
- Threat feed is disabled by default unless `GUARDIAN_THREAT_FEED_URL` is set to a valid URL.
- Do not expose upstream model endpoint directly to the internet.
