# Remote VPN Setup Guide

## Your Configuration

- **DuckDNS Domain**: `myfirstvpnnust.duckdns.org`
- **VPN Port**: `5555`
- **SOCKS5 Proxy**: `127.0.0.1:1080`

---

## Setup Steps

### On the Server Machine (Your Computer)

#### 1. Configure Router Port Forwarding

1. Access your router admin panel (usually http://192.168.1.1 or http://192.168.0.1)
2. Find **Port Forwarding** or **Virtual Server** settings
3. Add a new rule:
   - **Service Name**: VPN Server
   - **External Port**: 5555
   - **Internal Port**: 5555
   - **Protocol**: TCP
   - **Internal IP**: (Your PC's IP - find with `ipconfig`)
   - **Status**: Enabled

#### 2. Find Your PC's Local IP

Open PowerShell and run:

```powershell
ipconfig
```

Look for "IPv4 Address" under your active network adapter (usually something like `192.168.1.x`)

#### 3. Configure Windows Firewall

Run PowerShell as Administrator:

```powershell
New-NetFirewallRule -DisplayName "VPN Server" -Direction Inbound -LocalPort 5555 -Protocol TCP -Action Allow
```

#### 4. Keep DuckDNS Updated

**Run this on server startup** (keeps your domain pointing to current IP):

```powershell
cd D:\HP\Projects\VPN-InfoSecProject\Code
python domainupdater.py
```

Keep this running in the background. It updates every 5 minutes.

#### 5. Start the VPN Server

```powershell
cd D:\HP\Projects\VPN-InfoSecProject\Code
python server.py
```

---

### On the Client Machine (Other Laptop)

#### 1. Install Dependencies

```powershell
pip install cryptography requests
```

#### 2. Copy These Files to Client Laptop

- `client.py`
- `encryption.py`

#### 3. Run the Client

```powershell
python client.py
```

The GUI will open with the server pre-configured to `myfirstvpnnust.duckdns.org:5555`

#### 4. Connect

1. Click the "Connect" button
2. Wait for connection to establish
3. Configure your browser to use SOCKS5 proxy: `127.0.0.1:1080`

---

## Testing the Connection

### Test 1: Check if DuckDNS is working

Open browser and visit: `https://myfirstvpnnust.duckdns.org`

### Test 2: Check if port is open

On client laptop, open PowerShell:

```powershell
Test-NetConnection -ComputerName myfirstvpnnust.duckdns.org -Port 5555
```

Should show: `TcpTestSucceeded : True`

### Test 3: Verify public IP

On server machine:

```powershell
curl https://api.ipify.org
```

This IP should match what DuckDNS shows.

---

## Browser Configuration (SOCKS5 Proxy)

### Firefox

1. Settings → Network Settings → Manual proxy configuration
2. SOCKS Host: `127.0.0.1` Port: `1080`
3. Select "SOCKS v5"
4. Check "Proxy DNS when using SOCKS v5"

### Chrome/Edge

Use extension like "Proxy SwitchyOmega":

1. Install extension
2. New Profile → Proxy Profile
3. Protocol: SOCKS5
4. Server: `127.0.0.1` Port: `1080`

---

## Troubleshooting

### Client can't connect

1. **Check DuckDNS**: Visit your domain in browser - should not timeout
2. **Check firewall**: Temporarily disable Windows Firewall to test
3. **Check router**: Verify port forwarding is enabled
4. **Check server**: Make sure `server.py` is running
5. **Check logs**: Look at server console for connection attempts

### Connection drops frequently

- Router may have aggressive timeout settings
- Try enabling DMZ for your server PC (temporary test only)
- Check if your ISP blocks certain ports

### DuckDNS not updating

- Verify token is correct in `domainupdater.py`
- Check internet connection
- Run updater manually to see errors

---

## Security Notes

⚠️ **Important**:

- Change the default DH parameters (regenerate `dh_params.pem`)
- Use strong server authentication
- Monitor server logs for suspicious activity
- Consider adding IP whitelisting
- Don't expose this to public internet for production use without additional security layers

---

## Quick Reference Commands

**Start Server:**

```powershell
python domainupdater.py  # In one terminal
python server.py         # In another terminal
```

**Start Client (on remote laptop):**

```powershell
python client.py
```

**Check Server Status:**

```powershell
netstat -an | findstr :5555
```

**Test Public IP:**

```powershell
curl https://api.ipify.org
```
