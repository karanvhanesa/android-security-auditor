# 🔍 Android Security Auditor

> **ADB-powered Android security analysis tool with a beautiful localhost web report.**

Connect any Android device via USB and get a full security audit — app permissions, severity ratings, account/email mapping, system app verification, network info, and more — all presented in a sleek dark web dashboard.

---

## ✨ Features

| Feature | Details |
|---|---|
| 📱 **Device Info** | Brand, model, Android version, SDK, security patch, encryption, root status |
| 🛡️ **Severity Levels** | Critical / High / Medium / Low / Info per app, based on dangerous permissions |
| 🔐 **Permission Analysis** | All granted permissions per app, dangerous ones highlighted |
| 📧 **Account / Email Mapping** | Shows Google, email, and other accounts stored on the device |
| 🏗️ **System App Verification** | System apps are trusted — only 3rd-party apps get severity ratings |
| 📶 **Network Info** | IP, MAC address, interfaces |
| 🔋 **Battery & Storage** | Live battery stats and storage layout |
| ⚙️ **Running Services** | Shows currently active background services |
| 🌐 **Localhost Dashboard** | UI, filter by severity, search, expand each app |
| ⬇️ **JSON Export** | Full raw audit data downloadable |

---

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.10+
- `adb` installed and in your PATH
  - **Windows**: Download [Platform Tools](https://developer.android.com/studio/releases/platform-tools) and add to PATH
  - **macOS**: `brew install android-platform-tools`
  - **Linux**: `sudo apt install adb`

### 2. Prepare your Android device

1. Go to **Settings → About Phone** and tap **Build Number** 7 times to enable Developer Options
2. Go to **Settings → Developer Options** and enable **USB Debugging**
3. Connect your phone via USB cable
4. Accept the ADB authorization prompt on your phone

### 3. Install & Run

```bash
git clone https://github.com/YOUR_USERNAME/android-security-auditor
cd android-security-auditor

pip install -r requirements.txt

python server.py
```

4. Open **http://localhost:5000** in your browser
5. Click **Start Security Audit**

---

## 📊 Severity Levels Explained

| Level | Trigger |
|---|---|
| 🔴 **Critical** | 3+ critical permissions OR device admin / accessibility / install packages |
| 🟠 **High** | 1–2 critical permissions (camera, mic, location, SMS, contacts...) |
| 🟡 **Medium** | 3+ high-risk permissions |
| 🟢 **Low** | 1–2 high-risk permissions |
| ℹ️ **Info** | No risky permissions OR system app (trusted) |

### Critical Permissions Include:
- `CAMERA`, `RECORD_AUDIO`
- `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`
- `READ_SMS`, `SEND_SMS`, `RECEIVE_SMS`
- `READ_CONTACTS`, `READ_CALL_LOG`
- `BIND_DEVICE_ADMIN`, `BIND_ACCESSIBILITY_SERVICE`
- `MANAGE_EXTERNAL_STORAGE`, `REQUEST_INSTALL_PACKAGES`
- `GET_ACCOUNTS`, `USE_BIOMETRIC`
- ... and more

---

## 🗂️ Project Structure

```
android-security-auditor/
├── server.py           # Flask web server
├── audit_engine.py     # ADB scanning & analysis logic
├── requirements.txt
├── templates/
│   ├── index.html      # Landing page with device detection
│   └── report.html     # Full security report dashboard
└── README.md
```

---

## 📸 Screenshots

> *Connect your device and run to see the dashboard live.*

- **Landing page**: Device detection, live progress log during scan
- **Report page**: Severity cards, filterable app table, account mapping, device info

---

## ⚠️ Disclaimer

This tool is for **personal security auditing and educational purposes only**. Only run it on devices you own or have explicit permission to audit. The tool reads data via ADB — it does **not** install anything on your device.

---

## 🤝 Contributing

PRs welcome! Ideas for contribution:
- Google Play Protect API integration
- APK hash verification against VirusTotal
- Historical scan comparison
- Export to PDF report
- Network traffic capture via `tcpdump`

---

## 📄 License

MIT License
