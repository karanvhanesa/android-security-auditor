"""
Android Security Audit Engine
Collects device info, app data, permissions, and email associations via ADB.
"""

import subprocess
import json
import re
import os
import shutil
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

# ─── Dangerous permissions that warrant HIGH/CRITICAL severity ───────────────
CRITICAL_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
}

HIGH_PERMISSIONS = {
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.NFC",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.INTERNET",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.CHANGE_CONFIGURATION",
    "android.permission.REORDER_TASKS",
    "android.permission.READ_PRECISE_PHONE_STATE",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.DISABLE_KEYGUARD",
}

ALWAYS_CRITICAL_PERMISSIONS = {
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
}

RISK_WEIGHTS = {
    "android.permission.BIND_DEVICE_ADMIN": 10,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 10,
    "android.permission.REQUEST_INSTALL_PACKAGES": 9,
    "android.permission.MANAGE_EXTERNAL_STORAGE": 8,
    "android.permission.SYSTEM_ALERT_WINDOW": 7,
    "android.permission.WRITE_SETTINGS": 6,
    "android.permission.SEND_SMS": 6,
    "android.permission.RECEIVE_SMS": 6,
    "android.permission.READ_SMS": 6,
    "android.permission.READ_CALL_LOG": 5,
    "android.permission.WRITE_CALL_LOG": 5,
    "android.permission.PROCESS_OUTGOING_CALLS": 5,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 5,
    "android.permission.RECORD_AUDIO": 4,
    "android.permission.CAMERA": 4,
    "android.permission.ACCESS_FINE_LOCATION": 4,
    "android.permission.ACCESS_COARSE_LOCATION": 3,
    "android.permission.READ_CONTACTS": 4,
    "android.permission.WRITE_CONTACTS": 4,
    "android.permission.CALL_PHONE": 4,
    "android.permission.READ_PHONE_STATE": 3,
    "android.permission.GET_ACCOUNTS": 2,
    "android.permission.USE_BIOMETRIC": 1,
    "android.permission.USE_FINGERPRINT": 1,
}

PROFILE_KEYWORDS = {
    "messaging": ("whatsapp", "telegram", "signal", "messenger", "messages", "sms", "imo"),
    "social": ("instagram", "facebook", "twitter", "snapchat", "linkedin", "reddit"),
    "navigation": ("maps", "uber", "ola", "lyft", "gps", "nav"),
    "media": ("youtube", "camera", "music", "spotify", "netflix", "hotstar", "video"),
    "finance": ("pay", "bank", "wallet", "upi", "merchant", "money", "finance"),
    "commerce": ("flipkart", "amazon", "myntra", "shop", "store", "food", "zomato", "swiggy", "kfc"),
    "communication": ("meet", "zoom", "teams", "phone", "dialer", "call"),
}

EXPECTED_PERMISSIONS_BY_PROFILE = {
    "messaging": {
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
    },
    "social": {
        "android.permission.READ_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
    },
    "navigation": {
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.CALL_PHONE",
    },
    "media": {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
    },
    "finance": {
        "android.permission.USE_BIOMETRIC",
        "android.permission.USE_FINGERPRINT",
        "android.permission.CAMERA",
        "android.permission.READ_PHONE_STATE",
    },
    "commerce": {
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.CAMERA",
    },
    "communication": {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
    },
}

# Known system package prefixes
SYSTEM_PACKAGE_PREFIXES = [
    "com.android.", "com.google.android.", "com.samsung.", "com.miui.",
    "com.huawei.", "com.oneplus.", "com.oppo.", "com.realme.",
    "com.oplus.", "android", "com.sec.", "com.qualcomm.", "com.mediatek.",
    "com.lge.", "com.motorola.", "com.htc.", "com.sony.", "com.asus.",
]

SYSTEM_APP_PATH_PREFIXES = (
    "/system/",
    "/system_ext/",
    "/product/",
    "/vendor/",
    "/odm/",
    "/apex/",
)

THIRD_PARTY_APP_PATH_PREFIXES = (
    "/data/app/",
    "/mnt/expand/",
)


def find_adb_executable() -> Optional[str]:
    """Locate the adb executable from PATH or common Android SDK locations."""
    adb_from_path = shutil.which("adb")
    if adb_from_path:
        return adb_from_path

    candidates = [
        os.environ.get("ADB_PATH"),
        os.path.join(os.environ.get("ANDROID_SDK_ROOT", ""), "platform-tools", "adb.exe"),
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "adb.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "platform-tools", "adb.exe"),
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def run_adb(args: list[str], timeout: int = 30) -> Optional[str]:
    """Run an ADB command and return stdout, or None on failure."""
    adb_executable = find_adb_executable()
    if not adb_executable:
        return None
    try:
        result = subprocess.run(
            [adb_executable] + args,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def run_adb_shell(cmd: str, timeout: int = 30) -> Optional[str]:
    return run_adb(["shell", cmd], timeout=timeout)


def normalize_android_value(value: str) -> str:
    value = (value or "").strip()
    if value in {"", "null", "None", "<none>"}:
        return "Unknown"
    return value


def infer_app_profiles(package: str) -> list[str]:
    package_lower = package.lower()
    profiles = [profile for profile, keywords in PROFILE_KEYWORDS.items()
                if any(keyword in package_lower for keyword in keywords)]
    return profiles or ["general"]


def check_device_connected() -> dict:
    """Check if a device is connected via ADB."""
    adb_executable = find_adb_executable()
    if not adb_executable:
        return {
            "connected": False,
            "error": "ADB not found. Install Android platform-tools or add adb to PATH.",
        }

    output = run_adb(["devices"])
    if not output:
        return {
            "connected": False,
            "error": f"ADB was found at {adb_executable}, but it did not return any device data.",
        }

    lines = [l.strip() for l in output.splitlines() if l.strip() and "List of" not in l]
    authorized_devices = []
    unauthorized_devices = []
    offline_devices = []

    for line in lines:
        parts = re.split(r"\s+", line)
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        if state == "device":
            authorized_devices.append(line)
        elif state == "unauthorized":
            unauthorized_devices.append(serial)
        elif state == "offline":
            offline_devices.append(serial)

    if authorized_devices:
        return {"connected": True, "device_line": authorized_devices[0], "adb_path": adb_executable}
    if unauthorized_devices:
        return {
            "connected": False,
            "error": "Device detected but not authorized. Accept the USB debugging prompt on the phone.",
            "devices": unauthorized_devices,
            "adb_path": adb_executable,
        }
    if offline_devices:
        return {
            "connected": False,
            "error": "Device is offline in ADB. Reconnect USB or restart adb.",
            "devices": offline_devices,
            "adb_path": adb_executable,
        }
    return {
        "connected": False,
        "error": "No Android device detected. Connect a phone and enable USB debugging.",
        "adb_path": adb_executable,
    }


def get_device_info() -> dict:
    """Collect basic device information."""
    props = {
        "brand":        run_adb_shell("getprop ro.product.brand") or "Unknown",
        "model":        run_adb_shell("getprop ro.product.model") or "Unknown",
        "manufacturer": run_adb_shell("getprop ro.product.manufacturer") or "Unknown",
        "android_version": run_adb_shell("getprop ro.build.version.release") or "Unknown",
        "sdk_version":  run_adb_shell("getprop ro.build.version.sdk") or "Unknown",
        "build_number": run_adb_shell("getprop ro.build.display.id") or "Unknown",
        "device_name":  run_adb_shell("getprop ro.product.name") or "Unknown",
        "serial":       run_adb_shell("getprop ro.serialno") or "Unknown",
        "fingerprint":  run_adb_shell("getprop ro.build.fingerprint") or "Unknown",
        "security_patch": run_adb_shell("getprop ro.build.version.security_patch") or "Unknown",
        "kernel":       run_adb_shell("uname -r") or "Unknown",
        "cpu_abi":      run_adb_shell("getprop ro.product.cpu.abi") or "Unknown",
        "screen_size":  run_adb_shell("wm size") or "Unknown",
        "screen_density": run_adb_shell("wm density") or "Unknown",
        "total_ram":    run_adb_shell("cat /proc/meminfo | grep MemTotal") or "Unknown",
        "uptime":       run_adb_shell("uptime") or "Unknown",
        "timezone":     run_adb_shell("getprop persist.sys.timezone") or "Unknown",
        "language":     run_adb_shell("getprop persist.sys.locale") or "Unknown",
        "bootloader":   run_adb_shell("getprop ro.bootloader") or "Unknown",
        "hardware":     run_adb_shell("getprop ro.hardware") or "Unknown",
        "baseband":     run_adb_shell("getprop gsm.version.baseband") or "Unknown",
    }
    # Rooted?
    su_check = run_adb_shell("which su")
    props["is_rooted"] = bool(su_check and su_check.strip())
    # USB debugging
    props["usb_debug"] = run_adb_shell("getprop persist.service.adb.enable") == "1"
    # Unknown sources
    unknown_src = run_adb_shell("settings get global install_non_market_apps")
    props["unknown_sources"] = unknown_src == "1"
    # Encryption
    enc = run_adb_shell("getprop ro.crypto.state") or ""
    props["encryption"] = enc
    # Screen lock
    lock = run_adb_shell("getprop ro.lockscreen.disabledefaultininfo") or ""
    props["screen_lock"] = lock
    return props


def get_installed_packages() -> list[str]:
    """List all installed package names."""
    output = run_adb_shell("pm list packages -f") or ""
    packages = []
    for line in output.splitlines():
        # format: package:/data/app/.../base.apk=com.example.app
        cleaned = line.strip()
        if cleaned.startswith("package:"):
            cleaned = cleaned[len("package:"):]
        if "=" in cleaned:
            packages.append(cleaned.rsplit("=", 1)[1].strip())
    return packages


def classify_app_origin(package: str, package_dump: str, apk_path: str) -> dict:
    """Classify package origin with evidence and confidence.

    To reduce false positives, ambiguous packages are marked for manual review
    instead of being forced into system/third-party.
    """
    normalized_apk_path = normalize_android_value(apk_path)
    flags = set()

    for line in package_dump.splitlines():
        stripped = line.strip()
        if stripped.startswith("pkgFlags=[") or stripped.startswith("flags=["):
            inner = stripped.split("[", 1)[1].rsplit("]", 1)[0]
            flags.update(part.strip().upper() for part in inner.split() if part.strip())

    if normalized_apk_path != "Unknown":
        if normalized_apk_path.startswith(SYSTEM_APP_PATH_PREFIXES):
            return {
                "app_type": "system",
                "is_system": True,
                "classification_confidence": "high",
                "classification_reason": f"APK path is under protected system partition: {normalized_apk_path}",
                "needs_review": False,
            }
        if normalized_apk_path.startswith(THIRD_PARTY_APP_PATH_PREFIXES):
            if {"SYSTEM", "PRIVILEGED", "VENDOR"} & flags:
                return {
                    "app_type": "review",
                    "is_system": False,
                    "classification_confidence": "medium",
                    "classification_reason": f"APK path looks user-installed but package flags include system markers: {normalized_apk_path}",
                    "needs_review": True,
                }
            return {
                "app_type": "third_party",
                "is_system": False,
                "classification_confidence": "high",
                "classification_reason": f"APK path is under user app storage: {normalized_apk_path}",
                "needs_review": False,
            }

    if {"SYSTEM", "PRIVILEGED", "VENDOR", "OEM"} & flags:
        return {
            "app_type": "system",
            "is_system": True,
            "classification_confidence": "medium",
            "classification_reason": f"Package flags indicate system ownership: {', '.join(sorted(flags & {'SYSTEM', 'PRIVILEGED', 'VENDOR', 'OEM'}))}",
            "needs_review": False,
        }

    if any(package.startswith(p) for p in SYSTEM_PACKAGE_PREFIXES):
        return {
            "app_type": "review",
            "is_system": False,
            "classification_confidence": "low",
            "classification_reason": "Package prefix looks vendor/system-like, but package metadata was not strong enough to classify safely.",
            "needs_review": True,
        }

    return {
        "app_type": "review" if normalized_apk_path == "Unknown" else "third_party",
        "is_system": False,
        "classification_confidence": "low" if normalized_apk_path == "Unknown" else "medium",
        "classification_reason": "Package metadata was incomplete." if normalized_apk_path == "Unknown" else f"Package is outside protected system paths: {normalized_apk_path}",
        "needs_review": normalized_apk_path == "Unknown",
    }


def get_app_permissions(package: str) -> dict:
    """Get granted permissions for a package."""
    output = run_adb_shell(f"dumpsys package {package}") or ""
    granted = set()
    dangerous_granted = set()
    # Parse granted permissions
    in_perms = False
    for line in output.splitlines():
        if "granted=true" in line:
            match = re.search(r'(android\.permission\.\w+)', line)
            if match:
                perm = match.group(1)
                granted.add(perm)
                if perm in CRITICAL_PERMISSIONS:
                    dangerous_granted.add(perm)
    return {
        "granted": sorted(granted),
        "dangerous": sorted(dangerous_granted),
    }


def parse_package_record(package: str, output: str) -> dict:
    """Parse app metadata and permissions from a single dumpsys package output."""
    info = {
        "package": package,
        "name": package,  # fallback
        "version_name": "Unknown",
        "version_code": "Unknown",
        "install_date": "Unknown",
        "last_updated": "Unknown",
        "uid": "Unknown",
        "data_dir": "Unknown",
        "apk_path": "Unknown",
        "is_system": False,
        "app_type": "review",
        "classification_confidence": "low",
        "classification_reason": "Package metadata not yet analyzed.",
        "needs_review": True,
        "is_enabled": True,
        "target_sdk": "Unknown",
        "min_sdk": "Unknown",
    }
    granted = set()
    dangerous_granted = set()
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("versionName="):
            info["version_name"] = line.split("=", 1)[1]
        elif line.startswith("versionCode="):
            info["version_code"] = line.split("=", 1)[1].split(" ")[0]
        elif "userId=" in line:
            m = re.search(r'userId=(\d+)', line)
            if m:
                info["uid"] = m.group(1)
        elif line.startswith("dataDir="):
            info["data_dir"] = line.split("=", 1)[1]
        elif "codePath=" in line:
            info["apk_path"] = line.split("=", 1)[1]
        elif line.startswith("targetSdk="):
            info["target_sdk"] = line.split("=", 1)[1]
        elif "minSdk=" in line:
            m = re.search(r'minSdk=(\d+)', line)
            if m:
                info["min_sdk"] = m.group(1)
        elif line.startswith("firstInstallTime="):
            info["install_date"] = line.split("=", 1)[1]
        elif line.startswith("lastUpdateTime="):
            info["last_updated"] = line.split("=", 1)[1]
        elif "granted=true" in line:
            match = re.search(r'(android\.permission\.\w+)', line)
            if match:
                perm = match.group(1)
                granted.add(perm)
                if perm in CRITICAL_PERMISSIONS:
                    dangerous_granted.add(perm)

    info["data_dir"] = normalize_android_value(info["data_dir"])
    info["apk_path"] = normalize_android_value(info["apk_path"])
    classification = classify_app_origin(package, output, info["apk_path"])
    info.update(classification)

    # Enabled state
    state = run_adb_shell(f"pm list packages -d | grep {package}")
    if state:
        info["is_enabled"] = False
    return {
        "info": info,
        "permissions": {
            "granted": sorted(granted),
            "dangerous": sorted(dangerous_granted),
        }
    }


def get_app_info(package: str) -> dict:
    """Get detailed info for a single app."""
    output = run_adb_shell(f"dumpsys package {package}") or ""
    return parse_package_record(package, output)["info"]


def get_accounts() -> list[dict]:
    """Get accounts/emails from several ADB-readable sources."""
    seen = set()
    accounts = []

    def add_account(name: str, acc_type: str, source: str):
        name = (name or "").strip()
        acc_type = (acc_type or "").strip() or "unknown"
        if not name:
            return
        key = (name.lower(), acc_type.lower())
        if key in seen:
            return
        seen.add(key)
        accounts.append({
            "name": name,
            "type": acc_type,
            "source": source,
        })

    dumpsys_outputs = [
        ("dumpsys account", run_adb_shell("dumpsys account") or ""),
        ("dumpsys account_service", run_adb_shell("dumpsys account_service") or ""),
    ]
    for source, output in dumpsys_outputs:
        for line in output.splitlines():
            line = line.strip()
            if "name=" in line and "type=" in line:
                nm = re.search(r'name=([^,}]+)', line)
                tp = re.search(r'type=([^,}]+)', line)
                if nm and tp:
                    add_account(nm.group(1), tp.group(1), source)

    profile_output = run_adb_shell(
        'content query --uri content://com.android.contacts/profile/data --projection data1,mimetype'
    ) or ""
    for line in profile_output.splitlines():
        email = re.search(r'data1=([^\s,]+@[^\s,]+)', line, re.IGNORECASE)
        if email:
            add_account(email.group(1), "profile_email", "contacts_profile")

    contacts_output = run_adb_shell(
        'content query --uri content://com.android.contacts/data --projection data1,mimetype --where "mimetype=\'vnd.android.cursor.item/email_v2\'"'
    ) or ""
    for line in contacts_output.splitlines():
        email = re.search(r'data1=([^\s,]+@[^\s,]+)', line, re.IGNORECASE)
        if email:
            add_account(email.group(1), "contact_email", "contacts_data")

    return accounts


def get_network_info() -> dict:
    """Get network / WiFi info with Wi-Fi risk assessment.

    Android does not expose saved Wi-Fi passwords over standard ADB on
    non-rooted devices, so this audit checks network security types instead.
    """
    wifi_ssid = run_adb_shell("dumpsys wifi | grep 'mWifiInfo'") or ""
    ip = run_adb_shell("ip route get 8.8.8.8 2>/dev/null | awk '{print $7}'") or "Unknown"
    mac = run_adb_shell("cat /sys/class/net/wlan0/address") or "Unknown"
    interfaces = run_adb_shell("ip addr show") or ""
    wifi_status = run_adb_shell("cmd wifi status") or ""
    wifi_networks = run_adb_shell("cmd wifi list-networks") or ""
    wifi_dump = run_adb_shell("dumpsys wifi") or ""

    saved_network_map = {}
    saved_networks_by_ssid = {}
    open_saved_networks = set()
    weak_saved_networks = set()
    secure_saved_networks = 0
    for line in wifi_networks.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.+?)\s{2,}([a-zA-Z0-9\-\^_]+)\s*$", line)
        if not match:
            continue
        net_id, ssid, security_type = match.groups()
        entry = saved_network_map.setdefault(net_id, {"ssid": ssid.strip(), "security_types": set()})
        entry["security_types"].add(security_type.strip().lower())
        saved_networks_by_ssid.setdefault(ssid.strip(), set()).add(security_type.strip().lower())

    for ssid, security_types in saved_networks_by_ssid.items():
        if any(sec.startswith("wep") for sec in security_types):
            weak_saved_networks.add(ssid)
        elif security_types == {"open"}:
            open_saved_networks.add(ssid)
        else:
            secure_saved_networks += 1

    current_ssid_match = re.search(r'Wifi is connected to "([^"]+)"', wifi_status)
    current_ssid = current_ssid_match.group(1) if current_ssid_match else "Unknown"
    current_net_match = re.search(r'Net ID:\s*(\d+)', wifi_status)
    current_net_id = current_net_match.group(1) if current_net_match else None
    current_security_types = sorted(saved_network_map.get(current_net_id, {}).get("security_types", set()))
    ip_match = re.search(r'IP:\s*/([0-9.]+)', wifi_status)
    mac_match = re.search(r'MAC:\s*([0-9a-f:]{17})', wifi_status, re.IGNORECASE)
    bssid_match = re.search(r'BSSID:\s*([0-9a-f:]{17})', wifi_status, re.IGNORECASE)
    rssi_match = re.search(r'RSSI:\s*(-?\d+)', wifi_status)
    frequency_match = re.search(r'Frequency:\s*(\d+)MHz', wifi_status)
    wifi_standard_match = re.search(r'Wi-Fi standard:\s*([^\s,]+)', wifi_status)
    link_speed_match = re.search(r'Link speed:\s*([0-9]+Mbps)', wifi_status)
    tx_link_speed_match = re.search(r'Tx Link speed:\s*([0-9]+Mbps)', wifi_status)
    rx_link_speed_match = re.search(r'Rx Link speed:\s*([0-9]+Mbps)', wifi_status)
    trusted_match = re.search(r'Trusted:\s*(true|false)', wifi_status, re.IGNORECASE)
    hotspot_security_match = re.search(r"SecurityType\s*=\s*(\d+)", wifi_dump)
    hotspot_security = hotspot_security_match.group(1) if hotspot_security_match else "Unknown"
    hotspot_is_open = hotspot_security == "0"

    wifi_risks = []
    if current_security_types:
        if any(sec.startswith("open") for sec in current_security_types):
            wifi_risks.append({
                "level": "high",
                "title": "Current Wi-Fi network is open",
                "detail": f"{current_ssid} does not require a password.",
            })
        elif any(sec.startswith("wep") for sec in current_security_types):
            wifi_risks.append({
                "level": "high",
                "title": "Current Wi-Fi network uses WEP",
                "detail": f"{current_ssid} uses outdated WEP security.",
            })
    if open_saved_networks:
        sample = ", ".join(sorted(open_saved_networks)[:3])
        wifi_risks.append({
            "level": "medium",
            "title": "Open saved Wi-Fi networks detected",
            "detail": f"{len(open_saved_networks)} saved networks allow open access. Examples: {sample}",
        })
    if weak_saved_networks:
        sample = ", ".join(sorted(weak_saved_networks)[:3])
        wifi_risks.append({
            "level": "medium",
            "title": "Weak saved Wi-Fi networks detected",
            "detail": f"{len(weak_saved_networks)} saved networks use weak security. Examples: {sample}",
        })
    if hotspot_is_open:
        wifi_risks.append({
            "level": "high",
            "title": "Phone hotspot is configured as open",
            "detail": "Your hotspot configuration shows SecurityType=0, which means no password is required.",
        })

    saved_network_samples = []
    for ssid in sorted(saved_networks_by_ssid)[:15]:
        saved_network_samples.append({
            "ssid": ssid,
            "security": ", ".join(sorted(saved_networks_by_ssid[ssid])),
        })

    return {
        "wifi_info": wifi_ssid[:200] if wifi_ssid else "Unknown",
        "ip_address": ip_match.group(1) if ip_match else ip,
        "mac_address": mac_match.group(1) if mac_match else mac,
        "interfaces_summary": len(interfaces.splitlines()),
        "current_wifi_ssid": current_ssid,
        "current_wifi_security": ", ".join(current_security_types) if current_security_types else "Unknown",
        "current_wifi_bssid": bssid_match.group(1) if bssid_match else "Unknown",
        "current_wifi_rssi": rssi_match.group(1) + " dBm" if rssi_match else "Unknown",
        "current_wifi_frequency": frequency_match.group(1) + " MHz" if frequency_match else "Unknown",
        "current_wifi_standard": wifi_standard_match.group(1) if wifi_standard_match else "Unknown",
        "current_wifi_link_speed": link_speed_match.group(1) if link_speed_match else "Unknown",
        "current_wifi_tx_link_speed": tx_link_speed_match.group(1) if tx_link_speed_match else "Unknown",
        "current_wifi_rx_link_speed": rx_link_speed_match.group(1) if rx_link_speed_match else "Unknown",
        "current_wifi_trusted": trusted_match.group(1) if trusted_match else "Unknown",
        "saved_networks_total": len(saved_networks_by_ssid),
        "saved_secure_networks": secure_saved_networks,
        "saved_open_networks": len(open_saved_networks),
        "saved_weak_networks": len(weak_saved_networks),
        "saved_network_samples": saved_network_samples,
        "hotspot_security_type": hotspot_security,
        "hotspot_is_open": hotspot_is_open,
        "wifi_risks": wifi_risks,
        "wifi_password_check_note": "Saved Wi-Fi passwords are not readable through standard ADB on non-rooted Android devices, so this audit checks Wi-Fi security types instead.",
    }


def get_running_services() -> list[str]:
    """Get currently running services."""
    output = run_adb_shell("dumpsys activity services | grep ServiceRecord") or ""
    services = []
    for line in output.splitlines():
        m = re.search(r'\{[\w\s]+\s+([\w.]+)/[\w.]+\}', line)
        if m:
            services.append(m.group(1))
    return list(set(services))


def get_battery_info() -> dict:
    output = run_adb_shell("dumpsys battery") or ""
    info = {}
    for line in output.splitlines():
        line = line.strip()
        for key in ["level", "status", "health", "temperature", "voltage", "technology"]:
            if line.startswith(f"{key}:"):
                info[key] = line.split(":", 1)[1].strip()
    return info


def get_storage_info() -> dict:
    output = run_adb_shell("df -h /data /sdcard 2>/dev/null") or ""
    return {"raw": output[:500]}


def assess_severity(app: dict, permissions: dict, is_system: bool) -> str:
    """Calculate severity using contextual risk scoring instead of raw counts."""
    dangerous = permissions.get("dangerous", [])
    if is_system:
        app["risk_score"] = 0
        app["risk_explanation"] = "System app on protected partition; not scored as third-party risk."
        return "info"
    if app.get("needs_review"):
        app["risk_score"] = 0
        app["risk_explanation"] = "App classification needs review before assigning a risk level."
        return "info"

    profiles = infer_app_profiles(app["package"])
    app["app_profiles"] = profiles
    expected_permissions = set().union(*(EXPECTED_PERMISSIONS_BY_PROFILE.get(profile, set()) for profile in profiles))

    weighted_score = 0
    suspicious_permissions = []
    expected_permissions_found = []
    sensitive_domains = set()

    domain_map = {
        "sms": {"android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"},
        "calls": {"android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE"},
        "contacts": {"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS"},
        "audio_video": {"android.permission.CAMERA", "android.permission.RECORD_AUDIO"},
        "location": {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"},
        "admin": ALWAYS_CRITICAL_PERMISSIONS | {"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.WRITE_SETTINGS"},
    }

    for perm in dangerous:
        base_weight = RISK_WEIGHTS.get(perm, 1)
        if perm in expected_permissions:
            weighted_score += max(1, base_weight - 3)
            expected_permissions_found.append(perm)
        else:
            weighted_score += base_weight
            suspicious_permissions.append(perm)

        for domain, domain_permissions in domain_map.items():
            if perm in domain_permissions:
                sensitive_domains.add(domain)

    admin_permissions = [perm for perm in dangerous if perm in ALWAYS_CRITICAL_PERMISSIONS]
    if admin_permissions:
        app["risk_score"] = weighted_score
        app["risk_explanation"] = "Critical because the app has administrative or package-install style permissions."
        return "critical"

    if weighted_score >= 14 and len(sensitive_domains) >= 3:
        severity = "high"
    elif weighted_score >= 9 and len(sensitive_domains) >= 2:
        severity = "medium"
    elif weighted_score >= 4:
        severity = "low"
    else:
        severity = "info"

    summary_bits = []
    if suspicious_permissions:
        summary_bits.append(f"unexpected sensitive permissions: {', '.join(sorted(suspicious_permissions)[:5])}")
    if expected_permissions_found:
        summary_bits.append(f"expected for profile {', '.join(profiles)}: {', '.join(sorted(expected_permissions_found)[:5])}")
    if not summary_bits:
        summary_bits.append("no unusual dangerous-permission combination detected")

    app["risk_score"] = weighted_score
    app["risk_explanation"] = "; ".join(summary_bits)
    return severity


def calculate_severity_counts(apps: list[dict]) -> dict:
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for app in apps:
        severity = app.get("severity", "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return severity_counts


def is_ai_enabled() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY"))


def build_ai_review_payload(audit_result: dict) -> dict:
    apps = audit_result.get("apps", [])
    risky_apps = [
        {
            "package": app.get("package"),
            "severity": app.get("severity"),
            "risk_score": app.get("risk_score"),
            "app_type": app.get("app_type"),
            "profiles": app.get("app_profiles", []),
            "dangerous_permissions": app.get("permissions", {}).get("dangerous", [])[:10],
            "risk_explanation": app.get("risk_explanation"),
        }
        for app in apps if app.get("severity") != "info"
    ][:40]

    account_types = sorted({acc.get("type", "unknown") for acc in audit_result.get("accounts", [])})
    network = audit_result.get("network", {})

    return {
        "scan_time": audit_result.get("scan_time"),
        "device": audit_result.get("device", {}),
        "severity_summary": audit_result.get("severity_summary", {}),
        "system_apps": audit_result.get("system_apps", 0),
        "third_party_apps": audit_result.get("third_party_apps", 0),
        "accounts_count": len(audit_result.get("accounts", [])),
        "account_types": account_types[:12],
        "network": {
            "current_wifi_ssid": network.get("current_wifi_ssid"),
            "current_wifi_security": network.get("current_wifi_security"),
            "current_wifi_bssid": network.get("current_wifi_bssid"),
            "hotspot_is_open": network.get("hotspot_is_open"),
            "wifi_risks": network.get("wifi_risks", []),
        },
        "risky_apps": risky_apps,
    }


def extract_response_output_text(response_json: dict) -> str:
    if response_json.get("output_text"):
        return response_json["output_text"]

    for item in response_json.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and content.get("text"):
                return content["text"]
    raise ValueError("No text output returned from OpenAI response.")


def generate_ai_review(audit_result: dict) -> dict:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return {
            "enabled": False,
            "error": "OPENAI_API_KEY is not set. Add it to enable AI review.",
        }

    model = os.environ.get("OPENAI_MODEL", "gpt-5-mini")
    payload_data = build_ai_review_payload(audit_result)
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "summary": {"type": "string"},
            "overall_assessment": {
                "type": "string",
                "enum": ["safe", "watchlist", "investigate", "high_risk"],
            },
            "confidence": {
                "type": "string",
                "enum": ["low", "medium", "high"],
            },
            "false_positive_notes": {"type": "string"},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "package": {"type": "string"},
                        "title": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["low", "medium", "high"],
                        },
                        "rationale": {"type": "string"},
                        "recommended_action": {"type": "string"},
                    },
                    "required": ["package", "title", "severity", "confidence", "rationale", "recommended_action"],
                },
            },
        },
        "required": ["summary", "overall_assessment", "confidence", "false_positive_notes", "findings"],
    }

    request_body = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "You are an Android security analyst reviewing an ADB-based audit. "
                            "Be conservative about false positives. Do not escalate normal social, messaging, navigation, "
                            "media, or finance app permissions unless the combination is unusual for that app profile. "
                            "Focus on apps with unexpected dangerous permissions, abuse-style permissions, administrative "
                            "capabilities, package installation abilities, overlay abuse, or suspicious permission combinations."
                        ),
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "Review this Android security audit payload and return only the JSON schema response.\n\n"
                            + json.dumps(payload_data, indent=2)
                        ),
                    }
                ],
            },
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "android_audit_ai_review",
                "schema": schema,
                "strict": True,
            }
        },
    }

    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(request_body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            response_json = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        return {
            "enabled": True,
            "error": f"OpenAI API error: {exc.code}",
            "details": error_body[:1000],
        }
    except Exception as exc:
        return {
            "enabled": True,
            "error": f"AI review failed: {exc}",
        }

    output_text = extract_response_output_text(response_json)
    review = json.loads(output_text)
    review["enabled"] = True
    review["model"] = model
    return review


def run_full_audit(progress_callback=None) -> dict:
    """Run the complete audit and return structured results."""
    def log(msg):
        if progress_callback:
            progress_callback(msg)

    log("Checking device connection...")
    connection = check_device_connected()
    if not connection["connected"]:
        return {"error": connection["error"]}

    log("Gathering device information...")
    device_info = get_device_info()

    log("Scanning installed packages...")
    packages = get_installed_packages()

    log("Fetching account/email data...")
    accounts = get_accounts()

    log("Gathering network information...")
    network = get_network_info()

    log("Checking battery status...")
    battery = get_battery_info()

    log("Scanning storage...")
    storage = get_storage_info()

    log("Scanning running services...")
    services = get_running_services()

    apps = []
    total = len(packages)
    for i, pkg in enumerate(packages):
        if progress_callback and i % 10 == 0:
            progress_callback(f"Auditing app {i+1}/{total}: {pkg}")
        package_output = run_adb_shell(f"dumpsys package {pkg}") or ""
        parsed = parse_package_record(pkg, package_output)
        info = parsed["info"]
        perms = parsed["permissions"]
        severity = assess_severity(info, perms, info["is_system"])
        info["permissions"] = perms
        info["severity"] = severity
        apps.append(info)

    severity_counts = calculate_severity_counts(apps)

    # Map accounts to app types
    account_map = []
    for acc in accounts:
        acc_type = acc["type"]
        matched_apps = [a["package"] for a in apps if acc_type in a["package"] or
                        any(acc_type in p for p in a["permissions"].get("granted", []))]
        account_map.append({**acc, "likely_apps": matched_apps[:3]})

    return {
        "scan_time": datetime.now().isoformat(),
        "device": device_info,
        "apps": apps,
        "accounts": account_map,
        "network": network,
        "battery": battery,
        "storage": storage,
        "running_services": services[:50],
        "severity_summary": severity_counts,
        "total_apps": total,
        "system_apps": sum(1 for a in apps if a["is_system"]),
        "third_party_apps": sum(1 for a in apps if a["app_type"] == "third_party"),
        "review_apps": sum(1 for a in apps if a.get("needs_review")),
    }
