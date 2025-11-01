import sys
import os
import psutil
import wmi
import subprocess

# ==== Global subprocess hide-all windows patch ====
try:
    import subprocess as _sp

    _STARTUPINFO = _sp.STARTUPINFO()
    _STARTUPINFO.dwFlags |= _sp.STARTF_USESHOWWINDOW
    _CREATE_NO_WINDOW = 0x08000000

    _orig_run = _sp.run
    _orig_popen = _sp.Popen

    def _run_hidden(*args, **kwargs):
        # Ensure no console window flashes
        kwargs.setdefault('startupinfo', _STARTUPINFO)
        kwargs['creationflags'] = kwargs.get('creationflags', 0) | _CREATE_NO_WINDOW
        return _orig_run(*args, **kwargs)

    def _popen_hidden(*args, **kwargs):
        # Ensure no console window flashes
        kwargs.setdefault('startupinfo', _STARTUPINFO)
        kwargs['creationflags'] = kwargs.get('creationflags', 0) | _CREATE_NO_WINDOW
        return _orig_popen(*args, **kwargs)

    # Monkeypatch globally
    _sp.run = _run_hidden
    _sp.Popen = _popen_hidden
except Exception as _e:
    # Fallback: ignore if patching fails
    pass
# ==== END patch ====

import shutil
import ctypes
import winreg
import time
import json
import platform
import socket
import re
import webbrowser
import GPUtil
import base64
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QTabWidget, QPushButton, QLabel, QProgressBar, QTextEdit, QFrame,
                             QComboBox, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
                             QListWidget, QListWidgetItem, QGroupBox, QSizePolicy, QSplitter,
                             QCheckBox, QLineEdit, QFileDialog, QDialog, QDialogButtonBox,
                             QFormLayout, QTreeWidget, QTreeWidgetItem, QAbstractItemView,
                             QMenu, QAction, QMainWindow, QToolBar, QStatusBar, QScrollArea)
ICON_SIZE = 48  # unified icon size for Uninstaller icons
from PyQt5.QtCore import QTimer, Qt, QSize, QThread, pyqtSignal, QTranslator, QLocale, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont, QIcon, QColor, QFontDatabase, QPalette, QLinearGradient, QBrush, QPixmap, QRadialGradient, QImage

# Windows-specific imports for icon extraction
import win32gui
import win32ui
import win32con
import win32api

# ===================== إضافات جديدة لنظام التراخيص =====================
import requests
import uuid

# ===== Local Licensing (JWT, offline) =====
import jwt, hashlib, base64
from jwt import InvalidTokenError, ExpiredSignatureError
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# حمّل المفتاح العام من ملف أو ثابت داخل الكود
try:
    with open("license_public.pem", "rb") as f:
        PUBLIC_KEY_PEM = f.read()
except Exception:
    # لو ما بدك توزّع الملف، الصق محتوى license_public.pem بين السطور تحت
    PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3gdVR5BRaSuL74r8RbE9
9ZkHYxzp0BsMXfKZOB6YuPVgtat9HYC/kEYEpel1dvqdb48yyUlx/rhUlicqlwz7
SJKt1qCw0ujBgBZ65O3gC2wrEr6jLbYu1zWgJWHTi4YJAYBvCOpDOIearFsGRtZ4
6Gb5ugriF4LIalSq+Ydx8a86EuidKxN983mSqRTS0nEQK+tuLXIbdmizVpKB48hi
ldDIRbs/5ZeWetRpv4bVt86XjeCWCOPFISZ3iEkMLgarjIyuS4D+X0QzJuAixcUh
mpY4HXfv7FMyvJJZyap4P3VzvqL8NjBacFV4AjJns+BBB2t047efvg5mCLHpN+BQ
iwIDAQAB
-----END PUBLIC KEY-----"""

def get_machine_id_fingerprint():
    try:
        raw = get_machine_id()  # دالتك الموجودة أصلاً
    except Exception:
        raw = "unknown-machine"
    return hashlib.sha256(str(raw).encode()).hexdigest()

def verify_license_token(token: str):
    try:
        payload = jwt.decode(token, PUBLIC_KEY_PEM, algorithms=["RS256"])
        # ربط بجهاز واحد (اختياري لكنه مطلوب عندك)
        mh = payload.get("machine_hash")
        if mh and mh != get_machine_id_fingerprint():
            return False, "This license is bound to a different device."
        # Blacklist اختياري (لو عملته لاحقًا)
        try:
            resp = requests.get("https://YOUR-UPDATES-DOMAIN-OR-PAGES/latest_blacklist.json", timeout=3)
            if resp.ok and payload.get("license_id") in resp.json().get("revoked_ids", []):
                return False, "This license is revoked."
        except Exception:
            pass
        return True, f"License OK ({payload.get('type')})"
    except ExpiredSignatureError:
        return False, "License expired."
    except InvalidTokenError:
        return False, "Invalid license."
    except Exception as e:
        return False, f"License verification error: {e}"

def activate_license_offline(license_key: str):
    ok, msg = verify_license_token(license_key)
    if ok:
        save_license(license_key)  # عندك هذه الدالة جاهزة
        return True, "Activated successfully."
    return False, msg
# ===== End Local Licensing =====


# عنوان الخادم (قم بتغييره إلى عنوان الخادم الحقيقي في الإنتاج)

LICENSE_FILE = "license.key"
TRIAL_FILE = "trial_start.json"

# ===================== Professional Dark Theme Stylesheet V7 =====================
dark_stylesheet_v7 = """
QWidget {
    background-color: #0A0A0A;
    color: #E0E0E0;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 10pt;
}
QTabWidget::pane {
    border: 1px solid #1F1F1F;
    border-radius: 8px;
    background-color: #0A0A0A;
}
QTabBar::tab {
    background-color: #141414;
    color: #E0E0E0;
    padding: 10px 20px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    border: 1px solid #1F1F1F;
    border-bottom: none;
    margin-right: 4px;
    font-weight: bold;
    font-size: 10pt;
    min-width: 140px;
}
QTabBar::tab:selected, QTabBar::tab:hover {
    background-color: #1A73E8;
    color: #FFFFFF;
    border-color: #1662C9;
}
/* Enhanced Button Style with Shadow and Transition */
QPushButton {
    background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                                      stop: 0 #1A73E8, stop: 0.5 #1662C9, stop: 1 #1A73E8);
    color: #FFFFFF;
    border-style: solid;
    border-width: 1px;
    border-color: #1662C9;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 10pt;
    font-weight: bold;
    min-height: 25px;
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.2);
    transition: background-color 0.3s, box-shadow 0.3s;
}
QPushButton:hover {
    background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                                      stop: 0 #34A853, stop: 0.5 #2E8B57, stop: 1 #34A853);
    border-color: #2E8B57;
    box-shadow: 0px 3px 6px rgba(0, 0, 0, 0.3);
}
QPushButton:pressed {
    background-color: #1A73E8;
    padding: 7px 16px 9px 16px;
    box-shadow: 0px 1px 2px rgba(0, 0, 0, 0.1);
}
QPushButton:disabled {
    background-color: #333333;
    color: #888888;
    border-color: #444444;
}
QProgressBar {
    border: 1px solid #1F1F1F;
    border-radius: 5px;
    text-align: center;
    color: #E0E0E0;
    background-color: #141414;
    height: 20px;
}
QProgressBar::chunk {
    background-color: #34A853;
    border-radius: 4px;
}
QGroupBox {
    border: 1px solid #1F1F1F;
    border-radius: 8px;
    margin-top: 12px;
    font-weight: bold;
    color: #1A73E8;
    padding-top: 12px;
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1);
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top center;
    padding: 0 12px;
    background-color: #141414;
    border-radius: 4px;
}
QTableWidget, QListWidget {
    background-color: #0A0A0A;
    border: 1px solid #1F1F1F;
    gridline-color: #1F1F1F;
    border-radius: 6px;
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1);
}
QHeaderView::section {
    background-color: #141414;
    color: #1A73E8;
    padding: 6px;
    border: 1px solid #0A0A0A;
    font-weight: bold;
}
QTableWidget::item, QListWidget::item {
    padding: 6px;
}
QTableWidget::item:selected, QListWidget::item:selected {
    background-color: #1A73E8;
    color: #FFFFFF;
}
QLineEdit, QTextEdit {
    background-color: #0A0A0A;
    border: 1px solid #1F1F1F;
    border-radius: 6px;
    padding: 6px;
    color: #E0E0E0;
    selection-background-color: #1A73E8;
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1);
}
QComboBox {
    background-color: #0A0A0A;
    border: 1px solid #1F1F1F;
    border-radius: 6px;
    padding: 4px;
    color: #E0E0E0;
    min-width: 120px;
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1);
}
QComboBox:editable {
    background: #0A0A0A;
}
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left-width: 1px;
    border-left-color: #1F1F1F;
    border-left-style: solid;
    border-top-right-radius: 6px;
    border-bottom-right-radius: 6px;
    background-color: #141414;
}
QComboBox QAbstractItemView {
    background-color: #0A0A0A;
    color: #E0E0E0;
    selection-background-color: #1A73E8;
    selection-color: #FFFFFF;
    outline: 0px;
}
QCheckBox {
    color: #E0E0E0;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #1F1F1F;
    border-radius: 3px;
    background-color: #0A0A0A;
}
QCheckBox::indicator:checked {
    background-color: #1A73E8;
    border: 1px solid #1A73E8;
}
/* Premium Logo Style with Gradient and Shadow */
QLabel#logoLabel {
    font-size: 24pt;
    font-weight: bold;
    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                                stop: 0 #1662C9, stop: 0.4 #1A73E8, stop: 0.7 #5E97F6, stop: 1 #AECBFA);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.4);
    padding: 8px;
    border: 2px solid #1F1F1F;
    border-radius: 12px;
    min-width: 280px;
    box-shadow: 0px 3px 6px rgba(0, 0, 0, 0.2);
}
/* Logo Container with Subtle Gradient */
QWidget#logoContainer {
    background-color: #141414;
    border-radius: 12px;
    border: 1px solid #1F1F1F;
    box-shadow: 0px 3px 6px rgba(0, 0, 0, 0.2);
}
QDialog {
    background-color: #0A0A0A;
    color: #E0E0E0;
    border-radius: 8px;
    box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.3);
}
QMainWindow {
    background-color: #0A0A0A;
}
QMenuBar {
    background-color: #141414;
    color: #E0E0E0;
    border: 1px solid #1F1F1F;
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.1);
}
QMenuBar::item {
    background-color: transparent;
    padding: 4px 8px;
}
QMenuBar::item:selected {
    background-color: #1A73E8;
}
QMenu {
    background-color: #141414;
    border: 1px solid #1F1F1F;
    color: #E0E0E0;
    box-shadow: 0px 2px 4px rgba(0, 0, 0, 0.2);
}
QMenu::item:selected {
    background-color: #1A73E8;
}
QStatusBar {
    background-color: #141414;
    color: #E0E0E0;
    border-top: 1px solid #1F1F1F;
    padding: 3px;
}
QLabel#statusLabel {
    color: #FFC107;
    font-style: italic;
}
/* Locked feature style */
QPushButton:disabled {
    background-color: #333333;
    color: #888888;
    border-color: #444444;
}
QLabel#licenseStatus {
    font-size: 10pt;
    font-weight: bold;
    padding: 6px 12px;
    border-radius: 5px;
    margin: 3px;
}
QLabel#licenseStatus[trial="true"] {
    color: #FF9800;
}
QLabel#licenseStatus[licensed="true"] {
    color: #4CAF50;
}
QLabel#lockIcon {
    font-size: 12pt;
    color: #FFC107;
}
/* Locked feature message */
QLabel#lockedMessage {
    font-size: 10pt;
    font-weight: bold;
    color: #FFC107;
    padding: 12px;
    border: 1px solid #FFC107;
    border-radius: 6px;
    background-color: rgba(255, 193, 7, 0.1);
}
/* Responsive design */
QScrollArea {
    border: none;
    background-color: transparent;
}
QScrollArea > QWidget > QWidget {
    background-color: transparent;
}
/* Enhanced table for uninstaller */
QTableWidget::item {
    padding: 8px;
    border-bottom: 1px solid #1F1F1F;
}
QTableWidget::item:selected {
    background-color: #1A73E8;
}
QTableWidget {
    alternate-background-color: #141414;
}
"""

# ===================== TRANSLATION SYSTEM =====================
class Translation:
    def __init__(self):
        self.translations = {
            "en": {
                "file": "File",
                "exit": "Exit",
                "close": "Close",
                "send_email": "Send Email",
                "visit_website": "Visit Website",
                "app_title": "PCFixUltimate - Professional System Suite",
                "system_tab": "💻 System",
                "performance_tab": "⚡ Performance",
                "cleaner_tab": "🧹 Cleaner",
                "tools_tab": "🧰 Tools",
                "settings_tab": "⚙️ Settings",
                "reports_tab": "📊 Reports",
                "uninstaller_tab": "❌ Uninstaller",
                "pc_repair_tab": "🛠️ PC Repair",
                "ready": "System ready",
                "cpu": "CPU",
                "ram": "RAM",
                "gpu": "GPU",
                "disk": "Disk",
                "temp": "Temp",
                "system_info": "System Information",
                "hw_monitor": "Hardware Monitor",
                "cpu_usage": "CPU Usage",
                "ram_usage": "RAM Usage",
                "gpu_usage": "GPU Usage",
                "disk_usage": "C: Drive Usage",
                "optimize": "Optimize System Performance",
                "ultimate_perf": "Add Ultimate Performance Plan",
                "open_power_plan": "Open Power Plans",
                "process_explorer": "Open Process Explorer",
                "driver_updates": "Check for Driver Updates",
                "memory_clean": "Clean Memory Cache",
                "startup_manager": "Manage Startup Programs",
                "clean_temp": "Clean Temporary Files",
                "empty_recycle": "Empty Recycle Bin",
                "uninstall_apps": "Uninstall Applications",
                "clean_registry": "Clean Registry",
                "disk_analyzer": "Analyze Disk Space",
                "browser_clean": "Clean Browser Data",
                "check_updates": "Check for Updates",
                "system_tools": "System Tools",
                "repair_tools": "Repair Tools",
                "action_reports": "Action Reports",
                "perf_stats": "Performance Statistics",
                "app_uninstaller": "Application Uninstaller",
                "save_report": "Save Report",
                "clear_reports": "Clear Reports",
                "total_actions": "Total Actions:",
                "space_freed": "Space Freed:",
                "issues_fixed": "Issues Fixed:",
                "time_saved": "Time Saved:",
                "search_apps": "Search applications...",
                "uninstall_selected": "Uninstall Selected",
                "refresh_list": "Refresh List",
                "general_settings": "General Settings",
                "privacy_settings": "Privacy Settings",
                "language_settings": "Language Settings",
                "select_language": "Select Language:",
                "theme_settings": "Theme Settings",
                "select_theme": "Select Theme:",
                "light_theme": "Light",
                "dark_theme": "Dark",
                "run_startup": "Run on system startup",
                "auto_scan": "Run system scan on startup",
                "minimize_tray": "Minimize to system tray",
                "auto_clean": "Automatically clean privacy traces",
                "clear_history": "Clear browsing history on exit",
                "block_tracking": "Block tracking cookies",
                "save_settings": "Save Settings",
                "sys_repair": "System Repair",
                "disk_cleanup": "Disk Cleanup",
                "reset_network": "Reset Network",
                "optimize_startup": "Optimize Startup",
                "fix_associations": "Fix File Associations",
                "permission_repair": "Permission Repair",
                "check_disk": "Check Disk",
                "restore_points": "Restore Points",
                "sys_update": "System Update",
                "file_explorer": "File Explorer",
                "registry_editor": "Registry Editor",
                "device_manager": "Device Manager",
                "disk_management": "Disk Management",
                "sys_info": "System Information",
                "user_accounts": "User Accounts",
                "network_settings": "Network Settings",
                "scanning": "Scanning...",
                "cleaning": "Cleaning...",
                "optimizing": "Optimizing...",
                "uninstalling": "Uninstalling...",
                "repairing": "Repairing...",
                "updating": "Updating...",
                "completed": "Completed!",
                "operation_failed": "Operation failed",
                "found_items": "Found {} items",
                "cleaned_files": "Cleaned {} files",
                "freed_space": "Freed {} MB of space",
                "fixed_issues": "Fixed {} issues",
                "uninstalled_apps": "Uninstalled {} applications",
                "admin_required": "Administrator rights required",
                "admin_prompt": "This application requires administrator rights to function correctly. Please restart as an administrator.",
                "processing": "Processing...",
                "gpu_temp": "GPU Temp",
                "system_restore": "System Restore",
                "startup_optimizer": "Startup Optimizer",
                "service_manager": "Service Manager",
                "event_viewer": "Event Viewer",
                "task_scheduler": "Task Scheduler",
                "resource_monitor": "Resource Monitor",
                "advanced_scan": "Advanced System Scan",
                "privacy_shield": "Privacy Shield",
                "performance_monitor": "Performance Monitor",
                "network_optimizer": "Network Optimizer",
                "system_cleaner": "Deep System Cleaner",
                "registry_backup": "Registry Backup",
                "auto_update": "Auto Update Drivers",
                "power_management": "Power Management",
                "system_audit": "System Security Audit",
                "network_optimized": "Network optimized: TCP/IP parameters adjusted",
                "deep_clean_completed": "Deep clean completed: Removed {} unnecessary files from system caches.",
                "driver_update_check": "Driver update check completed",
                "system_update_completed": "System update check completed",
                "disk_cleanup_completed": "Disk cleanup completed",
                "check_disk_completed": "Disk check completed: {} issues found",
                "service_manager_opened": "Service Manager opened",
                "event_viewer_opened": "Event Viewer opened",
                "task_scheduler_opened": "Task Scheduler opened",
                "resource_monitor_opened": "Resource Monitor opened",
                "device_manager_opened": "Device Manager opened",
                "complete_uninstall": "Complete Uninstall",
                "uninstall_complete": "Application uninstalled successfully, and all leftovers removed.",
                "recycle_bin_empty": "Recycle Bin is already empty.",
                "memory_cleaned": "Memory cache cleaned. Freed approximately {} MB.",
                "memory_clean_report_title": "Memory Cleaning Report",
                "memory_clean_report_body": "The system's working set cache has been successfully flushed.\n\n- Available Memory Before: {} MB\n- Available Memory After: {} MB\n- Total Memory Freed: {} MB",
                "network_optimization_report_title": "Network Optimization Summary",
                "network_optimization_report_body": "The following optimizations were applied:\n\n- TCP/IP Auto-Tuning: Set to 'normal'\n- Receive-Side Scaling (RSS): Set to 'enabled'\n- NetDMA State: Set to 'enabled'\n\nThese changes can improve network throughput and reduce latency.",
                "repair_time_remaining": "Estimated time remaining: {}",
                "system_summary": "System Summary",
                "processor": "Processor:",
                "graphics": "Graphics:",
                "memory": "Memory:",
                "os": "OS:",
                "ip_address": "IP Address:",
                "long_operation_note": "This operation may take several minutes. Please be patient.",
                "repair_stage_1": "Scanning Windows system files...",
                "repair_stage_2": "Checking system image health...",
                "repair_stage_3": "Restoring system image...",
                "repair_stage_4": "Finalizing repairs...",
                "about": "About",
                "help": "Help",
                "contact": "Contact",
                "version": "Version: 1.0.0",
                "developer": "Developed by: PCFixUltimate Team",
                "email": "Email: support@pcfixultimate.com",
                "website": "Website: www.pcfixultimate.com",
                "eula": "End User License Agreement",
                "eula_text": "This software is provided as-is without any warranty. By using this software, you agree to the terms and conditions.",
                "user_manual": "User Manual",
                "user_manual_text": "For detailed instructions on how to use PCFixUltimate, please refer to the user manual available on our website.",
                "license_activation": "License Activation",
                "enter_license_key": "Please enter your license key to activate the software:",
                "activate": "Activate",
                "cancel": "Cancel",
                "buy_license": "Buy License",
                "purchase": "Purchase",
                "you_need_to_purchase": "You need to purchase the program to unlock this tool.",
                "trial_mode": "Trial Mode",
                "trial_expired": "Trial period has expired. Please activate with a license key.",
                "trial_active": "You are in trial mode. Full features available for 3 days.",
                "activate_program": "Activate Program",
                "licensed": "Licensed",
                "trial_expires_in": "Trial expires in {} hours.",
                "subscription_type": "Subscription Type:",
                "time_remaining": "Time Remaining:",
                "locked_tools_status": "Locked Tools Status:",
                "pc_repair_locked": "Some tools are locked in trial mode.",
                "license_info": "License Info",
                "trial_24h": "Trial (3 days)",
                "purchased": "Purchased",
                "none": "None",
                "locked_feature": "🔒 Locked Feature",
                "unlock_to_use": "This feature is locked in trial mode. Please purchase the full version to unlock all features.",
                "trial_version": "Trial Version",
                "full_version": "Full Version - Activated",
                "buy_now": "Buy Now",
                "unlock": "Unlock",
                "locked_feature_message": "🔒 This feature is locked in trial mode. Please purchase or activate the full version to access all tools.",
                "update_available": "Update Available",
                "up_to_date": "Up to Date",
                "no_update_check": "Could not check for updates. Please try again later.",
                "new_version": "A new version {} is available. Visit our website to download.",
                "install_date": "Install date",
                "version_app": "Version",
                "install_now": "Install now?",
                "update_downloaded": "Update downloaded. Install now?",
                "update_saved": "Update saved to: {}\nYou can run it manually.",
                "update_error": "Update Error",
                "hash_mismatch": "Hash mismatch. Update aborted.",
                "invalid_signature": "Invalid signature. Update aborted.",
                "invalid_latest": "Invalid latest.json (missing version/url).",
                "network_error": "Network error while checking updates.",
            },
            "ar": {
                "file": "ملف",
                "exit": "خروج",
                "close": "إغلاق",
                "send_email": "إرسال بريد إلكتروني",
                "visit_website": "زيارة الموقع",
                "app_title": "PCFixUltimate - مجموعة أدوات النظام الاحترافية",
                "system_tab": "💻 النظام",
                "performance_tab": "⚡ الأداء",
                "cleaner_tab": "🧹 التنظيف",
                "tools_tab": "🧰 الأدوات",
                "settings_tab": "⚙️ الإعدادات",
                "reports_tab": "📊 التقارير",
                "uninstaller_tab": "❌ المزيل",
                "pc_repair_tab": "🛠️ إصلاح الكمبيوتر",
                "ready": "النظام جاهز",
                "cpu": "المعالج",
                "ram": "الذاكرة",
                "gpu": "كرت الشاشة",
                "disk": "القرص",
                "temp": "الحرارة",
                "system_info": "معلومات النظام",
                "hw_monitor": "مراقبة العتاد",
                "cpu_usage": "استهلاك المعالج",
                "ram_usage": "استهلاك الذاكرة",
                "gpu_usage": "استهلاك كرت الشاشة",
                "disk_usage": "استهلاك القرص C:",
                "optimize": "تحسين أداء النظام",
                "ultimate_perf": "إضافة خطة الطاقة القصوى",
                "open_power_plan": "فتح خطط الطاقة",
                "process_explorer": "فتح مستكشف العمليات",
                "driver_updates": "فحص تحديثات التعاريف",
                "memory_clean": "تنظيف ذاكرة التخزين المؤقت",
                "startup_manager": "إدارة برامج بدء التشغيل",
                "clean_temp": "تنظيف الملفات المؤقتة",
                "empty_recycle": "إفراغ سلة المحذوفات",
                "uninstall_apps": "إلغاء تثبيت التطبيقات",
                "clean_registry": "تنظيف السجل",
                "disk_analyzer": "تحليل مساحة القرص",
                "browser_clean": "تنظيف بيانات المتصفح",
                "check_updates": "التحقق من وجود تحديثات",
                "system_tools": "أدوات النظام",
                "repair_tools": "أدوات الإصلاح",
                "action_reports": "تقارير الإجراءات",
                "perf_stats": "إحصائيات الأداء",
                "app_uninstaller": "مزيل التطبيقات",
                "save_report": "حفظ التقرير",
                "clear_reports": "مسح التقارير",
                "total_actions": "مجموع الإجراءات:",
                "space_freed": "المساحة المحررة:",
                "issues_fixed": "المشاكل التي تم حلها:",
                "time_saved": "الوقت الموفر:",
                "search_apps": "ابحث في التطبيقات...",
                "uninstall_selected": "إلغاء تثبيت المحدد",
                "refresh_list": "تحديث القائمة",
                "general_settings": "الإعدادات العامة",
                "privacy_settings": "إعدادات الخصوصية",
                "language_settings": "إعدادات اللغة",
                "select_language": "اختر اللغة:",
                "theme_settings": "إعدادات المظهر",
                "select_theme": "اختر المظهر:",
                "light_theme": "فاتح",
                "dark_theme": "داكن",
                "run_startup": "التشغيل عند بدء تشغيل النظام",
                "auto_scan": "إجراء فحص للنظام عند بدء التشغيل",
                "minimize_tray": "التصغير إلى علبة النظام",
                "auto_clean": "تنظيف آثار الخصوصية تلقائيًا",
                "clear_history": "مسح سجل التصفح عند الخروج",
                "block_tracking": "حظر ملفات تعريف الارتباط للتتبع",
                "save_settings": "حفظ الإعدادات",
                "sys_repair": "إصلاح النظام",
                "disk_cleanup": "تنظيف القرص",
                "reset_network": "إعادة تعيين الشبكة",
                "optimize_startup": "تحسين بدء التشغيل",
                "fix_associations": "إصلاح اقتران الملفات",
                "permission_repair": "إصلاح الأذونات",
                "check_disk": "فحص القرص",
                "restore_points": "نقاط الاستعادة",
                "sys_update": "تحديث النظام",
                "file_explorer": "مستكشف الملفات",
                "registry_editor": "محرر السجل",
                "device_manager": "مدير الأجهزة",
                "disk_management": "إدارة الأقراص",
                "sys_info": "معلومات النظام",
                "user_accounts": "حسابات المستخدمين",
                "network_settings": "إعدادات الشبكة",
                "scanning": "جارٍ الفحص...",
                "cleaning": "جارٍ التنظيف...",
                "optimizing": "جارٍ التحسين...",
                "uninstalling": "جارٍ إلغاء التثبيت...",
                "repairing": "جارٍ الإصلاح...",
                "updating": "جارٍ التحديث...",
                "completed": "اكتمل!",
                "operation_failed": "فشلت العملية",
                "found_items": "تم العثور على {} عناصر",
                "cleaned_files": "تم تنظيف {} ملفات",
                "freed_space": "تم تحرير {} ميجابايت من المساحة",
                "fixed_issues": "تم إصلاح {} مشاكل",
                "uninstalled_apps": "تم إلغاء تثبيت {} تطبيقات",
                "admin_required": "حقوق المسؤول مطلوبة",
                "admin_prompt": "يتطلب هذا التطبيق حقوق المسؤول للعمل بشكل صحيح. يرجى إعادة التشغيل كمسؤول.",
                "processing": "جارٍ المعالجة...",
                "gpu_temp": "حرارة كرت الشاشة",
                "system_restore": "استعادة النظام",
                "startup_optimizer": "محسن بدء التشغيل",
                "service_manager": "مدير الخدمات",
                "event_viewer": "عارض الأحداث",
                "task_scheduler": "مجدول المهام",
                "resource_monitor": "مراقب الموارد",
                "advanced_scan": "فحص متقدم للنظام",
                "privacy_shield": "درع الخصوصية",
                "performance_monitor": "مراقب الأداء",
                "network_optimizer": "محسن الشبكة",
                "system_cleaner": "منظف النظام العميق",
                "registry_backup": "نسخ احتياطي للسجل",
                "auto_update": "تحديث التعاريف تلقائيًا",
                "power_management": "إدارة الطاقة",
                "system_audit": "تدقيق أمان النظام",
                "network_optimized": "تم تحسين الشبكة: تم ضبط معلمات TCP/IP",
                "deep_clean_completed": "اكتمل التنظيف العميق: تم إزالة {} ملفات غير ضرورية من ذاكرة التخزين المؤقت للنظام.",
                "driver_update_check": "اكتمل فحص تحديثات التعاريف",
                "system_update_completed": "اكتمل فحص تحديثات النظام",
                "disk_cleanup_completed": "اكتمل تنظيف القرص",
                "check_disk_completed": "اكتمل فحص القرص: تم العثور على {} مشاكل",
                "service_manager_opened": "تم فتح مدير الخدمات",
                "event_viewer_opened": "تم فتح عارض الأحداث",
                "task_scheduler_opened": "تم فتح مجدول المهام",
                "resource_monitor_opened": "تم فتح مراقب الموارد",
                "device_manager_opened": "تم فتح مدير الأجهزة",
                "complete_uninstall": "إلغاء التثبيت بالكامل",
                "uninstall_complete": "تم إلغاء تثبيت التطبيق بنجاح، وتمت إزالة جميع المخلفات.",
                "recycle_bin_empty": "سلة المحذوفات فارغة بالفعل.",
                "memory_cleaned": "تم تنظيف ذاكرة التخزين المؤقت. تم تحرير ما يقرب من {} ميجابايت.",
                "memory_clean_report_title": "تقرير تنظيف الذاكرة",
                "memory_clean_report_body": "تم مسح ذاكرة التخزين المؤقت لمجموعة عمل النظام بنجاح.\n\n- الذاكرة المتاحة قبل: {} ميجابايت\n- الذاكرة المتاحة بعد: {} ميجابايت\n- إجمالي الذاكرة المحررة: {} ميجابايت",
                "network_optimization_report_title": "ملخص تحسين الشبكة",
                "network_optimization_report_body": "تم تطبيق التحسينات التالية:\n\n- الضبط التلقائي لـ TCP/IP: تم التعيين على 'normal'\n- تحجيم جانب الاستقبال (RSS): تم التعيين على 'enabled'\n- حالة NetDMA: تم التعيين على 'enabled'\n\nيمكن أن تؤدي هذه التغييرات إلى تحسين إنتاجية الشبكة وتقليل زمن الوصول.",
                "repair_time_remaining": "الوقت المتبقي المقدر: {}",
                "system_summary": "ملخص النظام",
                "processor": "المعالج:",
                "graphics": "كرت الشاشة:",
                "memory": "الذاكرة:",
                "os": "نظام التشغيل:",
                "ip_address": "عنوان IP:",
                "long_operation_note": "هذه العملية قد تستغرق عدة دقائق. يرجى الانتظار.",
                "repair_stage_1": "جارٍ فحص ملفات نظام ويندوز...",
                "repair_stage_2": "جارٍ فحص صحة صورة النظام...",
                "repair_stage_3": "جارٍ استعادة صورة النظام...",
                "repair_stage_4": "جارٍ الانتهاء من الإصلاحات...",
                "about": "حول",
                "help": "مساعدة",
                "contact": "اتصل بنا",
                "version": "الإصدار: 1.0.0",
                "developer": "مطور من قبل: فريق PCFixUltimate",
                "email": "البريد الإلكتروني: support@pcfixultimate.com",
                "website": "الموقع الإلكتروني: www.pcfixultimate.com",
                "eula": "اتفاقية ترخيص المستخدم",
                "eula_text": "يتم توفير هذا البرنامج كما هو دون أي ضمان. باستخدامك لهذا البرنامج، فإنك توافق على الشروط والأحكام.",
                "user_manual": "دليل المستخدم",
                "user_manual_text": "للحصول على تعليمات مفصلة حول كيفية استخدام PCFixUltimate، يرجى الرجوع إلى دليل المستخدم المتوفر على موقعنا الإلكتروني.",
                "license_activation": "تفعيل الترخيص",
                "enter_license_key": "يرجى إدخال مفتاح الترخيص الخاص بك لتفعيل البرنامج:",
                "activate": "تفعيل",
                "cancel": "إلغاء",
                "buy_license": "شراء ترخيص",
                "purchase": "شراء",
                "you_need_to_purchase": "تحتاج إلى شراء البرنامج لفتح هذه الأداة.",
                "trial_mode": "وضع التجربة",
                "trial_expired": "انتهت فترة التجربة. يرجى تفعيل بمفتاح ترخيص.",
                "trial_active": "أنت في وضع التجربة. الميزات الكاملة متاحة لمدة 3 أيام.",
                "activate_program": "تفعيل البرنامج",
                "licensed": "مرخص",
                "trial_expires_in": "تنتهي التجربة في {} ساعات.",
                "subscription_type": "نوع الاشتراك:",
                "time_remaining": "الوقت المتبقي:",
                "locked_tools_status": "حالة الأدوات المقفلة:",
                "pc_repair_locked": "بعض الأدوات مقفلة في وضع التجربة.",
                "license_info": "معلومات الترخيص",
                "trial_24h": "تجربة (3 أيام)",
                "purchased": "مشترى",
                "none": "لا شيء",
                "locked_feature": "🔒 ميزة مقفلة",
                "unlock_to_use": "هذه الميزة مقفلة في وضع التجربة. يرجى شراء النسخة الكاملة لفتح جميع الميزات.",
                "trial_version": "نسخة تجريبية",
                "full_version": "نسخة كاملة - مفعلة",
                "buy_now": "اشتر الآن",
                "unlock": "فتح",
                "locked_feature_message": "🔒 هذه الميزة مقفلة في وضع التجربة. يرجى شراء أو تفعيل النسخة الكاملة للوصول إلى جميع الأدوات.",
                "update_available": "تحديث متوفر",
                "up_to_date": "أنت تمتلك الإصدار الأحدث",
                "no_update_check": "تعذر التحقق من التحديثات. يرجى المحاولة لاحقًا.",
                "new_version": "إصدار جديد {} متوفر. قم بزيارة موقعنا للتنزيل.",
                "install_date": "تاريخ التنصيب",
                "version_app": "إصدار التطبيق",
                "install_now": "تثبيت الآن؟",
                "update_downloaded": "تم تنزيل التحديث. هل تريد التثبيت الآن؟",
                "update_saved": "تم حفظ التحديث في: {}\nيمكنك تشغيله يدويًا.",
                "update_error": "خطأ في التحديث",
                "hash_mismatch": "عدم تطابق الهاش. تم إلغاء التحديث.",
                "invalid_signature": "توقيع غير صالح. تم إلغاء التحديث.",
                "invalid_latest": "ملف latest.json غير صالح (نسخة أو رابط مفقود).",
                "network_error": "خطأ في الشبكة أثناء التحقق من التحديثات.",
            }
        }

    def get(self, key, lang, *args):
        text = self.translations.get(lang, self.translations["en"]).get(key, self.translations["en"].get(key, key))
        if args:
            return text.format(*args)
        return text

translator = Translation()

# Function to extract icon from file with index
def extract_icon(file_path, index):
    try:
        if file_path.lower().endswith('.ico'):
            return QIcon(QPixmap(file_path).scaled(ICON_SIZE, ICON_SIZE, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        
        if index >= 0:
            large, small = win32gui.ExtractIconEx(file_path, index)
        else:
            hinst = win32api.LoadLibraryEx(file_path, 0, win32con.LOAD_LIBRARY_AS_DATAFILE)
            hicon = win32gui.LoadIcon(hinst, -index)
            large = [hicon]
            win32api.FreeLibrary(hinst)
            small = []

        if not large:
            return QIcon()

        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, ICON_SIZE, ICON_SIZE)
        hdc = hdc.CreateCompatibleDC()
        hdc.SelectObject(hbmp)
        hdc.DrawIcon((0, 0), large[0])
        bmpinfo = hbmp.GetInfo()
        bmpstr = hbmp.GetBitmapBits(True)
        img = QImage(bmpstr, bmpinfo['bmWidth'], bmpinfo['bmHeight'], QImage.Format_ARGB32)
        win32gui.DestroyIcon(large[0])
        if small:
            win32gui.DestroyIcon(small[0])
        return QIcon(QPixmap.fromImage(img).scaled(ICON_SIZE, ICON_SIZE, Qt.KeepAspectRatio, Qt.SmoothTransformation))
    except Exception:
        return QIcon()



# ====== Added: Guaranteed Icon Helpers & Brand Overrides ======
from PyQt5.QtGui import QPixmap, QPainter, QColor, QFont, QImage
from PyQt5.QtWidgets import QStyle, QApplication
from ctypes import windll, wintypes

def _draw_badge_force(text, bg=(100,149,237), fg=(255,255,255), size=ICON_SIZE):
    """Create a simple badge icon (always non-null)."""
    pix = QPixmap(size, size)
    pix.fill(QColor(40, 40, 40))
    p = QPainter(pix)
    try:
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(QColor(*fg)); p.setBrush(QColor(*bg))
        m = max(4, size // 6); r = 6
        p.drawRoundedRect(m, m, size-2*m, size-2*m, r, r)
        f = QFont(); f.setBold(True); f.setPointSize(int(size*0.40))
        p.setFont(f); p.setPen(QColor(*fg))
        p.drawText(0, 0, size, size, Qt.AlignCenter, text)
    finally:
        p.end()
    return QIcon(pix)

def _badge_from_name_force(name, size=ICON_SIZE):
    n = (name or "").strip()
    if not n:
        return _draw_badge_force("APP", (128,128,128), (255,255,255), size)
    token = re.findall(r"[A-Za-z0-9]+", n)
    s = "".join(token)[:3].upper() or "APP"
    return _draw_badge_force(s, (100,149,237), (255,255,255), size)

def _parse_display_icon_value_force(val: str):
    if not val: return None, 0
    s = os.path.expandvars(str(val).strip()).strip('"').lstrip('@')
    m = re.search(r'^(.*?\.(?:exe|dll|ico))(.*)$', s, re.IGNORECASE)
    if m: path, rest = m.group(1), m.group(2)
    else: path, rest = s, ''
    idx = 0
    if ',' in rest:
        try: idx = int(rest.split(',')[-1].strip())
        except Exception: idx = 0
    elif ',' in s and not rest:
        try: path, idxs = s.rsplit(',', 1); idx = int(idxs.strip())
        except Exception: idx = 0
    return path.strip(), idx

def _exe_from_uninstall_string_force(uninstall_str: str):
    if not uninstall_str: return None
    s = os.path.expandvars(uninstall_str.strip().strip('"'))
    if 'msiexec' in s.lower():
        return os.path.expandvars(r"%SystemRoot%\\System32\\msi.dll")
    m = re.search(r'^\\s*\\"?([^\\"]*?\\.exe)\\"?(?:\\s+.*)?$', s, re.IGNORECASE)
    if m and os.path.exists(m.group(1)):
        return m.group(1)
    return None

def _find_any_exe_force(install_loc: str):
    if not install_loc or not os.path.isdir(install_loc): return None
    for root, dirs, files in os.walk(install_loc):
        for fn in files:
            if fn.lower().endswith('.exe'):
                return os.path.join(root, fn)
    return None

def _discord_candidates_force():
    base = os.path.expandvars(r"%LocalAppData%\\Discord")
    cands = []
    if os.path.isdir(base):
        try:
            for d in os.listdir(base):
                p = os.path.join(base, d, "Discord.exe")
                if os.path.isfile(p): cands.append(p)
        except Exception: pass
        p2 = os.path.join(base, "Discord.exe")
        if os.path.isfile(p2): cands.append(p2)
    return cands

def _brand_icon_override_force(app_name: str):
    n = (app_name or "").lower().strip()
    if "discord" in n:
        for p in _discord_candidates_force():
            ic = extract_icon(p, 0)
            if isinstance(ic, QIcon) and not ic.isNull():
                return ic
        return _draw_badge_force("DIS", (114,137,218), (255,255,255), ICON_SIZE)
    if "microsoft" in n and (".net" in n or " net" in n):
        return _draw_badge_force(".NET", (92,45,145), (255,255,255), ICON_SIZE)
    if ("microsoft" in n and "visual" in n and "c++" in n) or "visual c++" in n:
        return _draw_badge_force("VC++", (0,120,215), (255,255,255), ICON_SIZE)
    if "aura" in n and "service" in n:
        return _draw_badge_force("AURA", (208, 75, 162), (255,255,255), ICON_SIZE)
    if "game" in n and "sdk" in n and "service" in n:
        return _draw_badge_force("SDK", (0, 158, 73), (255,255,255), ICON_SIZE)
    return None

def resolve_icon_force_from_registry(subkey, display_name: str):
    # Brand override first
    ov = _brand_icon_override_force(display_name)
    if isinstance(ov, QIcon) and not ov.isNull():
        return ov

    # 1) DisplayIcon
    try:
        disp = winreg.QueryValueEx(subkey, "DisplayIcon")[0]
        path, idx = _parse_display_icon_value_force(disp)
        if path and os.path.exists(path):
            ic = extract_icon(path, idx)
            if isinstance(ic, QIcon) and not ic.isNull():
                return ic
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # 2) UninstallString / QuietUninstallString
    for valname in ("UninstallString", "QuietUninstallString"):
        try:
            uninst = winreg.QueryValueEx(subkey, valname)[0]
            exe = _exe_from_uninstall_string_force(uninst)
            if exe and os.path.exists(exe):
                ic = extract_icon(exe, 0)
                if isinstance(ic, QIcon) and not ic.isNull():
                    return ic
        except FileNotFoundError:
            pass
        except Exception:
            pass

    # 3) Any EXE inside InstallLocation
    try:
        iloc = winreg.QueryValueEx(subkey, "InstallLocation")[0]
        iloc = os.path.expandvars(str(iloc).strip().strip('"'))
        exe = _find_any_exe_force(iloc)
        if exe and os.path.exists(exe):
            ic = extract_icon(exe, 0)
            if isinstance(ic, QIcon) and not ic.isNull():
                return ic
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # 4) Fallback badge (guaranteed non-null)
    return _badge_from_name_force(display_name or "APP", ICON_SIZE)
# ====== End of Added Helpers ======



# ===================== ABOUT DIALOG =====================
class AboutDialog(QDialog):
    def __init__(self, parent=None, lang="en"):
        super().__init__(parent)
        self.setWindowTitle(translator.get("about", lang))
        self.setFixedSize(450, 300)
        self.lang = lang
        self.setStyleSheet("QDialog { border-radius: 12px; box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.5); }")
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Logo with animation
        logo_label = QLabel("PCFixUltimate")
        logo_label.setObjectName("logoLabel")
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        # Version
        version_label = QLabel(translator.get("version", lang))
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setFont(QFont("Segoe UI", 12))
        layout.addWidget(version_label)
        
        # Developer
        developer_label = QLabel(translator.get("developer", lang))
        developer_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(developer_label)
        
        # Email
        email_label = QLabel(translator.get("email", lang))
        email_label.setAlignment(Qt.AlignCenter)
        email_label.setStyleSheet("color: #1A73E8; text-decoration: underline;")
        email_label.mousePressEvent = lambda e: webbrowser.open("mailto:support@pcfixultimate.com")
        layout.addWidget(email_label)
        
        # Website
        website_label = QLabel(translator.get("website", lang))
        website_label.setAlignment(Qt.AlignCenter)
        website_label.setStyleSheet("color: #1A73E8; text-decoration: underline;")
        website_label.mousePressEvent = lambda e: webbrowser.open("https://www.pcfixultimate.com")
        layout.addWidget(website_label)
        
        # EULA
        eula_label = QLabel(translator.get("eula", lang))
        eula_label.setAlignment(Qt.AlignCenter)
        eula_label.setStyleSheet("font-weight: bold; margin-top: 15px;")
        layout.addWidget(eula_label)
        
        eula_text = QLabel(translator.get("eula_text", lang))
        eula_text.setWordWrap(True)
        eula_text.setAlignment(Qt.AlignCenter)
        layout.addWidget(eula_text)
        
        # Close button with animation
        close_button = QPushButton(translator.get("close", lang))
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)
        
        self.setLayout(layout)

# ===================== HELP DIALOG =====================
class HelpDialog(QDialog):
    def __init__(self, parent=None, lang="en"):
        super().__init__(parent)
        self.setWindowTitle(translator.get("help", lang))
        self.setFixedSize(500, 400)
        self.lang = lang
        self.setStyleSheet("QDialog { border-radius: 12px; box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.5); }")
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Logo
        logo_label = QLabel("PCFixUltimate")
        logo_label.setObjectName("logoLabel")
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        # Title
        help_title = QLabel(translator.get("user_manual", lang))
        help_title.setAlignment(Qt.AlignCenter)
        help_title.setStyleSheet("font-size: 16pt; font-weight: bold; margin: 10px;")
        layout.addWidget(help_title)
        
        # Text
        help_text = QLabel(translator.get("user_manual_text", lang))
        help_text.setWordWrap(True)
        help_text.setAlignment(Qt.AlignCenter)
        layout.addWidget(help_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        website_button = QPushButton(translator.get("visit_website", lang))
        website_button.clicked.connect(lambda: webbrowser.open("https://www.pcfixultimate.com/manual"))
        button_layout.addWidget(website_button)
        
        layout.addLayout(button_layout)
        
        # Close
        close_button = QPushButton(translator.get("close", lang))
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)
        
        self.setLayout(layout)

# ===================== CONTACT DIALOG =====================
class ContactDialog(QDialog):
    def __init__(self, parent=None, lang="en"):
        super().__init__(parent)
        self.setWindowTitle(translator.get("contact", lang))
        self.setFixedSize(450, 300)
        self.lang = lang
        self.setStyleSheet("QDialog { border-radius: 12px; box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.5); }")
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Logo
        logo_label = QLabel("PCFixUltimate")
        logo_label.setObjectName("logoLabel")
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        # Title
        contact_title = QLabel(translator.get("contact", lang))
        contact_title.setAlignment(Qt.AlignCenter)
        contact_title.setStyleSheet("font-size: 16pt; font-weight: bold; margin: 10px;")
        layout.addWidget(contact_title)
        
        # Email
        email_label = QLabel(translator.get("email", lang))
        email_label.setAlignment(Qt.AlignCenter)
        email_label.setStyleSheet("color: #1A73E8; text-decoration: underline;")
        email_label.mousePressEvent = lambda e: webbrowser.open("mailto:support@pcfixultimate.com")
        layout.addWidget(email_label)
        
        # Website
        website_label = QLabel(translator.get("website", lang))
        website_label.setAlignment(Qt.AlignCenter)
        website_label.setStyleSheet("color: #1A73E8; text-decoration: underline;")
        website_label.mousePressEvent = lambda e: webbrowser.open("https://www.pcfixultimate.com")
        layout.addWidget(website_label)
        
        # Support text
        support_label = QLabel("For technical support, please contact us via email or visit our website.")
        support_label.setWordWrap(True)
        support_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(support_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        email_button = QPushButton(translator.get("send_email", lang))
        email_button.clicked.connect(lambda: webbrowser.open("mailto:support@pcfixultimate.com"))
        button_layout.addWidget(email_button)
        
        website_button = QPushButton(translator.get("visit_website", lang))
        website_button.clicked.connect(lambda: webbrowser.open("https://www.pcfixultimate.com"))
        button_layout.addWidget(website_button)
        
        layout.addLayout(button_layout)
        
        # Close
        close_button = QPushButton(translator.get("close", lang))
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)
        
        self.setLayout(layout)

# ===================== LICENSE INFO DIALOG =====================
class LicenseInfoDialog(QDialog):
    def __init__(self, parent=None, lang="en", is_licensed=False, is_trial=False):
        super().__init__(parent)
        self.setWindowTitle(translator.get("license_info", lang))
        self.setFixedSize(450, 350)
        self.lang = lang
        self.is_licensed = is_licensed
        self.is_trial = is_trial
        self.setStyleSheet("QDialog { border-radius: 12px; box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.5); }")
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Subscription type
        sub_type = translator.get("purchased", lang) if is_licensed else (translator.get("trial_24h", lang) if is_trial else translator.get("none", lang))
        sub_label = QLabel(f"{translator.get('subscription_type', lang)} {sub_type}")
        sub_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(sub_label)
        
        # Time remaining if trial
        if is_trial:
            remaining_hours = get_remaining_trial_time()
            time_label = QLabel(f"{translator.get('time_remaining', lang)} {remaining_hours:.1f} hours")
            time_label.setFont(QFont("Segoe UI", 10))
            layout.addWidget(time_label)
        
        # Locked tools status
        status_label = QLabel(translator.get("locked_tools_status", lang))
        status_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(status_label)
        
        tools_status = QTextEdit()
        tools_status.setReadOnly(True)
        tools_status.setText(translator.get("pc_repair_locked", lang) if not is_licensed else "All tools unlocked.")
        layout.addWidget(tools_status)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        activate_button = QPushButton(translator.get("activate", lang))
        activate_button.clicked.connect(parent.show_license_dialog)
        button_layout.addWidget(activate_button)
        
        purchase_button = QPushButton(translator.get("purchase", lang))
        purchase_button.clicked.connect(lambda: webbrowser.open("https://www.pcfixultimate.com/purchase"))
        button_layout.addWidget(purchase_button)
        
        close_button = QPushButton(translator.get("close", lang))
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)

# ===================== LICENSE DIALOG =====================
class LicenseDialog(QDialog):
    def __init__(self, parent=None, lang="en"):
        super().__init__(parent)
        self.setWindowTitle(translator.get("license_activation", lang))
        self.setFixedSize(500, 280)
        self.lang = lang
        self.license_key = ""
        self.setStyleSheet("""
            QDialog { 
                background-color: #0A0A0A; 
                color: #E0E0E0; 
                border-radius: 12px; 
                box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.5); 
            }
            QLabel {
                color: #E0E0E0;
                padding: 5px;
            }
            QPushButton {
                background-color: #1A73E8;
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1662C9;
            }
            QLineEdit {
                background-color: #141414;
                color: #E0E0E0;
                border: 2px solid #1F1F1F;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header with gradient background
        header = QLabel(translator.get("license_activation", lang))
        header.setStyleSheet("""
            QLabel {
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 #1A73E8, stop: 1 #34A853);
                color: white;
                font-size: 16pt;
                font-weight: bold;
                padding: 15px;
                border-radius: 8px;
            }
        """)
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        label = QLabel(translator.get("enter_license_key", lang))
        label.setWordWrap(True)
        label.setFont(QFont("Segoe UI", 10))
        layout.addWidget(label)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter license key here (e.g., PCFX-XXXX-XXXX-XXXX)")
        self.key_input.setFont(QFont("Segoe UI", 10))
        layout.addWidget(self.key_input)
        
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        activate_button = QPushButton(translator.get("activate", lang))
        activate_button.clicked.connect(self.activate)
        button_layout.addWidget(activate_button)
        
        buy_button = QPushButton(translator.get("buy_license", lang))
        buy_button.clicked.connect(lambda: webbrowser.open("https://www.pcfixultimate.com/purchase"))
        button_layout.addWidget(buy_button)
        
        cancel_button = QPushButton(translator.get("cancel", lang))
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def activate(self):
        self.license_key = self.key_input.text().strip()
        if not self.license_key:
            QMessageBox.warning(self, "Error", "Please enter a license key.")
            return
        success, message = activate_license_offline(self.license_key)
        if success:
            QMessageBox.information(self, "Success", message)
            self.accept()
        else:
            QMessageBox.critical(self, "Error", message)


# ===================== WORKER THREAD =====================
class WorkerThread(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str, str)
    report_signal = pyqtSignal(str, str)
    repair_time_signal = pyqtSignal(str)
    repair_stage_signal = pyqtSignal(int)

    def __init__(self, task, *args, **kwargs):
        super().__init__()
        self.task = task
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            report = ""
            if self.task == "clean_temp": report = self.clean_temp_files()
            elif self.task == "empty_recycle": report = self.empty_recycle_bin()
            elif self.task == "clean_registry": report = self.clean_registry()
            elif self.task == "optimize_performance": report = self.optimize_performance()
            elif self.task == "ultimate_performance": report = self.add_ultimate_performance_plan()
            elif self.task == "memory_clean": report = self.clean_memory_cache()
            elif self.task == "uninstall_app": report = self.complete_uninstall(self.args[0])
            elif self.task == "disk_cleanup": report = self.disk_cleanup()
            elif self.task == "system_repair": report = self.system_repair()
            elif self.task == "reset_network": report = self.reset_network()
            elif self.task == "network_optimize": report = self.optimize_network()
            elif self.task == "deep_clean": report = self.deep_system_clean()
            elif self.task == "check_disk": report = self.check_disk()

            self.report_signal.emit(self.task, report)
            self.finished_signal.emit("success", report)
        except Exception as e:
            error_msg = f"Error in task '{self.task}': {str(e)}"
            self.update_signal.emit(error_msg)
            self.report_signal.emit(self.task, error_msg)
            self.finished_signal.emit("error", error_msg)

    def clean_temp_files(self):
        self.update_signal.emit(translator.get("scanning", self.kwargs.get('lang', 'en')))
        temp_dirs = {
            "Windows Temp": os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Temp'),
            "User Temp": os.environ.get('TEMP', ''),
            "System Prefetch": r'C:\Windows\Prefetch'
        }
        cleaned_size = 0; total_files = 0; failed_deletions = 0
        report_lines = [f"🧹 {translator.get('clean_temp', self.kwargs.get('lang', 'en'))} Report", "="*40]
        for name, temp_dir in temp_dirs.items():
            if os.path.exists(temp_dir):
                self.update_signal.emit(f"{translator.get('cleaning', self.kwargs.get('lang', 'en'))}: {name}")
                deleted_in_folder = 0
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            file_size = os.path.getsize(file_path)
                            os.remove(file_path); cleaned_size += file_size; total_files += 1; deleted_in_folder += 1
                        except (OSError, PermissionError): failed_deletions += 1
                report_lines.append(f"\n- Folder: {name}\n  - Deleted {deleted_in_folder} files.")
        if failed_deletions > 0: report_lines.append(f"\n⚠️ Could not delete {failed_deletions} files (in use).")
        cleaned_mb = cleaned_size / (1024 * 1024)
        summary = f"\n📊 Summary:\n{translator.get('cleaned_files', self.kwargs.get('lang', 'en'), total_files)}\n" \
                  f"{translator.get('freed_space', self.kwargs.get('lang', 'en'), f'{cleaned_mb:.2f}')}"
        report_lines.append(summary)
        return "\n".join(report_lines)

    def empty_recycle_bin(self):
        self.update_signal.emit(translator.get("cleaning", self.kwargs.get('lang', 'en')))
        try:
            import winshell
            if not list(winshell.recycle_bin()): return translator.get("recycle_bin_empty", self.kwargs.get('lang', 'en'))
            winshell.recycle_bin().empty(confirm=False, show_progress=False, sound=False)
            return "✅ Recycle bin emptied successfully"
        except Exception as e: return f"❌ Failed to empty recycle bin: {str(e)}"

    def clean_memory_cache(self):
        self.update_signal.emit("Cleaning memory cache...")
        try:
            mem_before = psutil.virtual_memory().available
            ctypes.windll.psapi.EmptyWorkingSet.argtypes = [ctypes.c_void_p]; ctypes.windll.psapi.EmptyWorkingSet.restype = ctypes.c_int
            for proc in psutil.process_iter(['pid']):
                try:
                    handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, proc.info['pid'])
                    if handle: ctypes.windll.psapi.EmptyWorkingSet(handle); ctypes.windll.kernel32.CloseHandle(handle)
                except (psutil.NoSuchProcess, psutil.AccessDenied): continue
            mem_after = psutil.virtual_memory().available
            freed_mb = (mem_after - mem_before) / (1024 * 1024)
            if freed_mb < 0: freed_mb = 0
            lang = self.kwargs.get('lang', 'en')
            title = translator.get("memory_clean_report_title", lang)
            body = translator.get("memory_clean_report_body", lang, f'{mem_before / (1024 * 1024):.2f}', f'{mem_after / (1024 * 1024):.2f}', f'{freed_mb:.2f}')
            return f"🧠 {title} 🧠\n\n{body}"
        except Exception as e: return f"❌ Failed to clean memory cache: {str(e)}"

    def optimize_network(self):
        self.update_signal.emit("Optimizing network...")
        try:
            commands = {"autotuninglevel": "netsh int tcp set global autotuninglevel=normal", "rss": "netsh int tcp set global rss=enabled", "netdma": "netsh int tcp set global netdma=enabled"}
            for key, cmd in commands.items(): subprocess.run(cmd, shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            lang = self.kwargs.get('lang', 'en')
            title = translator.get("network_optimization_report_title", lang)
            body = translator.get("network_optimization_report_body", lang)
            return f"🌐 {title} 🌐\n\n{body}"
        except Exception as e: return f"❌ Network optimization failed: {str(e)}"

    def deep_system_clean(self):
        self.update_signal.emit("Running deep system clean...")
        report_lines = [f"🧹 {translator.get('system_cleaner', self.kwargs.get('lang', 'en'))} Report", "="*30]
        dirs_to_clean = {
            "Software Distribution": os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SoftwareDistribution', 'Download'),
            "Internet Cache": os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Windows', 'INetCache'),
        }
        cleaned_files_total = 0
        for name, dir_path in dirs_to_clean.items():
            if os.path.exists(dir_path):
                cleaned_count = 0
                for root, dirs, files in os.walk(dir_path):
                    for file in files:
                        try: os.remove(os.path.join(root, file)); cleaned_files_total += 1; cleaned_count += 1
                        except: pass
                report_lines.append(f"\n- Removed {cleaned_count} files from {name}.")
        summary = f"\n📊 Summary:\n{translator.get('deep_clean_completed', self.kwargs.get('lang', 'en'), cleaned_files_total)}"
        report_lines.append(summary)
        return "\n".join(report_lines)

    def disk_cleanup(self):
        self.update_signal.emit("Configuring and running Disk Cleanup...")
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
            items_to_clean = ["Temporary Files", "Recycle Bin", "Thumbnails", "Update Cleanup", "Temporary Internet Files", "Delivery Optimization Files"]
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as base_key:
                for item in items_to_clean:
                    try:
                        with winreg.CreateKey(base_key, item) as item_key: winreg.SetValueEx(item_key, "StateFlags0001", 0, winreg.REG_DWORD, 2)
                    except OSError: continue
            subprocess.run('cleanmgr.exe /sagerun:1', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return translator.get("disk_cleanup_completed", self.kwargs.get('lang', 'en'))
        except Exception as e: return f"❌ Disk cleanup failed: {str(e)}"

    def system_repair(self):
        lang = self.kwargs.get('lang', 'en')
        report_lines = ["🛠️ System Repair Summary", "="*28]
        
        # Stage 1: SFC scan
        self.repair_stage_signal.emit(1)
        self.update_signal.emit(translator.get("repair_stage_1", lang))
        try:
            process = subprocess.Popen('sfc /scannow', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                report_lines.append("✅ SFC scan completed successfully. No integrity violations found.")
            else:
                report_lines.append("⚠️ SFC scan found and repaired some issues.")
        except Exception as e:
            report_lines.append(f"❌ SFC scan failed: {str(e)}")
        
        # Stage 2: DISM scan health
        self.repair_stage_signal.emit(2)
        self.update_signal.emit(translator.get("repair_stage_2", lang))
        try:
            process = subprocess.Popen('DISM /Online /Cleanup-Image /ScanHealth', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                report_lines.append("✅ DISM scan completed successfully. Component store is repairable.")
            else:
                report_lines.append("⚠️ DISM scan found some issues with the component store.")
        except Exception as e:
            report_lines.append(f"❌ DISM scan failed: {str(e)}")
        
        # Stage 3: DISM restore health
        self.repair_stage_signal.emit(3)
        self.update_signal.emit(translator.get("repair_stage_3", lang))
        try:
            process = subprocess.Popen('DISM /Online /Cleanup-Image /RestoreHealth', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                report_lines.append("✅ DISM restore completed successfully. Component store was restored.")
            else:
                report_lines.append("⚠️ DISM restore encountered issues.")
        except Exception as e:
            report_lines.append(f"❌ DISM restore failed: {str(e)}")
        
        # Stage 4: Final checks
        self.repair_stage_signal.emit(4)
        self.update_signal.emit(translator.get("repair_stage_4", lang))
        report_lines.append("✅ System repair process completed.")
            
        return "\n".join(report_lines)

    def clean_registry(self):
        self.update_signal.emit(translator.get("cleaning", self.kwargs.get('lang', 'en')))
        report_lines = [f"🔍 {translator.get('clean_registry', self.kwargs.get('lang', 'en'))} Report"]; issues_fixed = 0
        registry_keys = [r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"]
        for key_path in registry_keys:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as reg_key:
                    report_lines.append(f"- Cleaning key: {key_path}")
                    while True:
                        try: value_name, _, _ = winreg.EnumValue(reg_key, 0); winreg.DeleteValue(reg_key, value_name); issues_fixed += 1
                        except OSError: break
            except FileNotFoundError: pass
            except Exception as e: report_lines.append(f"❌ Error cleaning registry: {str(e)}")
        report_lines.append(f"\n📊 {translator.get('fixed_issues', self.kwargs.get('lang', 'en'), issues_fixed)}")
        return "\n".join(report_lines)

    def optimize_performance(self):
        self.update_signal.emit(translator.get("optimizing", self.kwargs.get('lang', 'en')))
        report_lines = [f"⚡ {translator.get('optimize', self.kwargs.get('lang', 'en'))} Report", "\n- Flushing DNS..."]
        subprocess.run(['ipconfig', '/flushdns'], capture_output=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        report_lines.append("  ✅ DNS flushed.")
        if os.path.exists(r'C:\Windows\Prefetch'):
            report_lines.append("- Cleaning Prefetch folder...")
            deleted_count = 0
            for file in os.listdir(r'C:\Windows\Prefetch'):
                if file.endswith('.pf'):
                    try: os.remove(os.path.join(r'C:\Windows\Prefetch', file)); deleted_count += 1
                    except (OSError, PermissionError): pass
            report_lines.append(f"  ✅ Deleted {deleted_count} prefetch files.")
        report_lines.append("- Disabling non-essential services...")
        for service in ["SysMain", "DiagTrack"]:
            try:
                subprocess.run(f'sc config {service} start= disabled', shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                subprocess.run(f'sc stop {service}', shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                report_lines.append(f"  ✅ Disabled service: {service}")
            except Exception: pass
        report_lines.append(f"\n📊 {translator.get('completed', self.kwargs.get('lang', 'en'))}")
        return "\n".join(report_lines)

    def add_ultimate_performance_plan(self):
        self.update_signal.emit(translator.get("optimizing", self.kwargs.get('lang', 'en')))
        report_lines = [f"🔋 {translator.get('ultimate_perf', self.kwargs.get('lang', 'en'))} Report"]
        try:
            guid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
            result = subprocess.run(f'powercfg -duplicatescheme {guid}', capture_output=True, text=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode == 0: report_lines.append("\n✅ Ultimate Performance power plan added successfully.")
            else: report_lines.append(f"\n⚠️ Could not add power plan (may already exist or not supported).")
            return "\n".join(report_lines)
        except Exception as e: return f"\n❌ Operation failed: {str(e)}"

    def reset_network(self):
        self.update_signal.emit(translator.get("repairing", self.kwargs.get('lang', 'en')))
        report_lines = [f"🌐 {translator.get('reset_network', self.kwargs.get('lang', 'en'))} Report", "\n- Resetting network components..."]
        try:
            subprocess.run('ipconfig /flushdns', capture_output=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run('netsh winsock reset', capture_output=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            report_lines.append("  ✅ Network reset complete. A restart is recommended.")
            return "\n".join(report_lines)
        except Exception as e: return f"\n❌ Network reset failed: {str(e)}"

    def complete_uninstall(self, app_name):
        # This is a complex operation and remains unchanged for stability
        self.update_signal.emit(translator.get("uninstalling", self.kwargs.get('lang', 'en')))
        report_lines = [f"❌ {translator.get('complete_uninstall', self.kwargs.get('lang', 'en'))}: {app_name}"]
        try:
            uninstall_cmd = None; install_location = ""
            reg_paths = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"), (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"), (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")]
            for hkey, path in reg_paths:
                try:
                    with winreg.OpenKey(hkey, path) as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    if winreg.QueryValueEx(subkey, "DisplayName")[0] == app_name:
                                        uninstall_cmd = winreg.QueryValueEx(subkey, "UninstallString")[0]
                                        install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                                        break
                            except WindowsError: continue
                except FileNotFoundError: continue
                if uninstall_cmd: break
            if uninstall_cmd:
                process = subprocess.Popen(uninstall_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                process.wait()
                report_lines.append(f"\n- Uninstaller executed.")
                if install_location and os.path.exists(install_location):
                    try: shutil.rmtree(install_location); report_lines.append(f"- Deleted installation directory: {install_location}")
                    except Exception: report_lines.append(f"- ⚠️ Could not delete directory (in use): {install_location}")
                report_lines.append(f"\n{translator.get('uninstall_complete', self.kwargs.get('lang', 'en'))}")
            else: report_lines.append(f"\n❌ Uninstall command not found for {app_name}")
            return "\n".join(report_lines)
        except Exception as e: return f"❌ Uninstallation failed: {str(e)}"

    def check_disk(self):
        self.update_signal.emit("Checking disk...")
        report_lines = [f"💾 {translator.get('check_disk', self.kwargs.get('lang', 'en'))} Report"]
        try:
            process = subprocess.Popen('chkdsk C: /scan', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            stdout, stderr = process.communicate()
            if process.returncode == 0: report_lines.append("\n✅ Disk check completed successfully. No issues found.")
            else:
                issues_found = len(re.findall(r'error|bad sector', stdout.lower()))
                report_lines.append(f"\n⚠️ Disk check found {issues_found} issues.")
            return "\n".join(report_lines)
        except Exception as e: return f"❌ Disk check failed: {str(e)}"

# ===================== SYSTEM TOOL THREAD =====================
class SystemToolThread(QThread):
    finished_signal = pyqtSignal(str, bool)  # tool_name, success

    def __init__(self, tool_name):
        super().__init__()
        self.tool_name = tool_name

    def run(self):
        try:
            # For Device Manager specifically, use a different approach to avoid freezing
            if self.tool_name == "devmgmt.msc":
                # Use a more robust method to open Device Manager
                subprocess.Popen('mmc devmgmt.msc', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            elif self.tool_name.endswith(('.msc', '.cpl')):
                os.startfile(self.tool_name)
            else:
                subprocess.Popen(self.tool_name, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self.finished_signal.emit(self.tool_name, True)
        except Exception as e:
            self.finished_signal.emit(f"Could not open {self.tool_name}: {str(e)}", False)

# ===================== SUMMARY DIALOG =====================
class SummaryDialog(QDialog):
    def __init__(self, title, summary_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Task Summary")
        self.setFixedSize(450, 250)
        self.setModal(True)
        self.setStyleSheet("QDialog { border-radius: 12px; box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.5); }")
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        title_label = QLabel(f"✅ {title}")
        title_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title_label.setStyleSheet("color: #34A853; margin-bottom: 10px;")
        title_label.setAlignment(Qt.AlignCenter)
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setText(summary_text)
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(title_label); layout.addWidget(self.summary_text); layout.addWidget(ok_button)
        self.setLayout(layout)

# ===================== PROGRESS DIALOG =====================
class ProgressDialog(QDialog):
    def __init__(self, parent=None, title="Processing", lang="en", show_note=False):
        super().__init__(parent)
        self.setWindowTitle(title); self.setFixedSize(400, 150 if show_note else 120); self.lang = lang
        self.setStyleSheet("QDialog { border-radius: 12px; box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.5); }")
        layout = QVBoxLayout(); layout.setSpacing(15); layout.setContentsMargins(20, 20, 20, 20)
        self.label = QLabel(translator.get("processing", lang))
        self.label.setAlignment(Qt.AlignCenter); self.progress = QProgressBar()
        self.progress.setRange(0, 0); self.progress.setTextVisible(False)
        self.details = QLabel("..."); self.details.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.label); layout.addWidget(self.progress); layout.addWidget(self.details)
        
        if show_note:
            self.note_label = QLabel(translator.get("long_operation_note", lang))
            self.note_label.setAlignment(Qt.AlignCenter)
            self.note_label.setStyleSheet("color: #FFC107; font-style: italic;")
            layout.addWidget(self.note_label)
            
        self.setLayout(layout)
    def update_progress(self, message): self.details.setText(message)

# ===================== SYSTEM REPAIR DIALOG =====================
class SystemRepairDialog(QDialog):
    def __init__(self, parent=None, lang="en"):
        super().__init__(parent)
        self.setWindowTitle(translator.get("sys_repair", lang)); self.setFixedSize(500, 250); self.lang = lang
        self.setStyleSheet("QDialog { border-radius: 12px; box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.5); }")
        layout = QVBoxLayout(); layout.setSpacing(15); layout.setContentsMargins(20, 20, 20, 20); self.setModal(True); 
        
        # Stage labels
        self.stage_label = QLabel("Starting repair process...")
        self.stage_label.setAlignment(Qt.AlignCenter); self.stage_label.setFont(QFont("Segoe UI", 12))
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 4)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Stage %v of 4")
        
        # Time remaining
        self.time_label = QLabel("10:00"); self.time_label.setAlignment(Qt.AlignCenter)
        self.time_label.setFont(QFont("Segoe UI", 24, QFont.Bold)); self.time_label.setStyleSheet("color: #34A853;")
        self.time_caption_label = QLabel(translator.get("repair_time_remaining", lang, "").replace(": {}", ""))
        self.time_caption_label.setAlignment(Qt.AlignCenter); self.time_caption_label.setFont(QFont("Segoe UI", 10))
        
        # Note
        self.note_label = QLabel(translator.get("long_operation_note", lang))
        self.note_label.setAlignment(Qt.AlignCenter)
        self.note_label.setStyleSheet("color: #FFC107; font-style: italic;")
        self.note_label.setWordWrap(True)
        
        layout.addWidget(self.stage_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.time_label)
        layout.addWidget(self.time_caption_label)
        layout.addWidget(self.note_label)
        self.setLayout(layout)
        
    def update_repair_time(self, time_str):
        if translator.get("completed", self.lang) in time_str: 
            self.time_label.setText("✅"); 
            self.time_caption_label.setText(translator.get("completed", self.lang))
        else: 
            self.time_label.setText(time_str.split(": ")[-1])
            
    def update_stage(self, stage_num):
        self.progress_bar.setValue(stage_num)
        stages = [
            translator.get("repair_stage_1", self.lang),
            translator.get("repair_stage_2", self.lang),
            translator.get("repair_stage_3", self.lang),
            translator.get("repair_stage_4", self.lang)
        ]
        if 0 <= stage_num - 1 < len(stages):
            self.stage_label.setText(stages[stage_num - 1])

# ===================== TRIAL AND LICENSE FUNCTIONS (SECURE VERSION) =====================
import hmac, hashlib, json, time, winreg
from datetime import datetime, timedelta

SECRET_KEY = b"PCFixUltimateSecretKey987"  # غيّرها لأي مفتاح خاص فيك
TRIAL_DAYS = 3

def _get_trial_info():
    try:
        reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\PCFixUltimate", 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(reg, "trial_data")
        winreg.CloseKey(reg)
        data = json.loads(val)
        return data
    except Exception:
        return None

def _save_trial_info(start_time):
    data = {"start": start_time}
    sig = hmac.new(SECRET_KEY, str(start_time).encode(), hashlib.sha256).hexdigest()
    data["sig"] = sig
    reg = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\PCFixUltimate")
    winreg.SetValueEx(reg, "trial_data", 0, winreg.REG_SZ, json.dumps(data))
    winreg.CloseKey(reg)

def _verify_trial_info(data):
    if not data:
        return False
    start_time = data.get("start")
    sig = data.get("sig")
    expected_sig = hmac.new(SECRET_KEY, str(start_time).encode(), hashlib.sha256).hexdigest()
    return sig == expected_sig

def start_trial():
    now = int(time.time())
    _save_trial_info(now)
    return now

def is_trial_active():
    data = _get_trial_info()
    if not _verify_trial_info(data):
        # أول تشغيل أو تم التلاعب بالبيانات
        start_trial()
        return True
    start_time = int(data.get("start"))
    days_passed = (int(time.time()) - start_time) // (24 * 3600)
    return days_passed < TRIAL_DAYS

def get_remaining_trial_time():
    data = _get_trial_info()
    if not _verify_trial_info(data):
        return TRIAL_DAYS * 24
    start_time = int(data.get("start"))
    elapsed = int(time.time()) - start_time
    remaining = TRIAL_DAYS * 24 * 3600 - elapsed
    return max(0, remaining / 3600)

def get_machine_id():
    """الحصول على معرف فريد للجهاز باستخدام WMI."""
    try:
        c = wmi.WMI()
        system_uuid = c.Win32_ComputerSystemProduct()[0].UUID
        if system_uuid:
            return system_uuid
        else:
            return str(uuid.getnode())
    except Exception:
        return str(uuid.getnode())

def load_license():
    """تحميل مفتاح الترخيص من الملف."""
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, 'r') as f:
            return f.read().strip()
    return None

def save_license(license_key):
    """حفظ مفتاح الترخيص في الملف."""
    with open(LICENSE_FILE, 'w') as f:
        f.write(license_key)


def _sha256_of_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _verify_signature_with_public_key(public_pem: bytes, message: bytes, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(public_pem)
        sig = base64.b64decode(signature_b64)
        pub.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

# ===================== MAIN APP CLASS =====================
class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_lang = "en"
        self.load_settings()
        
        # التحقق من الترخيص أو فترة التجربة
        self.is_licensed = False
        self.is_trial = False
        if not self.check_license_or_trial():
            sys.exit(0)
        
        self.initUI()
        self.apply_language()
        if self.is_trial:
            self.show_trial_message()
        
        # Timer لتحديث الوقت المتبقي كل دقيقة
        self.trial_timer = QTimer(self)
        self.trial_timer.timeout.connect(self.update_trial_status)
        self.trial_timer.start(60000)  # 60 ثانية

    def check_license_or_trial(self):
        """التحقق من الترخيص أو فترة التجربة."""
        license_key = load_license()
        if license_key:
            valid, message = verify_license_token(license_key)
            if valid:
                self.is_licensed = True
                return True
            else:
                QMessageBox.critical(self, translator.get("update_error", self.current_lang), message)
        
        if is_trial_active():
            self.is_trial = True
            return True
        else:
            # عرض حوار التفعيل
            dialog = LicenseDialog(self, self.current_lang)
            if dialog.exec_() == QDialog.Accepted:
                self.is_licensed = True
                return True
            else:
                QMessageBox.critical(self, translator.get("update_error", self.current_lang), translator.get("trial_expired", self.current_lang))
                return False

    def show_trial_message(self):
        """عرض رسالة وضع التجربة."""
        QMessageBox.information(self, translator.get("trial_mode", self.current_lang), translator.get("trial_active", self.current_lang))

    def update_trial_status(self):
        if self.is_trial:
            remaining_hours = get_remaining_trial_time()
            if remaining_hours <= 0:
                self.is_trial = False
                QMessageBox.critical(self, translator.get("trial_mode", self.current_lang), translator.get("trial_expired", self.current_lang))
                webbrowser.open("https://www.pcfixultimate.com/purchase")
                self.close()
            else:
                status_text = translator.get("trial_expires_in", self.current_lang, f"{remaining_hours:.1f}")
                self.statusBar().showMessage(status_text)
        elif self.is_licensed:
            self.statusBar().showMessage(translator.get("licensed", self.current_lang))

    def show_license_info(self):
        dialog = LicenseInfoDialog(self, self.current_lang, self.is_licensed, self.is_trial)
        dialog.exec_()

    def show_about(self):
        about_dialog = AboutDialog(self, self.current_lang)
        about_dialog.exec_()
        
    def show_help(self):
        help_dialog = HelpDialog(self, self.current_lang)
        help_dialog.exec_()
        
    def show_license_dialog(self):
        dialog = LicenseDialog(self, self.current_lang)
        if dialog.exec_() == QDialog.Accepted:
            self.is_licensed = True
            self.is_trial = False
            self.apply_language()  # إعادة تحميل لفتح الميزات
            self.update_trial_status()
            self.update_license_status_display()

    def check_for_updates(self):
        import requests, os, tempfile, subprocess, hashlib, json
        updates_url = "https://ameero197-dotcom.github.io/pcfixultimate/latest.json"
        APP_VERSION = "1.0.1"

        def parse_ver(v): return tuple(int(p) for p in str(v).split("."))
        def sha256_of_file(path):
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024*1024), b""):
                    h.update(chunk)
            return h.hexdigest()

        def have_public_key():
            try:
                return bool(PUBLIC_KEY_PEM and PUBLIC_KEY_PEM.strip())
            except NameError:
                return False

        try:
            # 1) latest.json
            r = requests.get(
                updates_url, timeout=15,
                headers={"User-Agent": "PCFixUltimate-Updater/1.0"}
            )
            r.raise_for_status()
            info = r.json()

            latest = info.get("version")
            url    = info.get("url")
            sha    = info.get("sha256")
            sig_b64= info.get("signature")

            if not latest or not url:
                QMessageBox.critical(self, translator.get("update_error", self.current_lang), translator.get("invalid_latest", self.current_lang))
                return

            if parse_ver(latest) <= parse_ver(APP_VERSION):
                QMessageBox.information(self, translator.get("up_to_date", self.current_lang), translator.get("up_to_date", self.current_lang))
                return

            # 2) نزّل الملف (نحفظه باسم واضح في نفس مجلد البرنامج لرؤيته بسهولة)
            out_path = os.path.join(os.getcwd(), f"PCFixUltimateSetup_{latest}.exe")
            dl = requests.get(url, stream=True, timeout=60, headers={"User-Agent": "PCFixUltimate-Updater/1.0"})
            print(f"Downloading installer from: {url}")
            dl.raise_for_status()

            total = 0
            with open(out_path, "wb") as f:
                for chunk in dl.iter_content(1024 * 256):
                    if chunk:
                        f.write(chunk)
                        total += len(chunk)

            # 3) تحقق SHA
            got = sha256_of_file(out_path)
            if sha and got.lower() != sha.lower():
                try: os.remove(out_path)
                except: pass
                QMessageBox.critical(self, translator.get("update_error", self.current_lang), translator.get("hash_mismatch", self.current_lang))
                return

            # 4) تحقق التوقيع (إن وُجد مفتاح عام وتوقيع)
            if have_public_key() and sig_b64 and sha:
                if not _verify_signature_with_public_key(PUBLIC_KEY_PEM, sha.encode("utf-8"), sig_b64):
                    try: os.remove(out_path)
                    except: pass
                    QMessageBox.critical(self, translator.get("update_error", self.current_lang), translator.get("invalid_signature", self.current_lang))
                    return

            # 5) اسأل المستخدم إذا يريد التثبيت الآن
            reply = QMessageBox.question(self, translator.get("update_available", self.current_lang), translator.get("update_downloaded", self.current_lang), QMessageBox.Yes | QMessageBox.No)

            if reply == QMessageBox.Yes:
                # شغّل المحدث وأغلق البرنامج
                try:
                    os.startfile(out_path)
                except Exception:
                    subprocess.Popen(f'"{out_path}"', shell=True)
                QApplication.quit()
            else:
                # أخبره أين الملف
                QMessageBox.information(self, translator.get("update_available", self.current_lang), translator.get("update_saved", self.current_lang, out_path))

        except requests.exceptions.RequestException as e:
            QMessageBox.warning(self, translator.get("update_error", self.current_lang), translator.get("network_error", self.current_lang))
        except Exception as e:
            QMessageBox.warning(self, translator.get("update_error", self.current_lang), f"{type(e).__name__}: {e}")

    def initUI(self):
        self.setWindowTitle(translator.get("app_title", self.current_lang))
        self.setGeometry(100, 100, 1200, 700)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget); main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        
        # Menu bar
        self.create_menu_bar()
        
        # Header with logo and license status
        header_layout = QHBoxLayout()
        
        # Logo container
        logo_container = QWidget()
        logo_container.setObjectName("logoContainer")
        logo_layout = QHBoxLayout(logo_container)
        logo_layout.setContentsMargins(4, 4, 4, 4)
        
        # 3D logo
        self.logo_label = QLabel("PCFixUltimate")
        self.logo_label.setObjectName("logoLabel")
        self.logo_label.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(self.logo_label)
        
        header_layout.addWidget(logo_container)
        header_layout.addStretch()
        
        # License status label
        self.license_status_label = QLabel()
        self.license_status_label.setObjectName("licenseStatus")
        self.license_status_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(self.license_status_label)
        
        main_layout.addLayout(header_layout)
        
        self.tabs = QTabWidget(); main_layout.addWidget(self.tabs)
        self.create_dashboard_tab(); self.create_performance_tab(); self.create_pc_repair_tab()
        self.create_uninstaller_tab(); self.create_tools_tab(); self.create_cleaner_tab()
        self.create_reports_tab(); self.create_settings_tab()
        self.timer = QTimer(self); self.timer.timeout.connect(self.update_hw_monitor)
        self.timer.start(2000); self.reports = {}; self.system_tool_threads = []
        
        # Position logo
        self.position_logo()
        
        # Update license status
        self.update_license_status_display()
        
        # Status bar
        self.statusBar().setStyleSheet("QStatusBar { background-color: #141414; color: #E0E0E0; border-top: 1px solid #1F1F1F; padding: 3px; }")
        self.update_trial_status()

    def update_license_status_display(self):
        """تحديث عرض حالة الترخيص في واجهة المستخدم."""
        if self.is_licensed:
            self.license_status_label.setText(translator.get("full_version", self.current_lang))
            self.license_status_label.setProperty("licensed", "true")
        elif self.is_trial:
            remaining_hours = get_remaining_trial_time()
            self.license_status_label.setText(f"{translator.get('trial_version', self.current_lang)} ({remaining_hours:.1f}h)")
            self.license_status_label.setProperty("trial", "true")
        self.license_status_label.style().unpolish(self.license_status_label)
        self.license_status_label.style().polish(self.license_status_label)

    def create_menu_bar(self):
        menu_bar = self.menuBar()
        menu_bar.clear()  # Clear existing menu to allow recreation
        
        # File menu
        file_menu = menu_bar.addMenu(translator.get("file", self.current_lang))
        
        exit_action = QAction(translator.get("exit", self.current_lang), self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # License Info action
        license_info_action = QAction(translator.get("license_info", self.current_lang), self)
        license_info_action.triggered.connect(self.show_license_info)
        menu_bar.addAction(license_info_action)
        
        # Activate action
        activate_action = QAction(translator.get("activate_program", self.current_lang), self)
        activate_action.triggered.connect(self.show_license_dialog)
        menu_bar.addAction(activate_action)
        
        # Help menu
        help_menu = menu_bar.addMenu(translator.get("help", self.current_lang))
        
        about_action = QAction(translator.get("about", self.current_lang), self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        help_action = QAction(translator.get("help", self.current_lang), self)
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
        
        # Add Check for Updates
        check_updates_action = QAction(translator.get("check_updates", self.current_lang), self)
        check_updates_action.triggered.connect(self.check_for_updates)
        help_menu.addAction(check_updates_action)
        
    def position_logo(self):
        if self.current_lang == "ar":
            self.logo_label.setAlignment(Qt.AlignRight)
            self.logo_label.parentWidget().layout().setAlignment(Qt.AlignRight)
        else:
            self.logo_label.setAlignment(Qt.AlignLeft)
            self.logo_label.parentWidget().layout().setAlignment(Qt.AlignLeft)
            
    def create_dashboard_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, translator.get("system_tab", self.current_lang)); layout = QGridLayout(); layout.setSpacing(15)
        hw_group = QGroupBox(translator.get("hw_monitor", self.current_lang)); hw_layout = QGridLayout()
        hw_group.setLayout(hw_layout); self.cpu_progress = QProgressBar(); self.ram_progress = QProgressBar()
        self.gpu_progress = QProgressBar(); self.disk_progress = QProgressBar(); self.gpu_temp_label = QLabel("N/A")
        hw_layout.addWidget(QLabel(f"🖥️ {translator.get('cpu_usage', self.current_lang)}"), 0, 0)
        hw_layout.addWidget(self.cpu_progress, 0, 1, 1, 3); hw_layout.addWidget(QLabel(f"🧠 {translator.get('ram_usage', self.current_lang)}"), 1, 0)
        hw_layout.addWidget(self.ram_progress, 1, 1, 1, 3); hw_layout.addWidget(QLabel(f"🎮 {translator.get('gpu_usage', self.current_lang)}"), 2, 0)
        hw_layout.addWidget(self.gpu_progress, 2, 1); hw_layout.addWidget(QLabel(f"🌡️ {translator.get('gpu_temp', self.current_lang)}"), 2, 2)
        hw_layout.addWidget(self.gpu_temp_label, 2, 3); hw_layout.addWidget(QLabel(f"💾 {translator.get('disk_usage', self.current_lang)}"), 3, 0)
        hw_layout.addWidget(self.disk_progress, 3, 1, 1, 3)
        sys_summary_group = QGroupBox(translator.get("system_summary", self.current_lang)); sys_summary_layout = QFormLayout()
        sys_summary_group.setLayout(sys_summary_layout); self.processor_label = QLabel("N/A"); self.graphics_label = QLabel("N/A")
        self.memory_label = QLabel("N/A"); self.os_label = QLabel(f"{platform.system()} {platform.release()}"); self.ip_label = QLabel(socket.gethostbyname(socket.gethostname()))
        sys_summary_layout.addRow(f"🖥️ {translator.get('processor', self.current_lang)}", self.processor_label); sys_summary_layout.addRow(f"🎮 {translator.get('graphics', self.current_lang)}", self.graphics_label)
        sys_summary_layout.addRow(f"🧠 {translator.get('memory', self.current_lang)}", self.memory_label); sys_summary_layout.addRow(f"💻 {translator.get('os', self.current_lang)}", self.os_label)
        sys_summary_layout.addRow(f"🌐 {translator.get('ip_address', self.current_lang)}", self.ip_label); self.update_system_summary()
        layout.addWidget(hw_group, 0, 0); layout.addWidget(sys_summary_group, 0, 1); tab.setLayout(layout)
        
    def create_performance_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, translator.get("performance_tab", self.current_lang)); layout = QGridLayout(); layout.setSpacing(15)
        perf_group = QGroupBox(translator.get("performance_tab", self.current_lang)); perf_layout = QVBoxLayout(); perf_group.setLayout(perf_layout)
        tools_group = QGroupBox(translator.get("tools_tab", self.current_lang)); tools_layout = QVBoxLayout(); tools_group.setLayout(tools_layout)
        perf_actions = [("optimize", "optimize_performance", "⚡"), ("ultimate_perf", "ultimate_performance", "🔋"), ("open_power_plan", self.open_power_plans, "⚡"), ("memory_clean", "memory_clean", "🧠"), ("network_optimizer", "network_optimize", "🌐")]
        for (text, task, icon) in perf_actions: 
            if isinstance(task, str):
                btn = QPushButton(f"{icon} {translator.get(text, self.current_lang)}"); btn.clicked.connect(lambda ch, t=task: self.run_task(t)); perf_layout.addWidget(btn)
            else:
                btn = QPushButton(f"{icon} {translator.get(text, self.current_lang)}"); btn.clicked.connect(task); perf_layout.addWidget(btn)
        system_tools = [("startup_optimizer", self.open_startup_manager, "🚀"), ("service_manager", lambda: self.open_system_tool("services.msc"), "⚙️"), ("event_viewer", lambda: self.open_system_tool("eventvwr.msc"), "👁️"), ("task_scheduler", lambda: self.open_system_tool("taskschd.msc"), "📅"), ("resource_monitor", lambda: self.open_system_tool("resmon.exe"), "📊")]
        for (text, func, icon) in system_tools: btn = QPushButton(f"{icon} {translator.get(text, self.current_lang)}"); btn.clicked.connect(func); tools_layout.addWidget(btn)
        layout.addWidget(perf_group, 0, 0); layout.addWidget(tools_group, 0, 1); tab.setLayout(layout)
        
    def create_cleaner_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, translator.get("cleaner_tab", self.current_lang)); 
        
        # Create scroll area for responsiveness
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        
        cleaner_group = QGroupBox(translator.get("cleaner_tab", self.current_lang)); cleaner_layout = QVBoxLayout(); cleaner_group.setLayout(cleaner_layout)
        cleaner_actions = [("clean_temp", "clean_temp", "🧹"), ("empty_recycle", "empty_recycle", "🗑️"), ("clean_registry", "clean_registry", "🔍"), ("system_cleaner", "deep_clean", "🧹")]
        for (text, task, icon) in cleaner_actions: 
            btn = QPushButton(f"{icon} {translator.get(text, self.current_lang)}")
            btn.clicked.connect(lambda ch, t=task: self.run_task(t))
            cleaner_layout.addWidget(btn)
        layout.addWidget(cleaner_group)
        
        scroll.setWidget(scroll_content)
        tab_layout = QVBoxLayout(tab)
        tab_layout.addWidget(scroll)
        
    def create_pc_repair_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, translator.get("pc_repair_tab", self.current_lang)); 
        
        # Create scroll area for responsiveness
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        
        repair_group = QGroupBox(translator.get("repair_tools", self.current_lang)); repair_layout = QVBoxLayout(); repair_group.setLayout(repair_layout)
        repair_tools = [("sys_repair", "system_repair", "🛠️"), ("disk_cleanup", "disk_cleanup", "🧹"), ("reset_network", "reset_network", "🌐"), ("check_disk", "check_disk", "💾")]
        self.repair_buttons = []
        for (text, task, icon) in repair_tools: 
            btn = QPushButton(f"{icon} {translator.get(text, self.current_lang)}")
            btn.clicked.connect(lambda ch, t=task: self.run_task(t))
            repair_layout.addWidget(btn)
            self.repair_buttons.append(btn)
        layout.addWidget(repair_group)
        
        scroll.setWidget(scroll_content)
        tab_layout = QVBoxLayout(tab)
        tab_layout.addWidget(scroll)
        
    def create_tools_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, translator.get("tools_tab", self.current_lang)); 
        
        # Create scroll area for responsiveness
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        layout = QGridLayout(scroll_content)
        
        tools = [("device_manager", lambda: self.open_system_tool("devmgmt.msc"), "⚙️"), ("disk_management", lambda: self.open_system_tool("diskmgmt.msc"), "💾"), ("sys_info", lambda: self.open_system_tool("msinfo32"), "ℹ️"), ("user_accounts", lambda: self.open_system_tool("netplwiz"), "👥"), ("network_settings", lambda: self.open_system_tool("ncpa.cpl"), "🌐"), ("registry_editor", lambda: self.open_system_tool("regedit"), "⚙️")]
        for i, (text, func, icon) in enumerate(tools): 
            btn = QPushButton(f"{icon} {translator.get(text, self.current_lang)}"); 
            btn.clicked.connect(func); 
            layout.addWidget(btn, i // 2, i % 2)
        
        scroll.setWidget(scroll_content)
        tab_layout = QVBoxLayout(tab)
        tab_layout.addWidget(scroll)
        
    def create_uninstaller_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, translator.get("uninstaller_tab", self.current_lang)); 
        
        # Create scroll area for responsiveness
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText(translator.get("search_apps", self.current_lang)); self.search_bar.textChanged.connect(self.filter_apps)
        self.app_list = QTableWidget(); self.app_list.setColumnCount(3); self.app_list.setHorizontalHeaderLabels([translator.get("app_uninstaller", self.current_lang), translator.get("version_app", self.current_lang), translator.get("install_date", self.current_lang)])
        self.app_list.setEditTriggers(QTableWidget.NoEditTriggers); self.app_list.setSelectionBehavior(QTableWidget.SelectRows); self.app_list.setSelectionMode(QTableWidget.SingleSelection)
        self.app_list.verticalHeader().setVisible(False); self.app_list.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); self.app_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.app_list.setColumnWidth(0, 400); uninstall_btn = QPushButton(translator.get("uninstall_selected", self.current_lang))
        self.app_list.setIconSize(QSize(48, 48))
        self.app_list.setSortingEnabled(True)
        
        uninstall_btn.clicked.connect(self.uninstall_selected_app)
            
        refresh_btn = QPushButton(translator.get("refresh_list", self.current_lang)); refresh_btn.clicked.connect(self.populate_app_list); hbox = QHBoxLayout()
        hbox.addWidget(uninstall_btn); hbox.addWidget(refresh_btn); layout.addWidget(self.search_bar); layout.addWidget(self.app_list); layout.addLayout(hbox)
        
        scroll.setWidget(scroll_content)
        tab_layout = QVBoxLayout(tab)
        tab_layout.addWidget(scroll)
        
        self.populate_app_list()
        
    def create_reports_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, translator.get("reports_tab", self.current_lang)); 
        
        # Create scroll area for responsiveness
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        
        self.report_display = QTextEdit()
        self.report_display.setReadOnly(True); save_btn = QPushButton(translator.get("save_report", self.current_lang)); save_btn.clicked.connect(self.save_report)
        clear_btn = QPushButton(translator.get("clear_reports", self.current_lang)); clear_btn.clicked.connect(self.clear_reports); hbox = QHBoxLayout()
        hbox.addWidget(save_btn); hbox.addWidget(clear_btn); layout.addWidget(self.report_display); layout.addLayout(hbox); 
        
        scroll.setWidget(scroll_content)
        tab_layout = QVBoxLayout(tab)
        tab_layout.addWidget(scroll)
        
    def create_settings_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, translator.get("settings_tab", self.current_lang)); 
        
        # Create scroll area for responsiveness
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        
        lang_group = QGroupBox(translator.get("language_settings", self.current_lang))
        lang_layout = QHBoxLayout(); lang_layout.addWidget(QLabel(translator.get("select_language", self.current_lang))); self.lang_combo = QComboBox()
        self.lang_combo.addItems(["English", "العربية"]); self.lang_combo.setCurrentIndex(0 if self.current_lang == "en" else 1); self.lang_combo.currentTextChanged.connect(self.change_language)
        lang_layout.addWidget(self.lang_combo); lang_group.setLayout(lang_layout); general_group = QGroupBox(translator.get("general_settings", self.current_lang))
        general_layout = QVBoxLayout(); self.run_startup_cb = QCheckBox(translator.get("run_startup", self.current_lang)); self.auto_scan_cb = QCheckBox(translator.get("auto_scan", self.current_lang))
        self.minimize_tray_cb = QCheckBox(translator.get("minimize_tray", self.current_lang)); general_layout.addWidget(self.run_startup_cb); general_layout.addWidget(self.auto_scan_cb); general_layout.addWidget(self.minimize_tray_cb)
        general_group.setLayout(general_layout); privacy_group = QGroupBox(translator.get("privacy_settings", self.current_lang)); privacy_layout = QVBoxLayout()
        self.auto_clean_cb = QCheckBox(translator.get("auto_clean", self.current_lang)); self.clear_history_cb = QCheckBox(translator.get("clear_history", self.current_lang)); self.block_tracking_cb = QCheckBox(translator.get("block_tracking", self.current_lang))
        privacy_layout.addWidget(self.auto_clean_cb); privacy_layout.addWidget(self.clear_history_cb); privacy_layout.addWidget(self.block_tracking_cb); privacy_group.setLayout(privacy_layout)
        save_btn = QPushButton(translator.get("save_settings", self.current_lang)); save_btn.clicked.connect(self.save_settings); layout.addWidget(lang_group); layout.addWidget(general_group)
        layout.addWidget(privacy_group); layout.addWidget(save_btn); layout.addStretch(); 
        
        scroll.setWidget(scroll_content)
        tab_layout = QVBoxLayout(tab)
        tab_layout.addWidget(scroll)
        
        self.load_settings_checkboxes()
        
    def update_hw_monitor(self):
        self.cpu_progress.setValue(int(psutil.cpu_percent())); self.ram_progress.setValue(int(psutil.virtual_memory().percent)); self.disk_progress.setValue(int(psutil.disk_usage('C:').percent))
        try:
            gpus = GPUtil.getGPUs()
            if gpus: self.gpu_progress.setValue(int(gpus[0].load * 100)); self.gpu_temp_label.setText(f"{gpus[0].temperature} °C")
        except Exception: self.gpu_progress.setValue(0); self.gpu_temp_label.setText("N/A")
        
    def update_system_summary(self):
        try:
            c = wmi.WMI(); self.processor_label.setText(c.Win32_Processor()[0].Name); self.graphics_label.setText(c.Win32_VideoController()[0].Name)
            self.memory_label.setText(f"{psutil.virtual_memory().total / (1024**3):.2f} GB")
        except Exception: pass
        
    def run_task(self, task, *args):
        if task == "system_repair":
            self.repair_dialog = SystemRepairDialog(self, self.current_lang)
            self.worker = WorkerThread(task, lang=self.current_lang)
            self.worker.update_signal.connect(self.repair_dialog.update_repair_time)
            self.worker.repair_stage_signal.connect(self.repair_dialog.update_stage)
            self.worker.finished_signal.connect(self.task_finished)
            self.worker.report_signal.connect(self.update_report)
            self.worker.start()
            self.repair_dialog.exec_()
        else:
            self.progress_dialog = ProgressDialog(self, title=f"Running {task}", lang=self.current_lang); self.worker = WorkerThread(task, *args, lang=self.current_lang)
            self.worker.update_signal.connect(self.progress_dialog.update_progress); self.worker.finished_signal.connect(self.task_finished)
            self.worker.report_signal.connect(self.update_report); self.worker.start(); self.progress_dialog.exec_()
            
    def task_finished(self, status, report):
        if hasattr(self, 'progress_dialog') and self.progress_dialog.isVisible(): self.progress_dialog.close()
        if hasattr(self, 'repair_dialog') and self.repair_dialog.isVisible(): self.repair_dialog.close()
        if status == "success":
            dialog = SummaryDialog(translator.get("completed", self.current_lang), report, self)
            dialog.exec_()
        else: QMessageBox.critical(self, translator.get("operation_failed", self.current_lang), report)
        
    def update_report(self, task, report):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_report = f"--- Report for '{task}' at {timestamp} ---\n{report}\n\n"; self.reports[task] = full_report; self.report_display.append(full_report)
        
    def save_report(self):
        fileName, _ = QFileDialog.getSaveFileName(self, "Save Report", "report.txt", "Text Files (*.txt);;All Files (*)")
        if fileName:
            with open(fileName, 'w', encoding='utf-8') as f: f.write(self.report_display.toPlainText())
            
    def clear_reports(self): self.report_display.clear(); self.reports = {}
    
    def populate_app_list(self):

        self.app_list.setRowCount(0)
        self.all_apps = []
        # Ensure visible icon size for the table (safe even if already set elsewhere)
        try:
            self.app_list.setIconSize(QSize(48, 48))
        except Exception:
            pass

        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        for hkey, path in reg_paths:
            try:
                with winreg.OpenKey(hkey, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    try:
                                        system_component = winreg.QueryValueEx(subkey, "SystemComponent")[0]
                                        if system_component == 1:
                                            continue
                                    except FileNotFoundError:
                                        pass

                                    try:
                                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    except FileNotFoundError:
                                        continue
                                    if not name:
                                        continue

                                    try:
                                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                    except FileNotFoundError:
                                        version = "N/A"

                                    try:
                                        date = winreg.QueryValueEx(subkey, "InstallDate")[0]
                                        if date and isinstance(date, str) and len(date) == 8:
                                            date = f"{date[:4]}-{date[4:6]}-{date[6:8]}"
                                    except FileNotFoundError:
                                        date = "N/A"

                                    # Start with a guaranteed badge icon
                                    icon = _badge_from_name_force(name, 32)
                                    # Try to get a real icon via registry values
                                    real = resolve_icon_force_from_registry(subkey, name)
                                    if isinstance(real, QIcon) and not real.isNull():
                                        icon = real

                                    self.all_apps.append((name, version, date, icon))
                                except (OSError, WindowsError, FileNotFoundError):
                                    continue
                        except OSError:
                            continue
            except FileNotFoundError:
                continue

        # Deduplicate & sort
        uniq = {}
        for (n, v, d, ic) in self.all_apps:
            key = (str(n).strip().lower(), str(v).strip())
            if key not in uniq:
                uniq[key] = (n, v, d, ic)
        self.all_apps = sorted(list(uniq.values()), key=lambda x: x[0].lower())

        self.app_list.setRowCount(len(self.all_apps))
        for i, (name, version, date, icon) in enumerate(self.all_apps):
            name_item = QTableWidgetItem(name)
            name_item.setIcon(icon)
            name_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self.app_list.setItem(i, 0, name_item)

            version_item = QTableWidgetItem(version)
            version_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            self.app_list.setItem(i, 1, version_item)

            date_item = QTableWidgetItem(date)
            date_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            self.app_list.setItem(i, 2, date_item)

            # Make rows a bit taller for icons
            try:
                self.app_list.setRowHeight(i, ICON_SIZE + 6)
            except Exception:
                pass
    def get_default_icon(self):
        # Extract default application icon from user32.dll using IDI_APPLICATION
        default_path = os.path.expandvars(r"%SystemRoot%\system32\user32.dll")
        icon = extract_icon(default_path, -32512)
        if icon.isNull():
            # Fallback to shell32.dll icon if user32 fails
            shell_path = os.path.expandvars(r"%SystemRoot%\system32\shell32.dll")
            icon = extract_icon(shell_path, 0)
        return icon

    def filter_apps(self, text):
        self.app_list.setRowCount(0); filtered_apps = [app for app in self.all_apps if text.lower() in app[0].lower()]
        self.app_list.setRowCount(len(filtered_apps))
        for i, (name, version, date, icon) in enumerate(filtered_apps): 
            name_item = QTableWidgetItem(name)
            if icon and not icon.isNull():
                name_item.setIcon(icon)
            name_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self.app_list.setItem(i, 0, name_item)
            
            version_item = QTableWidgetItem(version)
            version_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            self.app_list.setItem(i, 1, version_item)
            
            date_item = QTableWidgetItem(date)
            date_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            self.app_list.setItem(i, 2, date_item)
            
            self.app_list.setRowHeight(i, 50)
        
    def uninstall_selected_app(self):
        if not self.app_list.selectedItems(): return
        app_name = self.app_list.item(self.app_list.currentRow(), 0).text()
        if QMessageBox.question(self, "Confirm Uninstall", f"Are you sure you want to completely uninstall {app_name}?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            self.run_task("uninstall_app", app_name); self.populate_app_list()
            
    def open_system_tool(self, tool_name):
        # Use a separate thread to open system tools to prevent UI freezing
        thread = SystemToolThread(tool_name)
        thread.finished_signal.connect(self.on_system_tool_finished)
        thread.start()
        self.system_tool_threads.append(thread)
        
    def on_system_tool_finished(self, result, success):
        if not success:
            QMessageBox.critical(self, translator.get("update_error", self.current_lang), result)
            
    def open_startup_manager(self):
        try: os.startfile(os.path.join(os.environ['APPDATA'], r'Microsoft\Windows\Start Menu\Programs\Startup'))
        except Exception as e: QMessageBox.critical(self, translator.get("update_error", self.current_lang), f"Could not open startup folder: {str(e)}")
        
    def open_power_plans(self):
        try: 
            # Open Power Options in Control Panel
            subprocess.run("control.exe powercfg.cpl", shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e: QMessageBox.critical(self, translator.get("update_error", self.current_lang), f"Could not open power plans: {str(e)}")
        
    def change_language(self, lang_text): 
        self.current_lang = "ar" if lang_text == "العربية" else "en"; 
        self.apply_language()
        self.position_logo()
        
    def apply_language(self):
        self.setWindowTitle(translator.get("app_title", self.current_lang))
        self.setLayoutDirection(Qt.RightToLeft if self.current_lang == 'ar' else Qt.LeftToRight)
        QApplication.setLayoutDirection(self.layoutDirection())
        while self.tabs.count(): self.tabs.removeTab(0)
        self.create_dashboard_tab(); self.create_performance_tab(); self.create_pc_repair_tab()
        self.create_uninstaller_tab(); self.create_tools_tab(); self.create_cleaner_tab()
        self.create_reports_tab(); self.create_settings_tab()
        self.tabs.setTabText(0, translator.get("system_tab", self.current_lang)); self.tabs.setTabText(1, translator.get("performance_tab", self.current_lang)); self.tabs.setTabText(2, translator.get("pc_repair_tab", self.current_lang))
        self.tabs.setTabText(3, translator.get("uninstaller_tab", self.current_lang)); self.tabs.setTabText(4, translator.get("tools_tab", self.current_lang)); self.tabs.setTabText(5, translator.get("cleaner_tab", self.current_lang)); self.tabs.setTabText(6, translator.get("reports_tab", self.current_lang)); self.tabs.setTabText(7, translator.get("settings_tab", self.current_lang))
        self.create_menu_bar()  # Recreate menu bar for language update
        self.tabs.repaint()
        self.update_license_status_display()
        
    def save_settings(self):
        settings = {"language": self.current_lang, "run_on_startup": self.run_startup_cb.isChecked(), "auto_scan_on_startup": self.auto_scan_cb.isChecked(), "minimize_to_tray": self.minimize_tray_cb.isChecked(), "auto_clean_privacy": self.auto_clean_cb.isChecked(), "clear_history_on_exit": self.clear_history_cb.isChecked(), "block_tracking_cookies": self.block_tracking_cb.isChecked()}
        with open("settings.json", "w") as f: json.dump(settings, f)
        QMessageBox.information(self, "Settings Saved", "Your settings have been saved.")
        
    def load_settings(self):
        try:
            with open("settings.json", "r") as f: self.current_lang = json.load(f).get("language", "en")
        except FileNotFoundError: self.current_lang = "en"
        
    def load_settings_checkboxes(self):
        try:
            with open("settings.json", "r") as f:
                settings = json.load(f)
                self.run_startup_cb.setChecked(settings.get("run_on_startup", False)); self.auto_scan_cb.setChecked(settings.get("auto_scan_on_startup", False)); self.minimize_tray_cb.setChecked(settings.get("minimize_to_tray", False))
                self.auto_clean_cb.setChecked(settings.get("auto_clean_privacy", False)); self.clear_history_cb.setChecked(settings.get("clear_history_on_exit", False)); self.block_tracking_cb.setChecked(settings.get("block_tracking_cookies", False))
        except FileNotFoundError: pass

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if __name__ == '__main__':
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    app = QApplication(sys.argv)
    app.setStyleSheet(dark_stylesheet_v7)
    app.setWindowIcon(QIcon("pcfix_icon"))

    ex = App()
    ex.show()
    sys.exit(app.exec_())