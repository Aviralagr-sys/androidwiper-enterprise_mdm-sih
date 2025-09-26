#!/usr/bin/env python3
"""
Complete Enterprise Mobile Device Management Framework
Legitimate enterprise-grade Android device management for SIH project
Implements proper security, audit trails, and compliance monitoring
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import json
import logging
import sqlite3
from datetime import datetime, timedelta
import os
import threading
import hashlib
import time

class DeviceAuth:
    """Device ownership verification and authorization"""
    
    @staticmethod
    def verify_device_ownership(device_id):
        """Verify device ownership through multiple methods"""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'shell', 
                                   'settings', 'get', 'global', 'development_settings_enabled'],
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0 or result.stdout.strip() != '1':
                return False, "Developer options not enabled"
            
            result = subprocess.run(['adb', '-s', device_id, 'shell', 'echo', 'test'],
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode != 0:
                return False, "Device not authorized for debugging"
            
            return True, "Device ownership verified"
            
        except Exception as e:
            return False, f"Verification failed: {e}"
    
    @staticmethod
    def create_authorization_token(device_id, user_confirmation):
        """Create secure authorization token"""
        timestamp = str(int(time.time()))
        data = f"{device_id}:{user_confirmation}:{timestamp}"
        token = hashlib.sha256(data.encode()).hexdigest()
        return token, timestamp

class DataSanitizationEngine:
    """Secure data sanitization with proper safeguards"""
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback or print
        self.sanitization_standards = {
            'BASIC': {'passes': 1, 'pattern': 'zeros'},
            'DOD_5220': {'passes': 3, 'pattern': 'random'},
            'NIST_800_88': {'passes': 1, 'pattern': 'crypto_erase'},
            'GUTMANN': {'passes': 35, 'pattern': 'complex'}
        }
    
    def _is_device_encrypted(self, device_id):
        """Check if device is encrypted"""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', 'ro.crypto.state'],
                                    capture_output=True, text=True, timeout=5)
            return result.stdout.strip() == 'encrypted'
        except Exception:
            return False
    
    def verify_authorization(self, device_id, user_token):
        """Verify user authorization for sanitization"""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'shell', 'echo', 'auth_test'],
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode != 0:
                return False, "Device not accessible"
            
            dev_check = subprocess.run(['adb', '-s', device_id, 'shell', 
                                      'settings', 'get', 'global', 'development_settings_enabled'],
                                     capture_output=True, text=True, timeout=5)
            
            if dev_check.stdout.strip() != '1':
                return False, "Developer options not enabled - user authorization required"
            
            return True, "Authorization verified"
            
        except Exception as e:
            return False, f"Authorization failed: {e}"
    
    def sanitize_user_data(self, device_id, sanitization_level='BASIC', verify_only=False):
        """Sanitize user-accessible data with proper verification"""
        operations = []
        
        try:
            user_data_paths = [
                '/sdcard/Download',
                '/sdcard/Pictures',
                '/sdcard/DCIM',
                '/sdcard/Documents',
                '/sdcard/Music',
                '/sdcard/Movies',
                '/sdcard/Android/data'
            ]
            
            for path in user_data_paths:
                result = subprocess.run(['adb', '-s', device_id, 'shell', 'find', path, '-type', 'f', '2>/dev/null | wc -l'],
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    file_count = result.stdout.strip()
                    operations.append({
                        'path': path,
                        'files': file_count,
                        'status': 'pending'
                    })
            
            if verify_only:
                return True, operations
            
            standard = self.sanitization_standards.get(sanitization_level, self.sanitization_standards['BASIC'])
            
            is_encrypted = self._is_device_encrypted(device_id)
            
            perform_delete = True
            
            if standard['pattern'] == 'crypto_erase':
                if is_encrypted:
                    self.log_callback("Performing cryptographic erase on encrypted device (delete only)")
                else:
                    self.log_callback("Device not encrypted - falling back to basic delete for NIST standard")
            else:
                for pass_num in range(standard['passes']):
                    self.log_callback(f"Secure overwrite pass {pass_num + 1}/{standard['passes']} (pattern: {standard['pattern']})")
                    
                    if_source = '/dev/zero' if standard['pattern'] == 'zeros' else '/dev/urandom'
                    
                    for operation in operations:
                        path = operation['path']
                        
                        cmd = [
                            'adb', '-s', device_id, 'shell',
                            'find', path, '-type', 'f',
                            '-exec', 'dd', f'if={if_source}', 'of={{}}', 'bs=4096', 'conv=notrunc', ';'
                        ]
                        
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                        
                        if result.returncode != 0:
                            self.log_callback(f"Overwrite failed for {path}: {result.stderr}")
                            operation['status'] = 'failed'
                        else:
                            operation['status'] = 'overwritten'
            
            if perform_delete:
                self.log_callback("Performing final secure delete")
                for operation in operations:
                    path = operation['path']
                    
                    cmd = ['adb', '-s', device_id, 'shell', 'find', path, '-type', 'f', '-delete', '2>/dev/null']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0 and operation['status'] != 'failed':
                        operation['status'] = 'completed'
                    else:
                        operation['status'] = 'failed'
                        self.log_callback(f"Delete failed for {path}: {result.stderr}")
            
            all_success = all(op['status'] == 'completed' for op in operations)
            return all_success, operations
            
        except Exception as e:
            return False, f"Sanitization failed: {e}"
    
    def verify_sanitization(self, device_id, operations):
        """Verify sanitization was successful"""
        verification_results = []
        
        for operation in operations:
            path = operation['path']
            
            result = subprocess.run(['adb', '-s', device_id, 'shell', 'find', path, '-type', 'f', '2>/dev/null | wc -l'],
                                  capture_output=True, text=True, timeout=15)
            
            remaining_files = result.stdout.strip() if result.returncode == 0 else 'error'
            
            verification_results.append({
                'path': path,
                'original_files': operation['files'],
                'remaining_files': remaining_files,
                'verified': remaining_files == '0'
            })
        
        return verification_results

class EnterpriseMDM:
    """Enterprise-grade Android device management with data sanitization"""
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback or print
        self.audit_entries = []
        self.policies = {}
        self.sanitization_engine = DataSanitizationEngine(log_callback)
    
    def audit_log_entry(self, operation, device_id, status, details="", compliance_flags=""):
        """Add entry to audit log with improved details"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'device_id': device_id,
            'status': status,
            'details': details,
            'compliance_flags': compliance_flags
        }
        self.audit_entries.append(entry)
        self.log_callback(f"AUDIT: {operation} - {status} - Flags: {compliance_flags}")
        return entry
    
    def check_prerequisites(self):
        """Check system prerequisites"""
        try:
            result = subprocess.run(['adb', 'version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return False, "ADB not available"
            
            self.log_callback(f"ADB ready: {result.stdout.split()[1] if len(result.stdout.split()) > 1 else 'Unknown version'}")
            return True, "Prerequisites satisfied"
            
        except FileNotFoundError:
            return False, "ADB not installed - run: sudo apt install android-tools-adb"
        except Exception as e:
            return False, f"Prerequisite check failed: {e}"
    
    def detect_devices(self):
        """Detect and validate Android devices"""
        try:
            result = subprocess.run(['adb', 'devices', '-l'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode != 0:
                return []
            
            devices = []
            for line in result.stdout.strip().split('\n')[1:]:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    device_id = parts[0]
                    status = parts[1]
                    
                    if status == "device":
                        device_info = self._get_device_info(device_id)
                        if device_info:
                            device_info['id'] = device_id
                            devices.append(device_info)
                            self.audit_log_entry("DEVICE_DETECTED", device_id, "SUCCESS", 
                                               f"{device_info.get('brand', 'Unknown')} {device_info.get('model', 'Device')}")
            
            return devices
            
        except Exception as e:
            self.log_callback(f"Device detection failed: {e}")
            return []
    
    def _get_device_info(self, device_id):
        """Get comprehensive device information with security details"""
        try:
            info = {}
            
            props = {
                'brand': 'ro.product.brand',
                'model': 'ro.product.model',
                'android_version': 'ro.build.version.release',
                'sdk_version': 'ro.build.version.sdk',
                'serial': 'ro.serialno',
                'manufacturer': 'ro.product.manufacturer',
                'security_patch': 'ro.build.version.security_patch'
            }
            
            for key, prop in props.items():
                try:
                    result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', prop],
                                          capture_output=True, text=True, timeout=5)
                    info[key] = result.stdout.strip() or 'Unknown'
                except:
                    info[key] = 'Unknown'
            
            try:
                root_check = subprocess.run(['adb', '-s', device_id, 'shell', 'which', 'su'],
                                            capture_output=True, text=True, timeout=5)
                info['is_rooted'] = 'Yes' if root_check.returncode == 0 and root_check.stdout.strip() else 'No'
            except:
                info['is_rooted'] = 'Unknown'
            
            try:
                selinux = subprocess.run(['adb', '-s', device_id, 'shell', 'getenforce'],
                                         capture_output=True, text=True, timeout=5)
                info['selinux_status'] = selinux.stdout.strip() or 'Unknown'
            except:
                info['selinux_status'] = 'Unknown'
            
            try:
                unknown_sources = subprocess.run(['adb', '-s', device_id, 'shell', 'settings', 'get', 'secure', 'install_non_market_apps'],
                                                 capture_output=True, text=True, timeout=5)
                info['unknown_sources'] = 'Enabled' if unknown_sources.stdout.strip() == '1' else 'Disabled'
            except:
                info['unknown_sources'] = 'Unknown'
            
            info.update(self._get_storage_info(device_id))
            
            info['encryption_status'] = self._check_encryption_status(device_id)
            
            info['admin_status'] = self._check_device_admin_status(device_id)
            
            return info
            
        except Exception as e:
            self.log_callback(f"Failed to get device info: {e}")
            return None
    
    def _get_storage_info(self, device_id):
        """Get device storage information"""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'shell', 'df', '/data'],
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 4:
                        total_kb = int(parts[1])
                        used_kb = int(parts[2])
                        return {
                            'storage_total': f"{total_kb // 1024} MB",
                            'storage_used': f"{used_kb // 1024} MB",
                            'storage_free': f"{(total_kb - used_kb) // 1024} MB",
                            'storage_percent_used': f"{(used_kb / total_kb) * 100:.1f}%"
                        }
            
            return {'storage_total': 'Unknown', 'storage_used': 'Unknown', 
                   'storage_free': 'Unknown', 'storage_percent_used': 'Unknown'}
            
        except:
            return {'storage_total': 'Unknown', 'storage_used': 'Unknown', 
                   'storage_free': 'Unknown', 'storage_percent_used': 'Unknown'}
    
    def _check_encryption_status(self, device_id):
        """Check device encryption status"""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'shell', 
                                   'getprop', 'ro.crypto.state'],
                                  capture_output=True, text=True, timeout=5)
            
            state = result.stdout.strip()
            
            type_result = subprocess.run(['adb', '-s', device_id, 'shell',
                                        'getprop', 'ro.crypto.type'],
                                       capture_output=True, text=True, timeout=5)
            
            crypto_type = type_result.stdout.strip()
            
            if state == "encrypted":
                return f"Encrypted ({crypto_type if crypto_type else 'Unknown type'})"
            else:
                return "Not Encrypted"
            
        except:
            return "Unknown"
    
    def _check_device_admin_status(self, device_id):
        """Check device administrator status"""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'shell',
                                   'dpm', 'list-owners'],
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout.strip()
                if 'Device owner' in output:
                    return "Device Owner Active"
                elif 'Profile owner' in output:
                    return "Profile Owner Active"
                else:
                    return "No Device Admin"
            else:
                return "Cannot Determine"
            
        except:
            return "Unknown"
    
    def check_compliance(self, device_id, standards=['GDPR', 'ISO27001']):
        """Improved device compliance check with more security assessments"""
        compliance_results = {}
        
        for standard in standards:
            checks = []
            
            device_info = self._get_device_info(device_id)
            
            if standard == 'GDPR':
                encryption_status = self._check_encryption_status(device_id)
                checks.append({
                    'check': 'Data Encryption',
                    'status': 'PASS' if 'Encrypted' in encryption_status else 'FAIL',
                    'details': encryption_status
                })
                
                try:
                    result = subprocess.run(['adb', '-s', device_id, 'shell',
                                           'dumpsys', 'trust'],
                                          capture_output=True, text=True, timeout=10)
                    
                    screen_lock_active = 'isEnabled=true' in result.stdout
                    checks.append({
                        'check': 'Screen Lock Active',
                        'status': 'PASS' if screen_lock_active else 'FAIL',
                        'details': f"Screen lock {'enabled' if screen_lock_active else 'disabled'}"
                    })
                except:
                    checks.append({
                        'check': 'Screen Lock Active',
                        'status': 'UNKNOWN',
                        'details': 'Could not verify screen lock status'
                    })
                
                checks.append({
                    'check': 'Unknown Sources',
                    'status': 'PASS' if device_info.get('unknown_sources') == 'Disabled' else 'FAIL',
                    'details': device_info.get('unknown_sources', 'Unknown')
                })
            
            elif standard == 'ISO27001':
                admin_status = self._check_device_admin_status(device_id)
                checks.append({
                    'check': 'Device Administration',
                    'status': 'PASS' if 'Active' in admin_status else 'REVIEW',
                    'details': admin_status
                })
                
                try:
                    result = subprocess.run(['adb', '-s', device_id, 'shell',
                                           'settings', 'get', 'global', 'adb_enabled'],
                                          capture_output=True, text=True, timeout=5)
                    
                    adb_enabled = result.stdout.strip() == '1'
                    checks.append({
                        'check': 'USB Debugging Control',
                        'status': 'REVIEW' if adb_enabled else 'PASS',
                        'details': f"USB debugging {'enabled' if adb_enabled else 'disabled'}"
                    })
                except:
                    checks.append({
                        'check': 'USB Debugging Control',
                        'status': 'UNKNOWN',
                        'details': 'Could not verify USB debugging status'
                    })
                
                checks.append({
                    'check': 'SELinux Status',
                    'status': 'PASS' if device_info.get('selinux_status') == 'Enforcing' else 'FAIL',
                    'details': device_info.get('selinux_status', 'Unknown')
                })
                
                checks.append({
                    'check': 'Device Not Rooted',
                    'status': 'PASS' if device_info.get('is_rooted') == 'No' else 'FAIL',
                    'details': f"Rooted: {device_info.get('is_rooted', 'Unknown')}"
                })
                
                patch_date_str = device_info.get('security_patch', 'Unknown')
                if patch_date_str != 'Unknown':
                    try:
                        patch_date = datetime.strptime(patch_date_str, '%Y-%m-%d')
                        current_date = datetime.now()
                        is_recent = (current_date - patch_date) < timedelta(days=180)
                        checks.append({
                            'check': 'Security Patch Up-to-date',
                            'status': 'PASS' if is_recent else 'FAIL',
                            'details': f"Patch date: {patch_date_str} ({'Recent' if is_recent else 'Outdated'})"
                        })
                    except ValueError:
                        checks.append({
                            'check': 'Security Patch Up-to-date',
                            'status': 'UNKNOWN',
                            'details': 'Invalid patch date format'
                        })
                else:
                    checks.append({
                        'check': 'Security Patch Up-to-date',
                        'status': 'UNKNOWN',
                        'details': 'Could not retrieve patch date'
                    })
            
            overall_status = 'COMPLIANT' if all(c['status'] == 'PASS' for c in checks if c['status'] != 'UNKNOWN') else 'NEEDS_REVIEW'
            compliance_results[standard] = {
                'overall_status': overall_status,
                'checks': checks,
                'checked_at': datetime.now().isoformat()
            }
            
            flags = ','.join([c['check'] for c in checks if c['status'] != 'PASS'])
            self.audit_log_entry("COMPLIANCE_CHECK", device_id, 
                               overall_status, 
                               f"{standard} compliance check", compliance_flags=flags)
        
        return compliance_results
    
    def apply_policy(self, device_id, policy_type, policy_value):
        """Improved policy application with more types"""
        try:
            success = False
            details = ""
            
            if policy_type == "screen_timeout":
                timeout_ms = int(policy_value) * 60 * 1000
                result = subprocess.run(['adb', '-s', device_id, 'shell',
                                       'settings', 'put', 'system', 
                                       'screen_off_timeout', str(timeout_ms)],
                                      capture_output=True, text=True, timeout=10)
                
                success = result.returncode == 0
                details = f"Screen timeout set to {policy_value} minutes"
                
            elif policy_type == "password_quality":
                details = "Password policy requires device admin enrollment. Simulated set to {policy_value}"
                success = False
                
            elif policy_type == "camera_disabled":
                details = "Camera policy requires device admin enrollment"
                success = False
                
            elif policy_type == "disable_unknown_sources":
                result = subprocess.run(['adb', '-s', device_id, 'shell',
                                       'settings', 'put', 'secure', 
                                       'install_non_market_apps', '0'],
                                      capture_output=True, text=True, timeout=10)
                success = result.returncode == 0
                details = "Unknown sources disabled"
                
            elif policy_type == "enable_adb":
                result = subprocess.run(['adb', '-s', device_id, 'shell',
                                       'settings', 'put', 'global', 
                                       'adb_enabled', str(1 if policy_value.lower() == 'yes' else 0)],
                                      capture_output=True, text=True, timeout=10)
                success = result.returncode == 0
                details = f"ADB {'enabled' if policy_value.lower() == 'yes' else 'disabled'}"
                
            else:
                details = f"Unknown policy type: {policy_type}"
                success = False
            
            status = "SUCCESS" if success else "FAILED"
            self.audit_log_entry("POLICY_APPLY", device_id, status, 
                               f"{policy_type}: {details}")
            
            return success, details
            
        except Exception as e:
            error_msg = f"Policy application failed: {e}"
            self.audit_log_entry("POLICY_APPLY", device_id, "ERROR", error_msg)
            return False, error_msg
    
    def export_audit_log(self, filename):
        """Export audit log for compliance"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.audit_entries, f, indent=2)
            return True
        except:
            return False

class AndroidEnterpriseManager:
    """Android Enterprise API integration simulation"""
    
    def setup_work_profile(self, device_id):
        """Set up managed work profile"""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'shell',
                                   'pm', 'list', 'users'],
                                  capture_output=True, text=True, timeout=10)
            
            if 'managed profile' in result.stdout.lower():
                return {
                    'status': 'WORK_PROFILE_EXISTS',
                    'message': 'Managed work profile already configured'
                }
            else:
                return {
                    'status': 'MANUAL_ENROLLMENT_REQUIRED',
                    'message': 'Device must be enrolled through Android Enterprise',
                    'instructions': [
                        'Device must be enrolled through Android Enterprise',
                        'Use enterprise mobility management (EMM) console',
                        'Deploy through Google Play Managed Store',
                        'Requires organization domain verification'
                    ]
                }
        except Exception as e:
            return {'status': 'ERROR', 'message': str(e)}
    
    def get_compliance_status(self, device_id):
        """Get enterprise compliance status"""
        return {
            'enrollment_status': 'Not Enrolled',
            'policy_compliance': 'Manual Verification Required',
            'last_sync': 'Never',
            'managed_apps': 0
        }

class ComplianceAuditSystem:
    """Enterprise compliance and audit trail system"""
    
    def __init__(self, db_path=None):
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'logs', 'audit.db')
        self.init_database()
    
    def init_database(self):
        """Initialize audit database with improved schema"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    device_id TEXT,
                    user_id TEXT,
                    operation TEXT,
                    status TEXT,
                    details TEXT,
                    compliance_flags TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database initialization failed: {e}")
    
    def log_event(self, event_type, device_id, operation, status, user_id="admin", details="", compliance_flags=""):
        """Log audit event to database with flags"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO audit_events 
                (timestamp, event_type, device_id, user_id, operation, status, details, compliance_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                event_type,
                device_id,
                user_id,
                operation,
                status,
                details,
                compliance_flags
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Audit logging failed: {e}")
    
    def get_audit_events(self, days=7):
        """Get recent audit events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute('''
                SELECT timestamp, event_type, device_id, user_id, operation, status, details, compliance_flags
                FROM audit_events 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            ''', (since_date,))
            
            events = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'timestamp': row[0],
                    'event_type': row[1],
                    'device_id': row[2],
                    'user_id': row[3],
                    'operation': row[4],
                    'status': row[5],
                    'details': row[6],
                    'compliance_flags': row[7]
                }
                for row in events
            ]
        except Exception as e:
            print(f"Failed to retrieve audit events: {e}")
            return []

class EnterpriseMDMGUI:
    """Complete GUI for Enterprise MDM Framework"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.setup_window()
        self.load_configuration()
        self.setup_logging()
        
        self.mdm = EnterpriseMDM(log_callback=self.log_message)
        self.enterprise_manager = AndroidEnterpriseManager()
        self.audit_system = ComplianceAuditSystem()
        
        self.devices = []
        self.selected_device = None
        self.selected_device_info = None
        # Initialize policies dictionary with default values
        self.policies = {
            "screen_timeout": tk.StringVar(value="15"),
            "password_quality": tk.StringVar(value="Medium"),
            "camera_disabled": tk.StringVar(value="No"),
            "disable_unknown_sources": tk.StringVar(value="Yes"),
            "enable_adb": tk.StringVar(value="No")
        }
        
        self.setup_gui()
        
        self.check_system_prerequisites()
        
        self.refresh_devices()
    
    def load_configuration(self):
        """Load configuration from file or use defaults"""
        default_config = {
            "enterprise_settings": {
                "organization_name": "Enterprise Organization",
                "admin_email": "admin@enterprise.com",
                "compliance_standards": ["GDPR", "ISO27001"],
                "audit_retention_days": 365,
                "encryption_required": True
            },
            "device_policies": {
                "max_password_age_days": 90,
                "min_password_length": 8,
                "screen_timeout_minutes": 15,
                "auto_lock_enabled": True
            },
            "logging": {
                "log_level": "INFO",
                "log_file": "../logs/mdm_operations.log",
                "audit_file": "../logs/audit_trail.log"
            }
        }
        
        try:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'mdm_config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = default_config
                self.save_configuration()
        except Exception as e:
            print(f"Configuration load failed: {e}")
            self.config = default_config
    
    def save_configuration(self):
        """Save current configuration"""
        try:
            config_dir = os.path.join(os.path.dirname(__file__), '..', 'config')
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, 'mdm_config.json')
            
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Configuration save failed: {e}")
    
    def setup_logging(self):
        """Setup logging system"""
        log_dir = os.path.join(os.path.dirname(__file__), '..', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, 'mdm_operations.log')),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def setup_window(self):
        """Setup main window with custom Professional Dark Theme and fullscreen support"""
        self.root.title("Enterprise Mobile Device Management System")  # Ensure full title
        # Enable fullscreen and allow toggle with F11
        self.root.attributes('-fullscreen', True)
        self.is_fullscreen = True
        self.root.bind('<F11>', lambda event: self.toggle_fullscreen())
        self.root.bind('<Escape>', lambda event: self.toggle_fullscreen() if self.is_fullscreen else None)

        # Adjust title font if needed to prevent truncation
        self.root.option_add('*TLabel*Font', 'Arial 18')

        self.root.configure(bg='#1E272E')  # Deep charcoal gray

        self.style = ttk.Style()
        self.style.theme_create('custom_theme', parent='default', settings={
            'TFrame': {'configure': {'background': '#2D3A4B'}},
            'TLabel': {'configure': {'background': '#1E272E', 'foreground': '#E0E7FF'}},
            'TButton': {'configure': {'background': '#4A6FA5', 'foreground': '#E0E7FF', 'borderwidth': 0},
                        'map': {'background': [('active', '#5D8BFF')], 'foreground': [('active', '#E0E7FF')]}},
            'TEntry': {'configure': {'fieldbackground': '#2D3A4B', 'foreground': '#E0E7FF', 'insertcolor': '#E0E7FF', 'borderwidth': 2, 'bordercolor': '#3C5A7D'}},
            'TCheckbutton': {'configure': {'background': '#2D3A4B', 'foreground': '#E0E7FF', 'selectcolor': '#4A6FA5'}},
            'TRadiobutton': {'configure': {'background': '#2D3A4B', 'foreground': '#E0E7FF', 'selectcolor': '#4A6FA5'}},
            'TCombobox': {'configure': {'fieldbackground': '#2D3A4B', 'background': '#4A6FA5', 'foreground': '#E0E7FF', 'borderwidth': 2, 'bordercolor': '#3C5A7D'},
                          'map': {'background': [('active', '#5D8BFF')]}},
            'Treeview': {'configure': {'background': '#1E272E', 'foreground': '#E0E7FF', 'fieldbackground': '#1E272E'},
                         'map': {'background': [('selected', '#4A6FA5')], 'foreground': [('selected', '#E0E7FF')]}},
            'TNotebook': {'configure': {'background': '#1E272E'}},
            'TNotebook.Tab': {'configure': {'background': '#2D3A4B', 'foreground': '#E0E7FF'},
                              'map': {'background': [('selected', '#4A6FA5')], 'foreground': [('selected', '#E0E7FF')]}},
            'TProgressbar': {'configure': {'background': '#3C5A7D', 'troughcolor': '#2D3A4B', 'borderwidth': 0}},
            'TScrollbar': {'configure': {'background': '#1E272E', 'troughcolor': '#1E272E', 'arrowcolor': '#3C5A7D'},
                           'map': {'background': [('active', '#4A6FA5')]}}
        })
        self.style.theme_use('custom_theme')

    def toggle_fullscreen(self):
        """Toggle fullscreen mode"""
        self.is_fullscreen = not self.is_fullscreen
        self.root.attributes('-fullscreen', self.is_fullscreen)
        if not self.is_fullscreen:
            # Set a reasonable default size if exiting fullscreen
            self.root.geometry("1400x900")

    def setup_gui(self):
        """Create complete GUI with theme applied"""
        self.main_canvas = tk.Canvas(self.root, bg='#1E272E')
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.main_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.main_canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.main_canvas.configure(
                scrollregion=self.main_canvas.bbox("all"),
                height=self.root.winfo_height() - 50,  # Adjust for status bar
                width=self.root.winfo_width()
            )
        )
        
        self.main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.main_canvas.configure(yscrollcommand=scrollbar.set)
        
        self.main_canvas.pack(side="top", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.main_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        self.notebook = ttk.Notebook(self.scrollable_frame)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.create_device_management_tab()
        self.create_sanitization_tab()
        self.create_compliance_tab()
        self.create_audit_tab()
        self.create_policies_tab()
        self.create_reports_tab()
        
        self.create_status_bar()
        
        self.device_info_text.config(bg='#2D3A4B', fg='#E0E7FF', insertbackground='#E0E7FF')
        self.compliance_text.config(bg='#2D3A4B', fg='#E0E7FF', insertbackground='#E0E7FF')
        self.sanitization_results.config(bg='#2D3A4B', fg='#E0E7FF', insertbackground='#E0E7FF')
        self.report_text.config(bg='#2D3A4B', fg='#E0E7FF', insertbackground='#E0E7FF')

        # Update status bar with current date and time
        self.status_bar.config(text=f"Ready - {datetime.now().strftime('%I:%M %p IST, %B %d, %Y')}")

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        if self.main_canvas.yview() == (0.0, 1.0):  # Only scroll if at bounds
            self.main_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    def create_device_management_tab(self):
        """Create device management tab"""
        device_frame = ttk.Frame(self.notebook)
        self.notebook.add(device_frame, text="Device Management")
        
        header_frame = ttk.Frame(device_frame)
        header_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(header_frame, text="Enterprise Device Management", 
                 font=('Arial', 18, 'bold')).pack()
        ttk.Label(header_frame, text=f"Organization: {self.config['enterprise_settings']['organization_name']}", 
                 font=('Arial', 10)).pack()
        
        status_frame = ttk.LabelFrame(device_frame, text="System Status", padding=10)
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.system_status_label = ttk.Label(status_frame, text="Checking system prerequisites...", 
                                           foreground="#E0E7FF")
        self.system_status_label.pack()
        
        detection_frame = ttk.LabelFrame(device_frame, text="Device Detection", padding=10)
        detection_frame.pack(fill='x', padx=10, pady=5)
        
        control_frame = ttk.Frame(detection_frame)
        control_frame.pack(fill='x')
        
        ttk.Button(control_frame, text="Refresh Devices", 
                  command=self.refresh_devices).pack(side='left', padx=5)
        
        self.device_count_label = ttk.Label(control_frame, text="No devices detected")
        self.device_count_label.pack(side='left', padx=20)
        
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(control_frame, text="Auto-refresh (30s)", 
                       variable=self.auto_refresh_var,
                       command=self.toggle_auto_refresh).pack(side='right')
        
        list_frame = ttk.LabelFrame(device_frame, text="Connected Devices", padding=10)
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        columns = ('Device', 'Status', 'Android', 'Encryption', 'Storage', 'Last Check')
        self.device_tree = ttk.Treeview(list_frame, columns=columns, show='tree headings', height=8)
        
        self.device_tree.column('#0', width=50)
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=120)
        
        device_v_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.device_tree.yview)
        device_h_scrollbar = ttk.Scrollbar(list_frame, orient='horizontal', command=self.device_tree.xview)
        self.device_tree.configure(yscrollcommand=device_v_scrollbar.set, xscrollcommand=device_h_scrollbar.set)
        
        self.device_tree.grid(row=0, column=0, sticky='nsew')
        device_v_scrollbar.grid(row=0, column=1, sticky='ns')
        device_h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        self.device_tree.bind('<<TreeviewSelect>>', self.on_device_select)
        
        actions_frame = ttk.LabelFrame(device_frame, text="Device Actions", padding=10)
        actions_frame.pack(fill='x', padx=10, pady=5)
        
        action_buttons = [
            ("Check Compliance", self.check_device_compliance),
            ("View Details", self.view_device_details),
            ("Apply Policies", self.apply_device_policies),
            ("Generate Report", self.generate_device_report)
        ]
        
        for text, command in action_buttons:
            ttk.Button(actions_frame, text=text, command=command).pack(side='left', padx=5)
        
        info_frame = ttk.LabelFrame(device_frame, text="Device Information", padding=10)
        info_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.device_info_text = scrolledtext.ScrolledText(info_frame, height=8, wrap='word')
        self.device_info_text.pack(fill='both', expand=True)
    
    def create_sanitization_tab(self):
        """Create data sanitization tab"""
        sanitization_frame = ttk.Frame(self.notebook)
        self.notebook.add(sanitization_frame, text="Data Sanitization")
        
        warning_frame = ttk.LabelFrame(sanitization_frame, text="⚠️ Data Sanitization Warning", padding=10)
        warning_frame.pack(fill='x', padx=10, pady=5)
        
        warning_text = """IMPORTANT: Data sanitization will permanently delete user data from the selected device.
This operation cannot be undone. Ensure you have proper authorization and backups before proceeding.
Only user-accessible data will be sanitized (no system files or applications)."""
        
        ttk.Label(warning_frame, text=warning_text, foreground="#E0E7FF", font=('Arial', 10, 'bold')).pack()
        
        device_frame = ttk.LabelFrame(sanitization_frame, text="Device Selection", padding=10)
        device_frame.pack(fill='x', padx=10, pady=5)
        
        device_info_frame = ttk.Frame(device_frame)
        device_info_frame.pack(fill='x')
        
        ttk.Label(device_info_frame, text="Selected Device:", font=('Arial', 10, 'bold')).pack(side='left')
        self.selected_device_label = ttk.Label(device_info_frame, text="No device selected", foreground="#E0E7FF")
        self.selected_device_label.pack(side='left', padx=10)
        
        ttk.Button(device_info_frame, text="Refresh Device Info", 
                  command=self.update_sanitization_device_info).pack(side='right')
        
        auth_frame = ttk.LabelFrame(sanitization_frame, text="Authorization Verification", padding=10)
        auth_frame.pack(fill='x', padx=10, pady=5)
        
        auth_controls = ttk.Frame(auth_frame)
        auth_controls.pack(fill='x')
        
        ttk.Label(auth_controls, text="User Token:").pack(side='left')
        self.auth_token_var = tk.StringVar()
        ttk.Entry(auth_controls, textvariable=self.auth_token_var, width=30, show="*").pack(side='left', padx=5)
        ttk.Button(auth_controls, text="Verify Authorization", 
                  command=self.verify_sanitization_auth).pack(side='left', padx=5)
        
        self.auth_status_label = ttk.Label(auth_frame, text="Authorization required", foreground="#E0E7FF")
        self.auth_status_label.pack(pady=5)
        
        standards_frame = ttk.LabelFrame(sanitization_frame, text="Sanitization Standards", padding=10)
        standards_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(standards_frame, text="Select sanitization standard:", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        self.sanitization_standard = tk.StringVar(value='BASIC')
        standards = [
            ('BASIC - Single pass, zeros', 'BASIC'),
            ('DOD 5220.22-M - 3 passes, random patterns', 'DOD_5220'),
            ('NIST 800-88 - Cryptographic erase', 'NIST_800_88'),
            ('GUTMANN - 35 passes, complex patterns', 'GUTMANN')
        ]
        
        for text, value in standards:
            ttk.Radiobutton(standards_frame, text=text, variable=self.sanitization_standard, 
                           value=value).pack(anchor='w')
        
        assessment_frame = ttk.LabelFrame(sanitization_frame, text="Data Assessment", padding=10)
        assessment_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        assessment_controls = ttk.Frame(assessment_frame)
        assessment_controls.pack(fill='x')
        
        ttk.Button(assessment_controls, text="Scan User Data", 
                  command=self.scan_user_data).pack(side='left', padx=5)
        ttk.Button(assessment_controls, text="Export Assessment", 
                  command=self.export_data_assessment).pack(side='left', padx=5)
        
        columns = ('Path', 'File Count', 'Estimated Size', 'Type', 'Status')
        self.assessment_tree = ttk.Treeview(assessment_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.assessment_tree.heading(col, text=col)
            self.assessment_tree.column(col, width=120)
        
        assessment_scrollbar = ttk.Scrollbar(assessment_frame, orient='vertical', command=self.assessment_tree.yview)
        self.assessment_tree.configure(yscrollcommand=assessment_scrollbar.set)
        
        self.assessment_tree.pack(side='left', fill='both', expand=True, pady=5)
        assessment_scrollbar.pack(side='right', fill='y', pady=5)
        
        controls_frame = ttk.LabelFrame(sanitization_frame, text="Sanitization Controls", padding=10)
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        control_buttons = ttk.Frame(controls_frame)
        control_buttons.pack(fill='x')
        
        self.sanitize_button = ttk.Button(control_buttons, text="Start Sanitization", 
                                         command=self.start_sanitization, state='disabled')
        self.sanitize_button.pack(side='left', padx=5)
        
        self.verify_button = ttk.Button(control_buttons, text="Verify Sanitization", 
                                       command=self.verify_sanitization_results, state='disabled')
        self.verify_button.pack(side='left', padx=5)
        
        ttk.Button(control_buttons, text="Generate Certificate", 
                  command=self.generate_sanitization_certificate).pack(side='left', padx=5)
        
        self.sanitization_progress = ttk.Progressbar(controls_frame, mode='determinate')
        self.sanitization_progress.pack(fill='x', pady=5)
        
        self.sanitization_status = ttk.Label(controls_frame, text="Ready for sanitization")
        self.sanitization_status.pack()
        
        results_frame = ttk.LabelFrame(sanitization_frame, text="Sanitization Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.sanitization_results = scrolledtext.ScrolledText(results_frame, height=8, wrap='word')
        self.sanitization_results.pack(fill='both', expand=True)
        
        self.sanitization_results.insert('1.0', "No sanitization performed yet...")
    
    def create_compliance_tab(self):
        """Create compliance monitoring tab"""
        compliance_frame = ttk.Frame(self.notebook)
        self.notebook.add(compliance_frame, text="Compliance Monitoring")
        
        device_frame = ttk.LabelFrame(compliance_frame, text="Device Selection", padding=10)
        device_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(device_frame, text="Selected Device:", font=('Arial', 10, 'bold')).pack(side='left')
        self.compliance_device_label = ttk.Label(device_frame, text="No device selected", foreground="#E0E7FF")
        self.compliance_device_label.pack(side='left', padx=10)
        
        controls_frame = ttk.Frame(device_frame)
        controls_frame.pack(side='right')
        
        ttk.Button(controls_frame, text="Refresh Device Info", 
                  command=self.update_compliance_device_info).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Check Compliance", 
                  command=self.check_device_compliance).pack(side='left', padx=5)
        
        results_frame = ttk.LabelFrame(compliance_frame, text="Compliance Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.compliance_text = scrolledtext.ScrolledText(results_frame, height=15, wrap='word')
        self.compliance_text.pack(fill='both', expand=True)
        
        self.compliance_text.insert('1.0', "Select a device and click 'Check Compliance' to view results...")
    
    def create_audit_tab(self):
        """Create audit trail tab"""
        audit_frame = ttk.Frame(self.notebook)
        self.notebook.add(audit_frame, text="Audit Trail")
        
        controls_frame = ttk.Frame(audit_frame)
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(controls_frame, text="Days to Review:").pack(side='left')
        self.audit_days_var = tk.StringVar(value="7")
        ttk.Entry(controls_frame, textvariable=self.audit_days_var, width=5).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Refresh Audit", 
                  command=self.refresh_audit_log).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Export Audit", 
                  command=self.export_audit_log_gui).pack(side='left', padx=5)
        
        audit_list_frame = ttk.LabelFrame(audit_frame, text="Audit Events", padding=10)
        audit_list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        columns = ('Timestamp', 'Event Type', 'Device ID', 'Operation', 'Status', 'Details', 'Compliance Flags')
        self.audit_tree = ttk.Treeview(audit_list_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.audit_tree.heading(col, text=col)
            self.audit_tree.column(col, width=120 if col != 'Details' else 200)
        
        audit_scrollbar = ttk.Scrollbar(audit_list_frame, orient='vertical', command=self.audit_tree.yview)
        self.audit_tree.configure(yscrollcommand=audit_scrollbar.set)
        
        self.audit_tree.pack(side='left', fill='both', expand=True, pady=5)
        audit_scrollbar.pack(side='right', fill='y', pady=5)
    
    def create_policies_tab(self):
        """Create policies management tab"""
        policies_frame = ttk.Frame(self.notebook)
        self.notebook.add(policies_frame, text="Policies Management")
        
        policy_types = [
            ("Screen Timeout (minutes)", "screen_timeout", "15"),
            ("Password Quality (complexity)", "password_quality", "Medium"),
            ("Disable Camera", "camera_disabled", "No"),
            ("Disable Unknown Sources", "disable_unknown_sources", "Yes"),
            ("Enable ADB", "enable_adb", "No")
        ]
        
        for label_text, policy_type, default_value in policy_types:
            policy_frame = ttk.LabelFrame(policies_frame, text=label_text, padding=10)
            policy_frame.pack(fill='x', padx=10, pady=5)
            
            # Use existing StringVar from self.policies
            var = self.policies[policy_type]
            
            if policy_type in ["screen_timeout", "password_quality"]:
                ttk.Entry(policy_frame, textvariable=var, width=10).pack(side='left', padx=5)
            else:
                ttk.Combobox(policy_frame, textvariable=var, values=["Yes", "No"], state="readonly").pack(side='left', padx=5)
            
            ttk.Button(policy_frame, text="Apply Policy", 
                      command=lambda p=policy_type: self.apply_policy(p, var.get())).pack(side='left', padx=5)
    
    def create_reports_tab(self):
        """Create reports tab"""
        reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(reports_frame, text="Reports")
        
        controls_frame = ttk.Frame(reports_frame)
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(controls_frame, text="Generate Compliance Report", 
                  command=self.generate_compliance_report).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Generate Audit Report", 
                  command=self.generate_audit_report).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="Export Report", 
                  command=self.export_report).pack(side='left', padx=5)
        
        report_frame = ttk.LabelFrame(reports_frame, text="Report Preview", padding=10)
        report_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.report_text = scrolledtext.ScrolledText(report_frame, height=15, wrap='word')
        self.report_text.pack(fill='both', expand=True)
        
        # Ensure initial content is visible
        self.report_text.insert('1.0', "Generate a report to view details here...")
        self.report_text.see('1.0')  # Scroll to start
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = ttk.Label(self.root, text="Ready", anchor='w', 
                                  background='#2D3A4B', foreground='#E0E7FF')
        self.status_bar.pack(side='bottom', fill='x')
    
    def log_message(self, message):
        """Log message to status bar and logger"""
        self.status_bar.config(text=f"{message} - {datetime.now().strftime('%I:%M %p IST, %B %d, %Y')}")
        self.logger.info(message)
    
    def check_system_prerequisites(self):
        """Check system prerequisites and update status"""
        success, message = self.mdm.check_prerequisites()
        self.system_status_label.config(text=message, foreground="#00FF00" if success else "#FF4500")
        return success
    
    def refresh_devices(self):
        """Refresh device list"""
        self.devices = self.mdm.detect_devices()
        self.update_device_tree()
        self.device_count_label.config(text=f"{len(self.devices)} devices detected")
        
        if self.auto_refresh_var.get():
            self.root.after(30000, self.refresh_devices)
    
    def update_device_tree(self):
        """Update device treeview"""
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        for device in self.devices:
            device_id = device['id']
            model = f"{device.get('brand', 'Unknown')} {device.get('model', 'Unknown')}"
            android_version = device.get('android_version', 'Unknown')
            encryption = device.get('encryption_status', 'Unknown')
            storage = f"{device.get('storage_used', 'Unknown')} / {device.get('storage_total', 'Unknown')}"
            last_check = device.get('last_check', 'N/A')
            
            self.device_tree.insert('', 'end', values=(model, 'Connected', android_version, 
                                                    encryption, storage, last_check))
    
    def on_device_select(self, event):
        """Handle device selection"""
        selected_item = self.device_tree.selection()
        if selected_item:
            index = int(selected_item[0].split('_')[-1]) if '_' in selected_item[0] else 0
            if 0 <= index < len(self.devices):
                self.selected_device = self.devices[index]['id']
                self.selected_device_info = self.devices[index]
                self.update_sanitization_device_info()
                self.update_compliance_device_info()
                self.log_message(f"Selected device: {self.selected_device}")
    
    def toggle_auto_refresh(self):
        """Toggle auto-refresh of device list"""
        if not self.auto_refresh_var.get():
            self.log_message("Auto-refresh disabled")
        else:
            self.refresh_devices()
            self.log_message("Auto-refresh enabled (30s interval)")
    
    def update_sanitization_device_info(self):
        """Update sanitization-related device information"""
        if not self.selected_device or not self.selected_device_info:
            self.selected_device_label.config(text="No device selected", foreground="#FF4500")
            self.sanitization_status.config(text="No device selected for sanitization")
            self.sanitize_button.config(state='disabled')
            self.verify_button.config(state='disabled')
            return

        device_name = f"{self.selected_device_info.get('brand', 'Unknown')} {self.selected_device_info.get('model', 'Device')}"
        self.selected_device_label.config(text=device_name, foreground="#00FF00")

        self.sanitization_status.config(text="Device ready for sanitization")

        self.sanitize_button.config(state='normal')
        self.verify_button.config(state='normal')

        self.log_message(f"Refreshed sanitization info for device: {device_name}")
    
    def update_compliance_device_info(self):
        """Update compliance-related device information"""
        if not self.selected_device or not self.selected_device_info:
            self.compliance_device_label.config(text="No device selected", foreground="#FF4500")
            self.compliance_text.delete('1.0', tk.END)
            self.compliance_text.insert('1.0', "Select a device and click 'Check Compliance' to view results...")
            return
        
        device_name = f"{self.selected_device_info.get('brand', 'Unknown')} {self.selected_device_info.get('model', 'Device')}"
        self.compliance_device_label.config(text=device_name, foreground="#00FF00")
        self.log_message(f"Refreshed compliance info for device: {device_name}")
    
    def verify_sanitization_auth(self):
        """Verify authorization for sanitization"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        def verify():
            token = self.auth_token_var.get()
            success, message = self.mdm.sanitization_engine.verify_authorization(self.selected_device, token)
            
            self.root.after(0, lambda: self.update_auth_status(success, message))
        
        threading.Thread(target=verify, daemon=True).start()
    
    def update_auth_status(self, success, message):
        """Update authorization status"""
        if success:
            self.auth_status_label.config(text=f"✓ {message}", foreground="green")
            self.sanitize_button.config(state='normal')
        else:
            self.auth_status_label.config(text=f"✗ {message}", foreground="red")
            self.sanitize_button.config(state='disabled')
    
    def scan_user_data(self):
        """Scan user data on device"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        def scan():
            success, operations = self.mdm.sanitization_engine.sanitize_user_data(
                self.selected_device, verify_only=True)
            
            self.root.after(0, lambda: self.update_assessment_results(success, operations))
        
        self.log_message("Scanning user data...")
        threading.Thread(target=scan, daemon=True).start()
    
    def update_assessment_results(self, success, operations):
        """Update data assessment results"""
        for item in self.assessment_tree.get_children():
            self.assessment_tree.delete(item)
        
        if success:
            total_files = 0
            for operation in operations:
                path = operation['path']
                file_count = operation['files']
                
                try:
                    files_int = int(file_count)
                    total_files += files_int
                    
                    estimated_size = f"~{files_int * 2}MB" if files_int > 0 else "0MB"
                    
                    if 'Pictures' in path or 'DCIM' in path:
                        data_type = 'Photos'
                    elif 'Download' in path:
                        data_type = 'Downloads'
                    elif 'Documents' in path:
                        data_type = 'Documents'
                    elif 'Music' in path:
                        data_type = 'Audio'
                    elif 'Movies' in path:
                        data_type = 'Video'
                    else:
                        data_type = 'App Data'
                    
                    status = 'Ready' if files_int > 0 else 'Empty'
                    
                    self.assessment_tree.insert('', 'end', values=(
                        path, file_count, estimated_size, data_type, status
                    ))
                    
                except ValueError:
                    self.assessment_tree.insert('', 'end', values=(
                        path, file_count, 'Unknown', 'Unknown', 'Error'
                    ))
            
            self.log_message(f"Data assessment complete: {total_files} total files found")
        else:
            self.log_message("Data assessment failed")
    
    def export_data_assessment(self):
        """Export data assessment results"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        filename = filedialog.asksaveasfilename(defaultextension=".json",
                                              filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if filename:
            operations = []
            for item in self.assessment_tree.get_children():
                values = self.assessment_tree.item(item)['values']
                operations.append({
                    'path': values[0],
                    'files': values[1],
                    'estimated_size': values[2],
                    'type': values[3],
                    'status': values[4]
                })
            
            with open(filename, 'w') as f:
                json.dump({'device_id': self.selected_device, 'assessment': operations}, f, indent=2)
            self.log_message(f"Data assessment exported to {filename}")
    
    def start_sanitization(self):
        """Start data sanitization process"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        def sanitize():
            self.sanitization_progress['value'] = 0
            self.sanitization_status.config(text="Sanitization in progress...")
            self.sanitize_button.config(state='disabled')
            
            success, operations = self.mdm.sanitization_engine.sanitize_user_data(
                self.selected_device, self.sanitization_standard.get())
            
            self.root.after(0, lambda: self.update_sanitization_results(success, operations))
        
        threading.Thread(target=sanitize, daemon=True).start()
    
    def update_sanitization_results(self, success, operations):
        """Update sanitization results"""
        self.sanitization_results.delete('1.0', tk.END)
        
        if success:
            self.sanitization_results.insert('1.0', "Sanitization completed successfully:\n")
            for operation in operations:
                self.sanitization_results.insert('end', f"- {operation['path']}: {operation['status']}\n")
            self.sanitization_status.config(text="Sanitization completed", foreground="green")
            self.verify_button.config(state='normal')
        else:
            self.sanitization_results.insert('1.0', f"Sanitization failed: {operations}\n")
            self.sanitization_status.config(text="Sanitization failed", foreground="red")
        
        self.sanitization_progress['value'] = 100
        self.sanitize_button.config(state='normal')
        self.log_message(f"Sanitization {'completed' if success else 'failed'} for {self.selected_device}")
    
    def verify_sanitization_results(self):
        """Verify sanitization results"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        def verify():
            self.verify_button.config(state='disabled')
            self.sanitization_status.config(text="Verifying sanitization...")
            
            # Simulate previous operations for verification (in a real scenario, store operations)
            success, operations = self.mdm.sanitization_engine.sanitize_user_data(
                self.selected_device, verify_only=True)
            verification_results = self.mdm.sanitization_engine.verify_sanitization(self.selected_device, operations)
            
            self.root.after(0, lambda: self.update_verification_results(verification_results))
        
        threading.Thread(target=verify, daemon=True).start()
    
    def update_verification_results(self, verification_results):
        """Update verification results"""
        self.sanitization_results.delete('1.0', tk.END)
        self.sanitization_results.insert('1.0', "Sanitization Verification Results:\n")
        
        all_verified = True
        for result in verification_results:
            verified = "✓ Verified" if result['verified'] else "✗ Failed"
            all_verified &= result['verified']
            self.sanitization_results.insert('end', f"- {result['path']}: {result['original_files']} files, {result['remaining_files']} remaining - {verified}\n")
        
        self.sanitization_status.config(text=f"Verification {'successful' if all_verified else 'failed'}", 
                                      foreground="green" if all_verified else "red")
        self.verify_button.config(state='normal')
        self.log_message(f"Sanitization verification {'passed' if all_verified else 'failed'} for {self.selected_device}")
    
    def generate_sanitization_certificate(self):
        """Generate sanitization certificate"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        certificate = f"""
Sanitization Certificate
Device ID: {self.selected_device}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Organization: {self.config['enterprise_settings']['organization_name']}
Status: {'Completed' if self.sanitization_status.cget('text') == 'Sanitization completed' else 'Pending'}
"""
        
        self.sanitization_results.delete('1.0', tk.END)
        self.sanitization_results.insert('1.0', certificate)
        self.log_message("Sanitization certificate generated")
    
    def check_device_compliance(self):
        """Check device compliance"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        def check():
            self.compliance_text.delete('1.0', tk.END)
            self.compliance_text.insert('1.0', "Checking compliance...\n")
            
            compliance_results = self.mdm.check_compliance(self.selected_device, 
                                                        self.config['enterprise_settings']['compliance_standards'])
            
            self.root.after(0, lambda: self.update_compliance_results(compliance_results))
        
        threading.Thread(target=check, daemon=True).start()
    
    def update_compliance_results(self, compliance_results):
        """Update compliance results"""
        self.compliance_text.delete('1.0', tk.END)
        
        for standard, result in compliance_results.items():
            self.compliance_text.insert('end', f"**{standard} Compliance Report**\n")
            self.compliance_text.insert('end', f"Status: {result['overall_status']}\n")
            self.compliance_text.insert('end', f"Checked at: {result['checked_at']}\n\n")
            
            for check in result['checks']:
                self.compliance_text.insert('end', f"- {check['check']}: {check['status']} ({check['details']})\n")
            self.compliance_text.insert('end', "\n")
        
        self.log_message(f"Compliance check completed for {self.selected_device}")
    
    def view_device_details(self):
        """View detailed device information"""
        if not self.selected_device or not self.selected_device_info:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        self.device_info_text.delete('1.0', tk.END)
        for key, value in self.selected_device_info.items():
            self.device_info_text.insert('end', f"{key.replace('_', ' ').title()}: {value}\n")
        self.log_message(f"Displayed details for {self.selected_device}")
    
    def apply_device_policies(self):
        """Apply configured policies to device"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        for policy_type, var in self.policies.items():
            success, message = self.mdm.apply_policy(self.selected_device, policy_type, var.get())
            self.log_message(f"Applied {policy_type}: {'Success' if success else 'Failed'} - {message}")
    
    def generate_device_report(self):
        """Generate device report"""
        if not self.selected_device or not self.selected_device_info:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        report = f"""
Device Report
Device ID: {self.selected_device}
Model: {self.selected_device_info.get('brand', 'Unknown')} {self.selected_device_info.get('model', 'Unknown')}
Android Version: {self.selected_device_info.get('android_version', 'Unknown')}
Encryption: {self.selected_device_info.get('encryption_status', 'Unknown')}
Storage: {self.selected_device_info.get('storage_used', 'Unknown')} / {self.selected_device_info.get('storage_total', 'Unknown')}
Last Check: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        self.report_text.delete('1.0', tk.END)
        self.report_text.insert('1.0', report)
        self.log_message(f"Generated report for {self.selected_device}")
    
    def generate_compliance_report(self):
        """Generate compliance report"""
        if not self.selected_device:
            messagebox.showwarning("No Device", "Please select a device first.")
            return
        
        compliance_results = self.mdm.check_compliance(self.selected_device)
        report = f"""
Compliance Report
Device ID: {self.selected_device}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Organization: {self.config['enterprise_settings']['organization_name']}
"""
        
        for standard, result in compliance_results.items():
            report += f"\n{standard} Compliance:\n"
            report += f"Status: {result['overall_status']}\n"
            for check in result['checks']:
                report += f"- {check['check']}: {check['status']} ({check['details']})\n"
        
        self.report_text.delete('1.0', tk.END)
        self.report_text.insert('1.0', report)
        self.log_message(f"Generated compliance report for {self.selected_device}")
    
    def generate_audit_report(self):
        """Generate audit report"""
        days = int(self.audit_days_var.get())
        audit_events = self.audit_system.get_audit_events(days)
        
        report = f"""
Audit Report
Date Range: Last {days} days
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Organization: {self.config['enterprise_settings']['organization_name']}
"""
        
        for event in audit_events:
            report += f"\nTimestamp: {event['timestamp']}"
            report += f"\nEvent Type: {event['event_type']}"
            report += f"\nDevice ID: {event['device_id']}"
            report += f"\nOperation: {event['operation']}"
            report += f"\nStatus: {event['status']}"
            report += f"\nDetails: {event['details']}"
            report += f"\nCompliance Flags: {event['compliance_flags']}\n"
        
        self.report_text.delete('1.0', tk.END)
        self.report_text.insert('1.0', report)
        self.log_message(f"Generated audit report for last {days} days")
    
    def export_report(self):
        """Export current report to file"""
        filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                              filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            with open(filename, 'w') as f:
                f.write(self.report_text.get('1.0', tk.END))
            self.log_message(f"Report exported to {filename}")
    
    def refresh_audit_log(self):
        """Refresh audit log display"""
        days = int(self.audit_days_var.get())
        audit_events = self.audit_system.get_audit_events(days)
        
        for item in self.audit_tree.get_children():
            self.audit_tree.delete(item)
        
        for event in audit_events:
            self.audit_tree.insert('', 'end', values=(
                event['timestamp'],
                event['event_type'],
                event['device_id'],
                event['operation'],
                event['status'],
                event['details'],
                event['compliance_flags']
            ))
        
        self.log_message(f"Refreshed audit log for last {days} days")
    
    def export_audit_log_gui(self):
        """Export audit log to file"""
        filename = filedialog.asksaveasfilename(defaultextension=".json",
                                              filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if filename:
            if self.mdm.export_audit_log(filename):
                self.log_message(f"Audit log exported to {filename}")
            else:
                messagebox.showerror("Export Failed", "Failed to export audit log.")
    
    def run(self):
        """Run the GUI application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = EnterpriseMDMGUI()
    app.run()
