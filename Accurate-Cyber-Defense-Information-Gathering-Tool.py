#!/usr/bin/env python3
"""
Cyber Security Monitoring Tool
A comprehensive network security tool for port scanning, service detection,
and real-time monitoring with Telegram integration.
"""

import argparse
import asyncio
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Any

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration defaults
DEFAULT_CONFIG = {
    "scan_interval": 300,  # 5 minutes
    "timeout": 2,  # Socket timeout in seconds
    "max_workers": 50,  # Thread pool size for scanning
    "telegram": {
        "token": "",
        "chat_id": "",
        "enabled": False
    },
    "monitored_ips": {}
}

# Service mapping for common ports
COMMON_SERVICES = {
    7: "echo",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    43: "whois",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    115: "sftp",
    119: "nntp",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    179: "bgp",
    194: "irc",
    389: "ldap",
    443: "https",
    445: "smb",
    514: "syslog",
    515: "printer",
    587: "smtps",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1723: "pptp",
    1900: "upnp",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2086: "whm",
    2087: "whm-ssl",
    2095: "webmail",
    2096: "webmail-ssl",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-ssl",
    2483: "oracle",
    2484: "oracle-ssl",
    3000: "nodejs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5500: "vnc",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5938: "teamviewer",
    6379: "redis",
    6443: "kubernetes",
    6666: "irc",
    6667: "irc",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "php-fpm",
    9042: "cassandra",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb",
    27019: "mongodb",
    28017: "mongodb",
    50000: "db2"
}

class CyberSecurityTool:
    def __init__(self):
        self.config = DEFAULT_CONFIG.copy()
        self.monitored_ips = {}  # IP: {last_scan: [], changes: []}
        self.scanning_active = False
        self.scan_thread = None
        self.history = deque(maxlen=1000)  # Store last 1000 events
        self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        config_path = os.path.expanduser("~/.cyber_security_tool.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    saved_config = json.load(f)
                    # Merge with default config
                    for key, value in saved_config.items():
                        if key in self.config and isinstance(self.config[key], dict) and isinstance(value, dict):
                            self.config[key].update(value)
                        else:
                            self.config[key] = value
            except Exception as e:
                self.log(f"Error loading config: {e}")
    
    def save_config(self):
        """Save configuration to file"""
        config_path = os.path.expanduser("~/.cyber_security_tool.json")
        try:
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self.log(f"Error saving config: {e}")
    
    def log(self, message: str, level: str = "INFO"):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        self.history.append(log_message)
    
    def ping_ip(self, ip: str) -> bool:
        """Ping an IP address to check if it's reachable"""
        try:
            # Use system ping command with timeout
            param = "-n" if sys.platform.lower().startswith("win") else "-c"
            command = ["ping", param, "1", "-W", "2", ip]
            return subprocess.call(command, stdout=subprocess.DEVNULL, 
                                 stderr=subprocess.DEVNULL) == 0
        except Exception:
            return False
    
    def get_service_name(self, port: int, banner: str = "") -> str:
        """Get service name from port number and optional banner"""
        service = COMMON_SERVICES.get(port, "unknown")
        
        # Try to refine based on banner if available
        if banner:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                service = "ssh"
            elif "http" in banner_lower:
                service = "http" if port != 443 else "https"
            elif "smtp" in banner_lower:
                service = "smtp"
            elif "ftp" in banner_lower:
                service = "ftp"
            elif "mysql" in banner_lower:
                service = "mysql"
        
        return service
    
    def scan_port(self, ip: str, port: int) -> Tuple[bool, str]:
        """Scan a single port and return status and banner if available"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.config["timeout"])
                result = s.connect_ex((ip, port))
                
                if result == 0:
                    # Try to get banner
                    try:
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            return True, banner
                    except:
                        pass
                    
                    return True, ""
                else:
                    return False, ""
        except Exception:
            return False, ""
    
    def scan_ports(self, ip: str, ports: List[int] = None) -> Dict[int, Dict[str, Any]]:
        """Scan multiple ports on an IP address"""
        if ports is None:
            # Scan common ports + top 1000 ports
            ports = list(COMMON_SERVICES.keys()) + list(range(1, 1001))
        
        open_ports = {}
        
        with ThreadPoolExecutor(max_workers=self.config["max_workers"]) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        service = self.get_service_name(port, banner)
                        open_ports[port] = {
                            "service": service,
                            "banner": banner,
                            "timestamp": datetime.now().isoformat()
                        }
                except Exception as e:
                    self.log(f"Error scanning port {port} on {ip}: {e}", "ERROR")
        
        return open_ports
    
    def start_monitoring(self, ip: str):
        """Start monitoring an IP address"""
        if ip in self.monitored_ips:
            self.log(f"Already monitoring {ip}")
            return
        
        if not self.ping_ip(ip):
            self.log(f"IP {ip} is not reachable", "WARNING")
        
        self.monitored_ips[ip] = {
            "last_scan": {},
            "changes": [],
            "start_time": datetime.now().isoformat()
        }
        
        # Do initial scan
        self.log(f"Starting initial scan for {ip}")
        open_ports = self.scan_ports(ip)
        self.monitored_ips[ip]["last_scan"] = open_ports
        
        self.log(f"Found {len(open_ports)} open ports on {ip}")
        self.save_config()
        
        # Send Telegram notification if configured
        if self.config["telegram"]["enabled"] and self.config["telegram"]["chat_id"]:
            self.send_telegram_message(
                f"🚨 Started monitoring {ip}\n"
                f"📊 Initial scan found {len(open_ports)} open ports"
            )
    
    def stop_monitoring(self, ip: str):
        """Stop monitoring an IP address"""
        if ip in self.monitored_ips:
            del self.monitored_ips[ip]
            self.log(f"Stopped monitoring {ip}")
            self.save_config()
            
            # Send Telegram notification if configured
            if self.config["telegram"]["enabled"] and self.config["telegram"]["chat_id"]:
                self.send_telegram_message(f"🛑 Stopped monitoring {ip}")
        else:
            self.log(f"Not monitoring {ip}", "WARNING")
    
    def monitoring_loop(self):
        """Main monitoring loop that runs in a separate thread"""
        while self.scanning_active:
            for ip in list(self.monitored_ips.keys()):
                try:
                    self.log(f"Scanning {ip}")
                    current_scan = self.scan_ports(ip)
                    previous_scan = self.monitored_ips[ip]["last_scan"]
                    
                    # Detect changes
                    changes = self.detect_changes(previous_scan, current_scan, ip)
                    
                    if changes:
                        self.monitored_ips[ip]["changes"].extend(changes)
                        self.monitored_ips[ip]["last_scan"] = current_scan
                        
                        # Send notifications for changes
                        for change in changes:
                            self.log(change["message"])
                            
                            if self.config["telegram"]["enabled"] and self.config["telegram"]["chat_id"]:
                                self.send_telegram_message(change["message"])
                    else:
                        self.log(f"No changes detected for {ip}")
                    
                except Exception as e:
                    self.log(f"Error monitoring {ip}: {e}", "ERROR")
            
            # Sleep until next scan
            time.sleep(self.config["scan_interval"])
    
    def detect_changes(self, old_scan: Dict, new_scan: Dict, ip: str) -> List[Dict]:
        """Detect changes between two scans"""
        changes = []
        
        # Check for newly opened ports
        for port, info in new_scan.items():
            if port not in old_scan:
                change_msg = f"🚨 NEW PORT OPENED on {ip}:{port} ({info['service']})"
                changes.append({
                    "type": "port_opened",
                    "port": port,
                    "service": info["service"],
                    "timestamp": datetime.now().isoformat(),
                    "message": change_msg
                })
        
        # Check for closed ports
        for port, info in old_scan.items():
            if port not in new_scan:
                change_msg = f"🚨 PORT CLOSED on {ip}:{port} ({info['service']})"
                changes.append({
                    "type": "port_closed",
                    "port": port,
                    "service": info["service"],
                    "timestamp": datetime.now().isoformat(),
                    "message": change_msg
                })
        
        # Check for service changes
        for port, new_info in new_scan.items():
            if port in old_scan:
                old_info = old_scan[port]
                if new_info["service"] != old_info["service"]:
                    change_msg = f"🔄 SERVICE CHANGE on {ip}:{port} " \
                                f"({old_info['service']} → {new_info['service']})"
                    changes.append({
                        "type": "service_change",
                        "port": port,
                        "old_service": old_info["service"],
                        "new_service": new_info["service"],
                        "timestamp": datetime.now().isoformat(),
                        "message": change_msg
                    })
        
        return changes
    
    def send_telegram_message(self, message: str) -> bool:
        """Send message via Telegram bot"""
        token = self.config["telegram"]["token"]
        chat_id = self.config["telegram"]["chat_id"]
        
        if not token or not chat_id:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML"
            }
            
            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.log(f"Telegram API error: {e}", "ERROR")
            return False
    
    def test_telegram_connection(self) -> bool:
        """Test Telegram bot connection"""
        token = self.config["telegram"]["token"]
        chat_id = self.config["telegram"]["chat_id"]
        
        if not token:
            self.log("Telegram token not configured", "ERROR")
            return False
        
        if not chat_id:
            self.log("Telegram chat ID not configured", "ERROR")
            return False
        
        try:
            # Test by getting bot info
            url = f"https://api.telegram.org/bot{token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                self.log(f"Telegram token invalid: {response.text}", "ERROR")
                return False
            
            # Test by sending a message
            test_msg = "🔒 Accurate Cyber Security Tool Test Message\n" \
                      "✅ Telegram notifications are working correctly!"
            
            if self.send_telegram_message(test_msg):
                self.log("Telegram connection test successful")
                return True
            else:
                self.log("Telegram connection test failed", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Telegram connection test failed: {e}", "ERROR")
            return False
    
    def config_telegram_token(self, token: str):
        """Configure Telegram bot token"""
        if not token.startswith("bot"):
            self.config["telegram"]["token"] = token
            self.save_config()
            self.log("Telegram token configured")
        else:
            self.log("Invalid Telegram token format", "ERROR")
    
    def config_telegram_chat_id(self, chat_id: str):
        """Configure Telegram chat ID"""
        if re.match(r"^-?\d+$", chat_id):
            self.config["telegram"]["chat_id"] = chat_id
            self.save_config()
            self.log("Telegram chat ID configured")
        else:
            self.log("Invalid Telegram chat ID format", "ERROR")
    
    def config_telegram(self, enabled: bool = None):
        """Enable or disable Telegram notifications"""
        if enabled is not None:
            self.config["telegram"]["enabled"] = enabled
            self.save_config()
            status = "enabled" if enabled else "disabled"
            self.log(f"Telegram notifications {status}")
        else:
            current = self.config["telegram"]["enabled"]
            status = "enabled" if current else "disabled"
            self.log(f"Telegram notifications are currently {status}")
    
    def view_status(self):
        """View monitoring status"""
        if not self.monitored_ips:
            self.log("No IP addresses being monitored")
            return
        
        self.log("=== MONITORING STATUS ===")
        for ip, info in self.monitored_ips.items():
            start_time = datetime.fromisoformat(info["start_time"]).strftime("%Y-%m-%d %H:%M")
            open_ports = len(info["last_scan"])
            changes = len(info["changes"])
            
            self.log(f"IP: {ip}")
            self.log(f"  Started: {start_time}")
            self.log(f"  Open ports: {open_ports}")
            self.log(f"  Changes detected: {changes}")
            
            if open_ports > 0:
                self.log("  Open ports:")
                for port, port_info in info["last_scan"].items():
                    self.log(f"    {port}/tcp - {port_info['service']}")
    
    def view_history(self, limit: int = 20):
        """View recent history"""
        self.log("=== RECENT HISTORY ===")
        for i, entry in enumerate(list(self.history)[-limit:]):
            self.log(f"{i+1}. {entry}")
    
    def start(self):
        """Start the monitoring service"""
        if self.scanning_active:
            self.log("Monitoring is already active")
            return
        
        self.scanning_active = True
        self.scan_thread = threading.Thread(target=self.monitoring_loop)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        self.log("Monitoring service started")
        
        # Send Telegram notification if configured
        if self.config["telegram"]["enabled"] and self.config["telegram"]["chat_id"]:
            self.send_telegram_message("🚀 Accurate Cyber Defense Security Monitoring Tool Started")
    
    def stop(self):
        """Stop the monitoring service"""
        if not self.scanning_active:
            self.log("Monitoring is not active")
            return
        
        self.scanning_active = False
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        
        self.log("Monitoring service stopped")
        
        # Send Telegram notification if configured
        if self.config["telegram"]["enabled"] and self.config["telegram"]["chat_id"]:
            self.send_telegram_message("🛑 Accurate Cyber Defense Monitoring Stopped")
    
    def exit_tool(self):
        """Cleanup and exit the tool"""
        self.stop()
        self.log("Exiting Accurate Cyber Defense Security Tool")
        sys.exit(0)

def main():
    """Main function with command line interface"""
    tool = CyberSecurityTool()
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Cyber Security Monitoring Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Ping command
    ping_parser = subparsers.add_parser("ping", help="Ping an IP address")
    ping_parser.add_argument("ip", help="IP address to ping")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan an IP address")
    scan_parser.add_argument("ip", help="IP address to scan")
    scan_parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 80,443 or 1-1000)")
    
    # Monitor commands
    monitor_parser = subparsers.add_parser("monitor", help="Start monitoring an IP address")
    monitor_parser.add_argument("ip", help="IP address to monitor")
    
    stop_monitor_parser = subparsers.add_parser("stop-monitor", help="Stop monitoring an IP address")
    stop_monitor_parser.add_argument("ip", help="IP address to stop monitoring")
    
    # Service commands
    subparsers.add_parser("start", help="Start the monitoring service")
    subparsers.add_parser("stop", help="Stop the monitoring service")
    subparsers.add_parser("status", help="Show monitoring status")
    subparsers.add_parser("history", help="Show recent history")
    
    # Telegram commands
    telegram_parser = subparsers.add_parser("telegram", help="Configure Telegram notifications")
    telegram_parser.add_argument("--enable", action="store_true", help="Enable Telegram notifications")
    telegram_parser.add_argument("--disable", action="store_true", help="Disable Telegram notifications")
    
    token_parser = subparsers.add_parser("set-token", help="Set Telegram bot token")
    token_parser.add_argument("token", help="Telegram bot token")
    
    chatid_parser = subparsers.add_parser("set-chatid", help="Set Telegram chat ID")
    chatid_parser.add_argument("chat_id", help="Telegram chat ID")
    
    subparsers.add_parser("test-telegram", help="Test Telegram connection")
    
    # Exit command
    subparsers.add_parser("exit", help="Exit the tool")
    
    # If no arguments provided, start interactive mode
    if len(sys.argv) == 1:
        print("Accurate Cyber Defense - Interactive Mode")
        print("Type 'help' for available commands")
        
        while True:
            try:
                command = input("\n> ").strip()
                if not command:
                    continue
                
                # Parse the command manually for interactive mode
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:]
                
                if cmd == "help":
                    print("Available commands:")
                    print("  ping <ip>              - Ping an IP address")
                    print("  scan <ip>              - Scan an IP address")
                    print("  monitor <ip>           - Start monitoring an IP")
                    print("  stop-monitor <ip>      - Stop monitoring an IP")
                    print("  start                  - Start monitoring service")
                    print("  stop                   - Stop monitoring service")
                    print("  status                 - Show monitoring status")
                    print("  history                - Show recent history")
                    print("  telegram --enable      - Enable Telegram notifications")
                    print("  telegram --disable     - Disable Telegram notifications")
                    print("  set-token <token>      - Set Telegram bot token")
                    print("  set-chatid <chat_id>   - Set Telegram chat ID")
                    print("  test-telegram          - Test Telegram connection")
                    print("  exit                   - Exit the tool")
                
                elif cmd == "ping" and len(args) >= 1:
                    ip = args[0]
                    if tool.ping_ip(ip):
                        print(f"{ip} is reachable")
                    else:
                        print(f"{ip} is not reachable")
                
                elif cmd == "scan" and len(args) >= 1:
                    ip = args[0]
                    ports = None
                    
                    if len(args) > 1:
                        port_arg = args[1]
                        if "-" in port_arg:
                            # Port range
                            start, end = map(int, port_arg.split("-"))
                            ports = list(range(start, end + 1))
                        else:
                            # Comma-separated ports
                            ports = list(map(int, port_arg.split(",")))
                    
                    print(f"Scanning {ip}...")
                    results = tool.scan_ports(ip, ports)
                    
                    if results:
                        print(f"Open ports on {ip}:")
                        for port, info in results.items():
                            print(f"  {port}/tcp - {info['service']}")
                            if info['banner']:
                                print(f"    Banner: {info['banner'][:100]}...")
                    else:
                        print(f"No open ports found on {ip}")
                
                elif cmd == "monitor" and len(args) >= 1:
                    ip = args[0]
                    tool.start_monitoring(ip)
                
                elif cmd == "stop-monitor" and len(args) >= 1:
                    ip = args[0]
                    tool.stop_monitoring(ip)
                
                elif cmd == "start":
                    tool.start()
                
                elif cmd == "stop":
                    tool.stop()
                
                elif cmd == "status":
                    tool.view_status()
                
                elif cmd == "history":
                    tool.view_history()
                
                elif cmd == "telegram":
                    if "--enable" in args:
                        tool.config_telegram(True)
                    elif "--disable" in args:
                        tool.config_telegram(False)
                    else:
                        tool.config_telegram()
                
                elif cmd == "set-token" and len(args) >= 1:
                    token = args[0]
                    tool.config_telegram_token(token)
                
                elif cmd == "set-chatid" and len(args) >= 1:
                    chat_id = args[0]
                    tool.config_telegram_chat_id(chat_id)
                
                elif cmd == "test-telegram":
                    tool.test_telegram_connection()
                
                elif cmd == "exit":
                    tool.exit_tool()
                
                else:
                    print("Unknown command. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\nExiting...")
                tool.exit_tool()
            except Exception as e:
                print(f"Error: {e}")
    
    else:
        # Parse command line arguments
        args = parser.parse_args()
        
        if args.command == "ping":
            if tool.ping_ip(args.ip):
                print(f"{args.ip} is reachable")
            else:
                print(f"{args.ip} is not reachable")
        
        elif args.command == "scan":
            ports = None
            if args.ports:
                if "-" in args.ports:
                    start, end = map(int, args.ports.split("-"))
                    ports = list(range(start, end + 1))
                else:
                    ports = list(map(int, args.ports.split(",")))
            
            print(f"Scanning {args.ip}...")
            results = tool.scan_ports(args.ip, ports)
            
            if results:
                print(f"Open ports on {args.ip}:")
                for port, info in results.items():
                    print(f"  {port}/tcp - {info['service']}")
                    if info['banner']:
                        print(f"    Banner: {info['banner'][:100]}...")
            else:
                print(f"No open ports found on {args.ip}")
        
        elif args.command == "monitor":
            tool.start_monitoring(args.ip)
        
        elif args.command == "stop-monitor":
            tool.stop_monitoring(args.ip)
        
        elif args.command == "start":
            tool.start()
        
        elif args.command == "stop":
            tool.stop()
        
        elif args.command == "status":
            tool.view_status()
        
        elif args.command == "history":
            tool.view_history()
        
        elif args.command == "telegram":
            if args.enable:
                tool.config_telegram(True)
            elif args.disable:
                tool.config_telegram(False)
            else:
                tool.config_telegram()
        
        elif args.command == "set-token":
            tool.config_telegram_token(args.token)
        
        elif args.command == "set-chatid":
            tool.config_telegram_chat_id(args.chat_id)
        
        elif args.command == "test-telegram":
            tool.test_telegram_connection()
        
        elif args.command == "exit":
            tool.exit_tool()

if __name__ == "__main__":
    main()