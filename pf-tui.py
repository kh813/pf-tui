#!/usr/bin/env python3
"""
macOS Personal Firewall TUI
A Terminal User Interface for managing macOS firewall rules using pfctl
"""

import os
import sys
import platform
import subprocess
import json
import re
import getpass
import logging
import logging.handlers
import curses
import curses.textpad
import curses.ascii
import time
#from typing import List, Dict, Any, Tuple
from typing import List, Tuple
from dataclasses import dataclass
from enum import Enum

# Logging Configuration
LOG_DIR = os.path.expanduser("~/.config/pf-tui")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "pf-tui.log")

# Set up a rotating log handler
handler = logging.handlers.TimedRotatingFileHandler(
    LOG_FILE,
    when='midnight',  # Rotate daily
    backupCount=30    # Keep 30 old log files
)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Get the root logger, remove existing handlers, and add the new one
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
if logger.hasHandlers():
    logger.handlers.clear()
logger.addHandler(handler)

class Action(Enum):
    BLOCK = "block"
    PASS = "pass"

class Direction(Enum):
    IN = "in"
    OUT = "out"

@dataclass
class FirewallRule:
    action: Action
    direction: Direction
    interface: str = "any"
    protocol: str = "any"
    source: str = "any"
    destination: str = "any"
    port: str = "any"
    description: str = ""
    quick: bool = False
    keep_state: bool = False

@dataclass
class PortForwardingRule:
    interface: str
    protocol: str
    external_ip: str
    external_port: str
    internal_ip: str
    internal_port: str
    description: str = ""

class FirewallManager:
    def __init__(self):
        self.rules: List[FirewallRule] = []
        self.rdr_rules: List[PortForwardingRule] = []
        self.config_dir = os.path.expanduser("~/.config/pf-tui")
        self.config_file = os.path.join(self.config_dir, "rules.json")
        self.pf_conf_file = "/tmp/pf_rules.conf" # for immediate application
        self.persistent_pf_conf_file = os.path.join(self.config_dir, "pf.conf") # for startup
        self.startup_script_path = "/usr/local/bin/pf-tui-startup.sh"
        self.plist_path = "/Library/LaunchDaemons/com.user.pftui.plist"
        os.makedirs(self.config_dir, exist_ok=True)
        self.monitoring_process = None
        logging.info("FirewallManager initialized.")

    def load_rules(self):
        """設定ファイルからルールを読み込み"""
        logging.info(f"Attempting to load rules from {self.config_file}")
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    data = json.load(f)

                    if isinstance(data, list):
                        filter_rules_data = data
                        rdr_rules_data = []
                    else:
                        filter_rules_data = data.get('filter_rules', [])
                        rdr_rules_data = data.get('rdr_rules', [])

                    self.rules = []
                    for rule_data in filter_rules_data:
                        rule = FirewallRule(
                            action=Action(rule_data['action']),
                            direction=Direction(rule_data['direction']),
                            interface=rule_data.get('interface', 'any'),
                            protocol=rule_data.get('protocol', 'any'),
                            source=rule_data.get('source', 'any'),
                            destination=rule_data.get('destination', 'any'),
                            port=rule_data.get('port', 'any'),
                            description=rule_data.get('description', ''),
                            quick=rule_data.get('quick', False),
                            keep_state=rule_data.get('keep_state', False)
                        )
                        self.rules.append(rule)

                    self.rdr_rules = []
                    for rule_data in rdr_rules_data:
                        rdr_rule = PortForwardingRule(
                            interface=rule_data.get('interface', 'any'),
                            protocol=rule_data.get('protocol', 'tcp'),
                            external_ip=rule_data.get('external_ip', 'any'),
                            external_port=rule_data.get('external_port', ''),
                            internal_ip=rule_data.get('internal_ip', ''),
                            internal_port=rule_data.get('internal_port', ''),
                            description=rule_data.get('description', '')
                        )
                        self.rdr_rules.append(rdr_rule)
                    logging.info(f"Successfully loaded {len(self.rules)} filter rules and {len(self.rdr_rules)} RDR rules.")
            else:
                logging.info("Rules file not found. Starting with an empty rule list.")
                self.rules = []
                self.rdr_rules = []
        except Exception as e:
            logging.error(f"Failed to load rules: {e}", exc_info=True)
            self.rules = []
            self.rdr_rules = []

    def save_rules(self):
        """ルールを設定ファイルに保存（JSON + pfctl形式）"""
        logging.info(f"Attempting to save {len(self.rules)} filter rules and {len(self.rdr_rules)} RDR rules to {self.config_file}")
        try:
            # 既存のJSON保存処理
            filter_rules_data = []
            for rule in self.rules:
                filter_rules_data.append({
                    'action': rule.action.value,
                    'direction': rule.direction.value,
                    'interface': rule.interface,
                    'protocol': rule.protocol,
                    'source': rule.source,
                    'destination': rule.destination,
                    'port': rule.port,
                    'description': rule.description,
                    'quick': rule.quick,
                    'keep_state': rule.keep_state
                })

            rdr_rules_data = []
            for rule in self.rdr_rules:
                rdr_rules_data.append({
                    'interface': rule.interface,
                    'protocol': rule.protocol,
                    'external_ip': rule.external_ip,
                    'external_port': rule.external_port,
                    'internal_ip': rule.internal_ip,
                    'internal_port': rule.internal_port,
                    'description': rule.description
                })

            combined_data = {
                "filter_rules": filter_rules_data,
                "rdr_rules": rdr_rules_data
            }

            with open(self.config_file, 'w') as f:
                json.dump(combined_data, f, indent=2)

            # pfctl形式のルールファイルを生成
            if not self._generate_pfctl_rules():
                logging.error("Failed to generate pfctl rules file")
                return False

            logging.info("Successfully saved rules.")
            return True

        except Exception as e:
            logging.error(f"Failed to save rules: {e}", exc_info=True)
            return False

    def rule_exists(self, new_rule: 'FirewallRule') -> bool:
        """Check if an identical filter rule already exists."""
        for rule in self.rules:
            if (
                rule.action == new_rule.action and
                rule.direction == new_rule.direction and
                rule.interface == new_rule.interface and
                rule.protocol == new_rule.protocol and
                rule.source == new_rule.source and
                rule.destination == new_rule.destination and
                rule.port == new_rule.port and
                rule.quick == new_rule.quick and
                rule.keep_state == new_rule.keep_state
            ):
                return True
        return False

    def rdr_rule_exists(self, new_rule: 'PortForwardingRule') -> bool:
        """Check if an identical RDR rule already exists."""
        for rule in self.rdr_rules:
            if (
                rule.interface == new_rule.interface and
                rule.protocol == new_rule.protocol and
                rule.external_ip == new_rule.external_ip and
                rule.external_port == new_rule.external_port and
                rule.internal_ip == new_rule.internal_ip and
                rule.internal_port == new_rule.internal_port
            ):
                return True
        return False

    def _generate_pfctl_rules(self):
        """pfctl形式のルールファイルを生成"""
        try:
            # 即座適用用のルールファイル
            with open(self.pf_conf_file, 'w') as f:
                f.write("# User-defined firewall rules\n")
                f.write("# Generated by pf-tui\n\n")

                # RDRルール（リダイレクション）を先に記述
                if self.rdr_rules:
                    f.write("# RDR Rules (Port Forwarding)\n")
                    for rule in self.rdr_rules:
                        pf_rule = self._convert_rdr_rule_to_pf(rule)
                        if pf_rule:
                            if rule.description:
                                f.write(f"# {rule.description}\n")
                            f.write(f"{pf_rule}\n")
                    f.write("\n")

                # フィルタールール
                if self.rules:
                    f.write("# Filter Rules\n")
                    for rule in self.rules:
                        pf_rule = self._convert_filter_rule_to_pf(rule)
                        if pf_rule:
                            if rule.description:
                                f.write(f"# {rule.description}\n")
                            f.write(f"{pf_rule}\n")

            # 永続化用のルールファイル
            with open(self.persistent_pf_conf_file, 'w') as f:
                f.write("# User-defined firewall rules\n")
                f.write("# Generated by pf-tui\n\n")

                # RDRルール（リダイレクション）を先に記述
                if self.rdr_rules:
                    f.write("# RDR Rules (Port Forwarding)\n")
                    for rule in self.rdr_rules:
                        pf_rule = self._convert_rdr_rule_to_pf(rule)
                        if pf_rule:
                            if rule.description:
                                f.write(f"# {rule.description}\n")
                            f.write(f"{pf_rule}\n")
                    f.write("\n")

                # フィルタールール
                if self.rules:
                    f.write("# Filter Rules\n")
                    for rule in self.rules:
                        pf_rule = self._convert_filter_rule_to_pf(rule)
                        if pf_rule:
                            if rule.description:
                                f.write(f"# {rule.description}\n")
                            f.write(f"{pf_rule}\n")

            return True

        except Exception as e:
            logging.error(f"Failed to generate pfctl rules: {e}")
            return False

    def _convert_filter_rule_to_pf(self, rule):
        """フィルタールールをpf形式に変換"""
        try:
            pf_rule = ""

            # アクション
            if rule.action.value == "pass":
                pf_rule += "pass"
            elif rule.action.value == "block":
                pf_rule += "block"
            else:
                return None

            # quick オプション
            if rule.quick:
                pf_rule += " quick"

            # 方向
            if rule.direction.value == "in":
                pf_rule += " in"
            elif rule.direction.value == "out":
                pf_rule += " out"

            # インターフェース
            if rule.interface and rule.interface.strip() != "any":
                pf_rule += f" on {rule.interface.strip()}"

            # プロトコル
            if rule.protocol and rule.protocol != "any":
                pf_rule += f" proto {rule.protocol}"

            # ソース
            if rule.source and rule.source != "any":
                pf_rule += f" from {rule.source}"
            else:
                pf_rule += " from any"

            # デスティネーション
            if rule.destination and rule.destination != "any":
                pf_rule += f" to {rule.destination}"
            else:
                pf_rule += " to any"

            # ポート
            if rule.port and rule.port != "any":
                pf_rule += f" port {rule.port}"

            # keep state
            if rule.keep_state and rule.action == Action.PASS:
                pf_rule += " keep state"

            # コメント
            # if rule.description:
            #     pf_rule += f" # {rule.description}"

            return pf_rule

        except Exception as e:
            logging.error(f"Failed to convert filter rule: {e}")
            return None

    def _convert_rdr_rule_to_pf(self, rule):
        """RDRルールをpf形式に変換"""
        try:
            if not all([rule.interface, rule.protocol, rule.external_port, rule.internal_ip, rule.internal_port]):
                logging.warning(f"Skipping invalid RDR rule due to missing fields: {rule}")
                return None

            pf_rule = "rdr pass"

            # インターフェース
            if rule.interface and rule.interface.strip().lower() != "any":
                pf_rule += f" on {rule.interface}"

            # プロトコル
            if rule.protocol:
                pf_rule += f" proto {rule.protocol}"

            # 外部ポート
            pf_rule += f" from any to {rule.external_ip} port {rule.external_port}"

            # 内部IP:ポート
            pf_rule += f" -> {rule.internal_ip} port {rule.internal_port}"

            return pf_rule

        except Exception as e:
            logging.error(f"Failed to convert RDR rule: {e}")
            return None

    def save_rules_to_path(self, path):
        """ルールを指定されたパスに保存"""
        logging.info(f"Attempting to save {len(self.rules)} rules to {path}")
        try:
            data = []
            for rule in self.rules:
                data.append({
                    'action': rule.action.value,
                    'direction': rule.direction.value,
                    'interface': rule.interface,
                    'protocol': rule.protocol,
                    'source': rule.source,
                    'destination': rule.destination,
                    'port': rule.port,
                    'description': rule.description,
                    'quick': rule.quick,
                    'keep_state': rule.keep_state
                })
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
            logging.info("Successfully saved rules.")
            return True
        except Exception as e:
            logging.error(f"Failed to save rules: {e}", exc_info=True)
            return False

    def import_rules(self, import_path):
        """指定されたJSONファイルからルールをインポート"""
        logging.info(f"Attempting to import rules from {import_path}")
        try:
            if not os.path.exists(import_path):
                return False, "Import file not found."

            with open(import_path, 'r') as f:
                data = json.load(f)

            new_rules = []
            for rule_data in data:
                rule = FirewallRule(
                    action=Action(rule_data['action']),
                    direction=Direction(rule_data['direction']),
                    interface=rule_data.get('interface', 'any'),
                    protocol=rule_data.get('protocol', 'any'),
                    source=rule_data.get('source', 'any'),
                    destination=rule_data.get('destination', 'any'),
                    port=rule_data.get('port', 'any'),
                    description=rule_data.get('description', ''),
                    quick=rule_data.get('quick', False),
                    keep_state=rule_data.get('keep_state', False)
                )
                new_rules.append(rule)

            self.rules = new_rules
            logging.info(f"Successfully imported {len(self.rules)} rules.")
            return True, f"Successfully imported {len(self.rules)} rules from {os.path.basename(import_path)}"

        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON file: {e}", exc_info=True)
            return False, "Failed to import: Invalid JSON format."
        except Exception as e:
            logging.error(f"Failed to import rules: {e}", exc_info=True)
            return False, f"Failed to import rules: {e}"

    def _parse_rule_line(self, line: str) -> FirewallRule | None:
        """個々のpfctlルール行を解析する（基本的なルールのみ）"""
        try:
            line = line.strip()
            description = ""
            if "#" in line:
                line, description = line.split("#", 1)
                description = description.strip()

            parts = line.split()
            if len(parts) < 2:
                return None

            action = Action(parts[0])
            direction = Direction(parts[1])

            rule = FirewallRule(action=action, direction=direction, description=description)

            if " all" in line:
                return rule

            # 正規表現を使用して各部分を抽出
            on_match = re.search(r'on\s+(\S+)', line)
            if on_match:
                rule.interface = on_match.group(1)

            proto_match = re.search(r'proto\s+(\S+)', line)
            if proto_match:
                rule.protocol = proto_match.group(1)

            from_match = re.search(r'from\s+(\S+)', line)
            if from_match:
                rule.source = from_match.group(1)

            to_match = re.search(r'to\s+(\S+)', line)
            if to_match:
                rule.destination = to_match.group(1)

            port_match = re.search(r'port\s+(\S+)', line)
            if port_match:
                rule.port = port_match.group(1)

            return rule
        except (ValueError, IndexError):
            return None

    def load_from_system(self):
        """システムから現在のルールを読み込んで解析する"""
        logging.info("Loading rules from system.")
        system_rules = self.get_current_rules()
        parsed_count = 0
        unparsed_lines = []

        self.rules = []  # 現在のルールをクリア
        for line in system_rules:
            if not line.strip() or "ALTQ" in line or "scrub" in line:
                continue

            rule = self._parse_rule_line(line)
            if rule:
                self.rules.append(rule)
                parsed_count += 1
            else:
                logging.warning(f"Could not parse system rule line: {line}")
                unparsed_lines.append(line)

        logging.info(f"Loaded {parsed_count} rules from system. {len(unparsed_lines)} lines were unparsed.")
        return parsed_count, len(unparsed_lines)



    def generate_anchor_config(self):
        """pfctl用のアンカー設定ファイルを生成"""
        config_lines = []

        # --- RDR Rules (Port Forwarding) ---
        for rule in self.rdr_rules:
            if rule.description:
                config_lines.append(f"# {rule.description}")

            if not all([rule.interface, rule.protocol, rule.external_port, rule.internal_ip, rule.internal_port]):
                logging.warning(f"Skipping invalid RDR rule due to missing fields: {rule}")
                config_lines.append(f"# SKIPPED: Incomplete RDR rule: {rule}")
                continue

            if rule.interface.strip().lower() == "any":
                line = (f"rdr pass proto {rule.protocol} "
                        f"from any to {rule.external_ip} port {rule.external_port} -> "
                        f"{rule.internal_ip} port {rule.internal_port}")
            else:
                line = f"rdr pass on {rule.interface} proto {rule.protocol} from any to {rule.external_ip} port {rule.external_port} -> {rule.internal_ip} port {rule.internal_port}"
            config_lines.append(line)

        if self.rdr_rules and self.rules:
            config_lines.append("")
            config_lines.append("# --- Filter Rules ---")

        # --- Filter Rules ---
        for rule in self.rules:
            if rule.description:
                config_lines.append(f"# {rule.description}")

            protocols_to_process = []
            # If a port is specified, 'any' protocol is not valid, so default to tcp and udp.
            if rule.port.strip().lower() != 'any' and rule.protocol.strip().lower() == 'any':
                protocols_to_process = ['tcp', 'udp']
            else:
                protocols_to_process = [p.strip() for p in rule.protocol.split(',') if p.strip()]

            for proto in protocols_to_process:
                line = f"{rule.action.value} {rule.direction.value}"
                if rule.quick:
                    line += " quick"
                has_filter_criteria = False

                if rule.interface.strip() != "any":
                    line += f" on {rule.interface.strip()}"

                # Add protocol if it's not 'any'
                if proto.lower() != "any":
                    line += f" proto {proto}"
                    has_filter_criteria = True

                source = rule.source.strip()
                destination = rule.destination.strip()
                port = rule.port.strip()

                # Add from/to if not default 'any'
                if source != "any" or destination != "any":
                    line += f" from {source} to {destination}"
                    has_filter_criteria = True
                # If port is specified, and from/to is not, add the default 'from any to any'
                elif port != "any":
                    line += " from any to any"
                    has_filter_criteria = True

                if port != "any":
                    if '-' in port and port.count('-') == 1:
                        parts = [p.strip() for p in port.split('-')]
                        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                            line += f" port {parts[0]}:{parts[1]}"
                        else:
                            line += f" port {port}"
                    elif ',' in port:
                        ports = [p.strip() for p in port.split(',') if p.strip()]
                        if ports:
                            line += f" port {{ {', '.join(ports)} }}"
                    else:
                        line += f" port {port}"
                    has_filter_criteria = True

                if not has_filter_criteria:
                    line += " all"

                if rule.action == Action.PASS and rule.keep_state:
                    line += " keep state"

                config_lines.append(line)
        return "\n".join(config_lines) + "\n"

    def check_sudo_access(self) -> Tuple[bool, str]:
        """sudo権限の確認とパスワード要求"""
        try:
            # 既存のsudo認証をチェック
            result = subprocess.run(['sudo', '-n', 'true'],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return True, "Sudo access confirmed"

            # パスワードが必要な場合はTUIを一時的に停止してパスワード入力
            return False, "Sudo password required"
        except subprocess.TimeoutExpired:
            return False, "Sudo check timeout"
        except Exception as e:
            return False, f"Sudo check error: {str(e)}"

    def request_sudo_password(self, stdscr=None) -> Tuple[bool, str]:
        """sudoパスワードの要求（TUI外で実行）"""
        password = None
        try:
            if stdscr:
                curses.endwin()

            print("\nSudo password required for pfctl operations.")

            try:
                password = getpass.getpass("Please enter your sudo password: ")
            except (KeyboardInterrupt, EOFError):
                print("\nPassword input cancelled.")
                return False, "Password input cancelled"

            result = subprocess.run(
                ['sudo', '-S', '-v'],
                input=password,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return True, "Authentication successful"
            else:
                error_msg = "Authentication failed"
                if "incorrect password" in result.stderr.lower():
                    error_msg += ": Incorrect password"
                elif result.stderr:
                    error_msg += f": {result.stderr.strip()}"
                return False, error_msg

        except subprocess.TimeoutExpired:
            return False, "Authentication timeout"
        except KeyboardInterrupt:
            return False, "Authentication cancelled"
        except Exception as e:
            return False, f"Authentication error: {str(e)}"
        finally:
            if password:
                # Securely clear password
                password = '0' * len(password)
                del password

            # cursesモードを再開
            if stdscr:
                stdscr.refresh()

    def apply_rules(self, stdscr=None):
        """ルールをシステムに適用（改良版アンカー経由）"""
        logging.info("Applying rules via improved anchor method.")

        # Sudo権限の確認
        has_sudo, message = self.check_sudo_access()
        if not has_sudo:
            logging.warning("Sudo access not available. Requesting password.")
            success, auth_message = self.request_sudo_password(stdscr)
            if not success:
                logging.error(f"Sudo password request failed: {auth_message}")
                return False, auth_message

        # IPフォワーディングをチェック・有効化
        fwd_success, fwd_message = self.check_and_enable_forwarding(stdscr)
        if not fwd_success:
            # このエラーは致命的ではないので、ログに記録して続行する
            logging.error(f"Could not enable IP forwarding: {fwd_message}")
            # オプションで、ユーザーに通知することもできる
            # self.show_dialog(f"Warning: {fwd_message}", "warning")

        anchor_name = "pf-tui.rules"
        anchor_file_path = f"/etc/pf.anchors/{anchor_name}"
        temp_file_path = "/tmp/pf_tui_rules_temp"

        try:
            # 1. アンカー設定を生成
            anchor_config = self.generate_anchor_config()
            logging.info(f"--- Generated anchor config for validation ---\n{anchor_config}\n-------------------------------------------------")

            # 2. 一時ファイルに書き込み
            with open(temp_file_path, "w") as f:
                f.write(anchor_config)
            logging.info(f"Wrote temporary rules to {temp_file_path}")

            # 3. ルールファイルが存在し、内容があるかチェック
            if not os.path.exists(temp_file_path):
                logging.error("Failed to create temporary rules file.")
                return False, "Failed to create temporary rules file"

            with open(temp_file_path, 'r') as f:
                content = f.read().strip()
                if not content:
                    logging.warning("No rules to apply (empty ruleset). Skipping application.")
                    return True, "No rules to apply (empty ruleset)"

            # 4. ルールを事前検証（テストモード）
            test_cmd = ['sudo', 'pfctl', '-n', '-f', temp_file_path]
            logging.info(f"Validating rules with command: {' '.join(test_cmd)}")

            test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=10)

            logging.info(f"pfctl validation return code: {test_result.returncode}")
            logging.info(f"pfctl validation stdout:\n{test_result.stdout.strip()}")
            logging.info(f"pfctl validation stderr:\n{test_result.stderr.strip()}")

            if test_result.returncode != 0:
                known_warnings = [
                    "pfctl: Use of -f option, could result in flushing of rules",
                    "present in the main ruleset"
                ]
                stderr_lines = test_result.stderr.strip().split('\n')
                real_errors = [
                    line.strip() for line in stderr_lines
                    if line.strip() and not any(warning in line for warning in known_warnings)
                ]

                if real_errors:
                    error_output = '\n'.join(real_errors)
                    full_error_details = (f"Rule validation failed. Return code: {test_result.returncode}\n"
                                          f"Stdout:\n{test_result.stdout}\nStderr:\n{test_result.stderr}")
                    logging.error(full_error_details)
                    error_msg = f"Rule validation failed: {error_output}"
                    return False, error_msg

            logging.info("Rule validation passed")

            # 5. アンカーファイルを適切な場所に移動
            move_cmd = ['sudo', 'mv', temp_file_path, anchor_file_path]
            move_result = subprocess.run(move_cmd, capture_output=True, text=True, timeout=5)

            if move_result.returncode != 0:
                error_msg = f"Failed to move rules file: {move_result.stderr.strip()}"
                logging.error(error_msg)
                return False, error_msg

            # 6. アンカーにルールを適用
            apply_cmd = ['sudo', 'pfctl', '-a', anchor_name, '-f', anchor_file_path]
            logging.info(f"Applying rules with command: {' '.join(apply_cmd)}")

            apply_result = subprocess.run(apply_cmd, capture_output=True, text=True, timeout=30)

            # 詳細なログ出力
            logging.info("pfctl apply command finished.")
            logging.info(f"pfctl return code: {apply_result.returncode}")
            logging.info(f"pfctl stdout: {apply_result.stdout.strip()}")
            logging.info(f"pfctl stderr: {apply_result.stderr.strip()}")

            if apply_result.returncode != 0:
                error_msg = f"Failed to apply rules: {apply_result.stderr.strip()}"
                logging.error(error_msg)
                return False, error_msg

            # 7. pfctlが有効化されているかチェック、必要に応じて有効化
            enable_cmd = ['sudo', 'pfctl', '-e']
            enable_result = subprocess.run(enable_cmd, capture_output=True, text=True, timeout=10)

            # pfctlが既に有効な場合は正常とみなす
            if enable_result.returncode == 0 or "already enabled" in enable_result.stderr:
                success_msg = f"Rules applied successfully to anchor '{anchor_name}'"

                # 適用されたルール数を確認
                try:
                    check_cmd = ['sudo', 'pfctl', '-a', anchor_name, '-s', 'rules']
                    check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)

                    if check_result.returncode == 0:
                        rule_lines = [line for line in check_result.stdout.strip().split('\n') if line.strip()]
                        rule_count = len(rule_lines)
                        success_msg += f" ({rule_count} rules active)"
                        logging.info(f"Active rules in anchor: {rule_count}")

                except Exception as e:
                    logging.warning(f"Failed to check active rules: {e}")

                logging.info(success_msg)
                return True, success_msg
            else:
                error_msg = f"Failed to enable pfctl: {enable_result.stderr.strip()}"
                logging.error(error_msg)
                return False, error_msg

        except subprocess.TimeoutExpired:
            error_msg = "Command timed out while applying rules"
            logging.error(error_msg)
            return False, error_msg
        except FileNotFoundError as e:
            error_msg = f"Required file not found: {e}"
            logging.error(error_msg)
            return False, error_msg
        except PermissionError as e:
            error_msg = f"Permission denied: {e}"
            logging.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Failed to apply rules via anchor: {e}"
            logging.error(error_msg, exc_info=True)
            return False, error_msg
        finally:
            # 一時ファイルのクリーンアップ
            try:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
            except Exception as e:
                logging.warning(f"Failed to cleanup temporary file: {e}")

    def check_and_enable_forwarding(self, stdscr=None):
        """IPフォワーディングが有効かチェックし、必要であれば有効にする"""
        if not self.rdr_rules:
            logging.info("No RDR rules, skipping forwarding check.")
            return True, ""

        logging.info("Checking IP forwarding status.")
        try:
            # Check current forwarding status
            check_cmd = ['sysctl', 'net.inet.ip.forwarding']
            result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                status = result.stdout.strip()
                logging.info(f"Current net.inet.ip.forwarding status: {status}")
                if '1' in status:
                    return True, "IP forwarding is already enabled."
            else:
                logging.warning(f"Could not determine IP forwarding status: {result.stderr.strip()}")

            # Enable forwarding if we are here
            logging.info("Attempting to enable IP forwarding.")
            has_sudo, message = self.check_sudo_access()
            if not has_sudo:
                logging.warning("Sudo access not available. Requesting password.")
                success, auth_message = self.request_sudo_password(stdscr)
                if not success:
                    logging.error(f"Sudo password request failed: {auth_message}")
                    return False, auth_message

            enable_cmd = ['sudo', 'sysctl', '-w', 'net.inet.ip.forwarding=1']
            logging.info(f"Running command: {' '.join(enable_cmd)}")
            enable_result = subprocess.run(enable_cmd, capture_output=True, text=True, timeout=10)

            if enable_result.returncode == 0:
                logging.info("Successfully enabled IP forwarding.")
                return True, "Successfully enabled IP forwarding."
            else:
                error_msg = f"Failed to enable IP forwarding: {enable_result.stderr.strip()}"
                logging.error(error_msg)
                return False, error_msg

        except Exception as e:
            error_msg = f"An error occurred while checking/enabling IP forwarding: {e}"
            logging.error(error_msg, exc_info=True)
            return False, error_msg


    def get_current_rules(self):
        """現在のpfctlルールを取得"""
        logging.info("Attempting to get current pfctl rules.")
        all_rules = []
        try:
            has_sudo, _ = self.check_sudo_access()
            if not has_sudo:
                logging.warning("Sudo access not available for getting current rules.")
                return []

            # First, get NAT rules
            rules_anchor_name = "pf-tui.rules"
            try:
                nat_command = ['sudo', 'pfctl', '-a', rules_anchor_name, '-s', 'nat']
                logging.info(f"Executing command: {' '.join(nat_command)}")
                nat_result = subprocess.run(nat_command, capture_output=True, text=True, timeout=5)
                if nat_result.returncode == 0 and nat_result.stdout.strip():
                    all_rules.extend(nat_result.stdout.strip().split('\n'))
            except Exception as e:
                logging.warning(f"Could not get NAT rules: {e}")

            # Then, get filter rules
            #rules_anchor_name = "pf-tui.rules"
            command = ['sudo', 'pfctl', '-a', rules_anchor_name, '-s', 'rules']
            logging.info(f"Executing command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                stdout = result.stdout.strip()
                if stdout and "no rules" not in stdout.lower():
                    all_rules.extend(stdout.split('\n'))
            else:
                stderr = result.stderr.strip()
                if "no such anchor" in stderr.lower():
                    logging.warning(f"Anchor '{rules_anchor_name}' does not exist yet.")
                else:
                    logging.error(f"pfctl failed to get rules from anchor: {stderr}")

            # Filter out lines containing ALTQ
            final_rules = [rule for rule in all_rules if "ALTQ" not in rule]
            logging.info(f"Successfully retrieved {len(final_rules)} rules.")
            return final_rules

        except Exception as e:
            logging.error(f"Failed to get current rules: {e}", exc_info=True)
            return []

    def get_pf_status(self, stdscr=None):
        """pfの現在のステータスを取得 (Enabled/Disabled)"""
        logging.info("Checking pf status.")
        try:
            has_sudo, _ = self.check_sudo_access()
            if not has_sudo:
                logging.warning("Sudo access not available for checking pf status. Requesting password.")
                success, auth_message = self.request_sudo_password(stdscr)
                if not success:
                    logging.error(f"Sudo password request failed: {auth_message}")
                    return "Unknown"

            command = ['sudo', 'pfctl', '-s', 'info']
            logging.info(f"Running command: {' '.join(command)}")
            result = subprocess.run(command,
                                    capture_output=True, text=True, timeout=5)

            if result.returncode == 0 and "Status: Enabled" in result.stdout:
                logging.info("PF status is Enabled.")
                return "Enabled"
            else:
                logging.info("PF status is Disabled.")
                return "Disabled"
        except Exception as e:
            logging.error(f"Failed to get pf status: {e}", exc_info=True)
            return "Disabled"  # Assume disabled on any error

    def enable_pf(self, stdscr=None):
        """pfを有効化"""
        logging.info("Attempting to enable PF.")
        has_sudo, message = self.check_sudo_access()
        if not has_sudo:
            logging.warning("Sudo access not available. Requesting password.")
            success, auth_message = self.request_sudo_password(stdscr)
            if not success:
                logging.error(f"Sudo password request failed: {auth_message}")
                return False, auth_message

        # 1. Modify /etc/pf.conf to load the anchor
        pf_conf_path = "/etc/pf.conf"
        anchor_name = "pf-tui.rules"
        anchor_file_path = f"/etc/pf.anchors/{anchor_name}"
        anchor_load_line = f'load anchor "{anchor_name}" from "{anchor_file_path}"'
        try:
            read_cmd = ['sudo', 'cat', pf_conf_path]
            result = subprocess.run(read_cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()

            new_lines = []
            anchor_found = False
            modified = False

            for line in lines:
                stripped_line = line.strip()
                if anchor_load_line in stripped_line:
                    anchor_found = True
                    if stripped_line.startswith('#'):
                        new_lines.append(anchor_load_line)
                        modified = True
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)

            if not anchor_found:
                new_lines.append(anchor_load_line)
                modified = True

            if modified:
                new_content = "\n".join(new_lines) + "\n"
                temp_pf_conf = "/tmp/pf.conf.new"
                with open(temp_pf_conf, "w") as f:
                    f.write(new_content)

                move_cmd = ['sudo', 'mv', temp_pf_conf, pf_conf_path]
                subprocess.run(move_cmd, check=True)
                logging.info(f"Updated {pf_conf_path}")

                # Validate configuration
                validate_cmd = ['sudo', 'pfctl', '-nf', pf_conf_path]
                logging.info(f"Validating pf config: {' '.join(validate_cmd)}")
                #result = subprocess.run(validate_cmd, capture_output=True, text=True)
                result = subprocess.run(validate_cmd, capture_output=True, text=True, check=True)
                if result.returncode != 0:
                    error_msg = f"pf.conf validation failed: {result.stderr.strip()}"
                    logging.error(error_msg)
                    return False, error_msg

                # Load new rules
                load_cmd = ['sudo', 'pfctl', '-f', pf_conf_path]
                logging.info(f"Loading new pf rules: {' '.join(load_cmd)}")
                result = subprocess.run(load_cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    error_msg = f"Failed to load pf.conf: {result.stderr.strip()}"
                    logging.error(error_msg)
                    return False, error_msg

        except Exception as e:
            logging.error(f"Failed to modify {pf_conf_path}: {e}", exc_info=True)
            return False, f"Failed to modify {pf_conf_path}: {e}"

        # 2. Enable PF
        try:
            command = ['sudo', 'pfctl', '-e']
            logging.info(f"Running command: {' '.join(command)}")
            result = subprocess.run(command,
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logging.info("PF enabled successfully.")
                # Also apply the rules to make sure the firewall is in a known state
                self.apply_rules(stdscr)
                return True, "PF enabled successfully"
            # Handle cases where PF is already enabled
            elif "pf already enabled" in result.stderr.lower():
                logging.info("PF is already enabled.")
                # Still apply rules to ensure they are up-to-date
                self.apply_rules(stdscr)
                return True, "PF is already enabled. Rules re-applied."
            else:
                logging.error(f"Failed to enable PF: {result.stderr.strip()}")
                return False, f"Enable failed: {result.stderr.strip()}"
        except Exception as e:
            logging.error(f"Error enabling PF: {e}", exc_info=True)
            return False, f"Enable error: {str(e)}"

    def get_pf_info(self, stdscr=None) -> Tuple[bool, str]:
        """pfの現在の詳細情報を取得"""
        logging.info("Checking pf info.")
        try:
            has_sudo, _ = self.check_sudo_access()
            if not has_sudo:
                # This is a read-only operation, so we can ask for password
                # without interrupting the user experience too much.
                logging.warning("Sudo access not available for checking pf info.")
                return False, "Sudo access is required to view PF info."

            command = ['sudo', 'pfctl', '-s', 'info']
            logging.info(f"Running command: {' '.join(command)}")
            result = subprocess.run(command,
                                    capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                logging.info("PF info retrieved successfully.")
                return True, result.stdout
            else:
                logging.error(f"pfctl -s info failed: {result.stderr.strip()}")
                return False, f"Failed to get pf info: {result.stderr.strip()}"
        except Exception as e:
            logging.error(f"Failed to get pf info: {e}", exc_info=True)
            return False, f"Failed to get pf info: {str(e)}"

    def get_startup_status(self):
        """起動時のPF有効状態を確認"""
        logging.info("Checking startup status.")
        if os.path.exists(self.plist_path):
            logging.info("Startup status is Enabled.")
            return "Enabled"
        else:
            logging.info("Startup status is Disabled.")
            return "Disabled"

    def enable_pf_on_startup(self, stdscr=None):
        """OS起動時にpfを有効にする"""
        logging.info("Attempting to enable PF on startup.")
        has_sudo, message = self.check_sudo_access()
        if not has_sudo:
            logging.warning("Sudo access not available. Requesting password.")
            success, auth_message = self.request_sudo_password(stdscr)
            if not success:
                logging.error(f"Sudo password request failed: {auth_message}")
                return False, auth_message

        # 1. Save current rules to the anchor file for persistence
        anchor_name = "pf-tui.rules"
        anchor_file_path = f"/etc/pf.anchors/{anchor_name}"
        anchor_config = self.generate_anchor_config()
        try:
            with open("/tmp/anchor_rules", "w") as f:
                f.write(anchor_config)
            subprocess.run(['sudo', 'mv', '/tmp/anchor_rules', anchor_file_path], check=True)
            logging.info(f"Wrote persistent anchor config to {anchor_file_path}")
        except Exception as e:
            logging.error(f"Failed to write persistent anchor config: {e}", exc_info=True)
            return False, f"Failed to write persistent anchor config: {e}"

        # 2. Modify /etc/pf.conf to load the anchor
        pf_conf_path = "/etc/pf.conf"
        anchor_load_line = f'load anchor "{anchor_name}" from "/etc/pf.anchors/{anchor_name}"'
        try:
            read_cmd = ['sudo', 'cat', pf_conf_path]
            result = subprocess.run(read_cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()

            new_lines = []
            anchor_found = False
            modified = False

            for line in lines:
                stripped_line = line.strip()
                if anchor_load_line in stripped_line:
                    anchor_found = True
                    if stripped_line.startswith('#'):
                        new_lines.append(anchor_load_line)
                        modified = True
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)

            if not anchor_found:
                new_lines.append(anchor_load_line)
                modified = True

            if modified:
                new_content = "\n".join(new_lines) + "\n"
                temp_pf_conf = "/tmp/pf.conf.new"
                with open(temp_pf_conf, "w") as f:
                    f.write(new_content)

                move_cmd = ['sudo', 'mv', temp_pf_conf, pf_conf_path]
                subprocess.run(move_cmd, check=True)
                logging.info(f"Updated {pf_conf_path}")

        except Exception as e:
            logging.error(f"Failed to modify {pf_conf_path}: {e}", exc_info=True)
            return False, f"Failed to modify {pf_conf_path}: {e}"

        # 3. Create and load the launchd plist
        plist_content = '''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.pftui</string>
    <key>ProgramArguments</key>
    <array>
        <string>/sbin/pfctl</string>
        <string>-e</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
'''
        try:
            with open("/tmp/com.user.pftui.plist", "w") as f:
                f.write(plist_content)
            subprocess.run(['sudo', 'mv', '/tmp/com.user.pftui.plist', self.plist_path], check=True)
            subprocess.run(['sudo', 'chown', 'root:wheel', self.plist_path], check=True)
            subprocess.run(['sudo', 'launchctl', 'load', self.plist_path], check=True)
            logging.info(f"Moved plist to {self.plist_path} and loaded it.")
            return True, "Enabled on startup successfully"
        except Exception as e:
            logging.error(f"Failed to enable on startup: {e}", exc_info=True)
            return False, f"Failed to enable on startup: {e}"

    def disable_pf_on_startup(self, stdscr=None):
        """OS起動時のpfを無効にする"""
        logging.info("Attempting to disable PF on startup.")
        has_sudo, message = self.check_sudo_access()
        if not has_sudo:
            logging.warning("Sudo access not available. Requesting password.")
            success, auth_message = self.request_sudo_password(stdscr)
            if not success:
                logging.error(f"Sudo password request failed: {auth_message}")
                return False, auth_message

        # 1. Comment out the anchor in /etc/pf.conf
        pf_conf_path = "/etc/pf.conf"
        anchor_name = "pf-tui.rules"
        anchor_file_path = f"/etc/pf.anchors/{anchor_name}"
        anchor_load_line = f'load anchor "{anchor_name}" from "{anchor_file_path}"'
        try:
            read_cmd = ['sudo', 'cat', pf_conf_path]
            result = subprocess.run(read_cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()

            new_lines = []
            modified = False

            for line in lines:
                stripped_line = line.strip()
                if stripped_line == anchor_load_line:
                    new_lines.append(f"# {stripped_line}")
                    modified = True
                else:
                    new_lines.append(line)

            if modified:
                new_content = "\n".join(new_lines) + "\n"
                temp_pf_conf = "/tmp/pf.conf.new"
                with open(temp_pf_conf, "w") as f:
                    f.write(new_content)

                move_cmd = ['sudo', 'mv', temp_pf_conf, pf_conf_path]
                subprocess.run(move_cmd, check=True)
                logging.info(f"Disabled anchor in {pf_conf_path}")

        except Exception as e:
            logging.error(f"Failed to modify {pf_conf_path}: {e}", exc_info=True)
            return False, f"Failed to modify {pf_conf_path}: {e}"

        # 2. Unload and remove the launchd plist
        try:
            if os.path.exists(self.plist_path):
                logging.info(f"Unloading and removing plist: {self.plist_path}")
                subprocess.run(['sudo', 'launchctl', 'unload', self.plist_path], check=False)
                subprocess.run(['sudo', 'rm', self.plist_path], check=True)
            return True, "Disabled on startup successfully"
        except Exception as e:
            logging.error(f"Failed to disable on startup: {e}", exc_info=True)
            return False, f"Failed to disable on startup: {e}"

    def disable_pf(self, stdscr=None):
        """pfを無効化"""
        logging.info("Attempting to disable PF.")
        has_sudo, message = self.check_sudo_access()
        if not has_sudo:
            logging.warning("Sudo access not available. Requesting password.")
            success, auth_message = self.request_sudo_password(stdscr)
            if not success:
                logging.error(f"Sudo password request failed: {auth_message}")
                return False, auth_message

        # 1. Comment out the anchor in /etc/pf.conf
        pf_conf_path = "/etc/pf.conf"
        anchor_name = "pf-tui.rules"
        anchor_file_path = f"/etc/pf.anchors/{anchor_name}"
        anchor_load_line = f'load anchor "{anchor_name}" from "{anchor_file_path}"'
        try:
            read_cmd = ['sudo', 'cat', pf_conf_path]
            result = subprocess.run(read_cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()

            new_lines = []
            modified = False

            for line in lines:
                stripped_line = line.strip()
                if stripped_line == anchor_load_line:
                    new_lines.append(f"# {stripped_line}")
                    modified = True
                else:
                    new_lines.append(line)

            if modified:
                new_content = "\n".join(new_lines) + "\n"
                temp_pf_conf = "/tmp/pf.conf.new"
                with open(temp_pf_conf, "w") as f:
                    f.write(new_content)

                move_cmd = ['sudo', 'mv', temp_pf_conf, pf_conf_path]
                subprocess.run(move_cmd, check=True)
                logging.info(f"Disabled anchor in {pf_conf_path}")

        except Exception as e:
            logging.error(f"Failed to modify {pf_conf_path}: {e}", exc_info=True)
            return False, f"Failed to modify {pf_conf_path}: {e}"

        # 2. Disable PF
        try:
            command = ['sudo', 'pfctl', '-d']
            logging.info(f"Running command: {' '.join(command)}")
            result = subprocess.run(command,
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logging.info("PF disabled successfully.")
                return True, "PF disabled successfully"
            # Handle cases where PF is already disabled
            elif "pf not running" in result.stderr.lower():
                logging.info("PF is already disabled.")
                return True, "PF is already disabled."
            else:
                logging.error(f"Failed to disable PF: {result.stderr.strip()}")
                return False, f"Disable failed: {result.stderr.strip()}"
        except Exception as e:
            logging.error(f"Error disabling PF: {e}", exc_info=True)
            return False, f"Disable error: {str(e)}"


class MyTextbox(curses.textpad.Textbox):
    """Custom Textbox for a better editing experience."""
    def __init__(self, win, safe_addstr_func):
        super().__init__(win)
        self.win = win
        self.safe_addstr = safe_addstr_func
        self.cancelled = False

    def do_command(self, ch):
        y, x = self.win.getyx()

        if ch == 27:  # ESC
            self.cancelled = True
            return 0

        if ch in (curses.KEY_BACKSPACE, 127, 8, 263):
            if x > 0:
                self.win.move(y, x - 1)
                self.win.delch()
            return 1

        if ch == curses.KEY_DC:
            self.win.delch()
            return 1

        if curses.ascii.isprint(ch):
            self.win.insch(ch)
            self.win.move(y, x + 1)
            return 1

        # Let the parent class handle other keys (like arrows)
        return super().do_command(ch)


class FirewallTUI:
    def __init__(self):
        logging.info("FirewallTUI initialized.")
        self.firewall = FirewallManager()
        self.current_selection = 0
        self.mode = "main"  # main, add_rule, edit_rule, dialog, view_log, file_browser, show_info
        self.browser_path = "/"
        self.browser_selection = 0
        self.browser_mode = None
        self.form_data = {}
        self.form_field = 0
        self.status_message = ""
        self.dialog_message = ""
        self.dialog_type = "info"  # info, error, confirm
        self.confirm_action = None
        self.pf_status = "Checking..." # PFのステータスを保持
        self.startup_status = "Checking..."
        self.edit_selection = 0
        self.scroll_offset = 0
        self.editing_rule_index = None
        self.log_view_content = []
        self.log_view_title = ""
        self.info_view_content = ""
        self.last_info_refresh = 0
        self.form_defaults = {
            "action": "block",
            "direction": "in",
            "interface": "any",
            "protocol": "any",
            "source": "any",
            "destination": "any",
            "port": "any",
            "description": "",
            "quick": "No",
            "keep_state": "No"
        }
        self.rdr_form_defaults = {
            "interface": "any",
            "protocol": "tcp",
            "external_ip": "any",
            "external_port": "",
            "internal_ip": "127.0.0.1",
            "internal_port": "",
            "description": ""
        }

    def safe_addstr(self, win, y, x, text, *args):
        """A wrapper for addstr that logs and truncates to prevent crashes."""
        try:
            max_y, max_x = win.getmaxyx()

            if y >= max_y or x >= max_x:
                logging.error(f"safe_addstr: Invalid coordinates y={y}, x={x} for screen size ({max_y}, {max_x}). Text: '{text}'")
                return

            # Truncate text to fit. The last position (max_y-1, max_x-1) is writeable.
            available_width = max_x - x
            truncated_text = text[:available_width]

            # Prevent writing to the bottom-right corner which can cause errors
            if y == max_y - 1 and (x + len(truncated_text)) >= max_x:
                if len(truncated_text) > 0:
                    truncated_text = truncated_text[:-1]

            if len(text) > len(truncated_text):
                logging.warning(f"safe_addstr: Truncated text. Original: {len(text)} chars, Truncated: {len(truncated_text)} chars. YX=({y},{x}), Text: '{text}'")

            win.addstr(y, x, truncated_text, *args)
        except curses.error as e:
            logging.error(f"safe_addstr: curses.error at YX=({y},{x}), MaxYX=({max_y},{max_x}), TextLen={len(truncated_text)}. Text: '{truncated_text}'. Error: {e}")
        except Exception as e:
            logging.critical(f"safe_addstr: Unexpected error at YX=({y},{x}). Text: '{text}'. Error: {e}", exc_info=True)

    def init_curses(self, stdscr):
        self.stdscr = stdscr
        self.stdscr.keypad(True)
        curses.curs_set(0)
        curses.use_default_colors()

        # カラーペア定義
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)   # ヘッダー
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)  # 選択
        curses.init_pair(3, curses.COLOR_GREEN, -1)                  # 成功
        curses.init_pair(4, curses.COLOR_RED, -1)                    # エラー
        curses.init_pair(5, curses.COLOR_YELLOW, -1)                 # 警告

        self.firewall.load_rules()
        self.pf_status = self.firewall.get_pf_status(self.stdscr) # 初期ステータスを取得
        self.startup_status = self.firewall.get_startup_status()
        self.main_loop()

    def show_dialog(self, message, dialog_type="info", action=None):
        """ダイアログを表示"""
        self._previous_mode = self.mode
        self.dialog_message = message
        self.dialog_type = dialog_type
        self.confirm_action = action
        self.mode = "dialog"

    def draw_dialog(self):
        """ダイアログを描画"""
        if self.mode != "dialog":
            return

        # ダイアログボックスのサイズ
        dialog_width = min(60, curses.COLS - 4)
        dialog_height = 8

        # 中央に配置
        start_y = (curses.LINES - dialog_height) // 2
        start_x = (curses.COLS - dialog_width) // 2

        # ダイアログのウィンドウを作成
        dialog_win = curses.newwin(dialog_height, dialog_width, start_y, start_x)
        dialog_win.bkgd(' ', curses.color_pair(2))
        dialog_win.border()

        # タイトル
        if self.dialog_type == "error":
            title = " Error "
            color = curses.color_pair(4)
        elif self.dialog_type == "confirm":
            title = " Confirm "
            color = curses.color_pair(5)
        else:
            title = " Information "
            color = curses.color_pair(3)

        title_x = (dialog_width - len(title)) // 2
        self.safe_addstr(dialog_win, 0, title_x, title[:dialog_width - 2], color | curses.A_BOLD)

        # メッセージを複数行に分割して表示
        lines = []
        words = self.dialog_message.split()
        current_line = ""
        max_line_width = dialog_width - 4

        for word in words:
            if len(current_line + " " + word) <= max_line_width:
                current_line += (" " if current_line else "") + word
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word
        if current_line:
            lines.append(current_line)

        # メッセージ表示
        message_start_y = 2
        for i, line in enumerate(lines[:3]):  # 最大3行まで
            self.safe_addstr(dialog_win, message_start_y + i, (dialog_width - len(line)) // 2, line)

        # ボタンテキスト
        if self.dialog_type == "confirm":
            button_text = "[Enter] to continue, [Esc] to cancel"
        else:
            button_text = "[Enter] or [Esc] to close"

        self.safe_addstr(dialog_win, dialog_height - 2, (dialog_width - len(button_text)) // 2, button_text[:dialog_width - 2], curses.A_BOLD)
        dialog_win.refresh()

    def draw_header(self):
        """ヘッダーを描画"""
        self.stdscr.attron(curses.color_pair(1))
        self.safe_addstr(self.stdscr, 0, 0, ' ' * (curses.COLS - 1))
        header_text = "macOS Personal Firewall TUI (ALTQ-Safe)"
        status_text = f"PF: {self.pf_status}"
        if curses.COLS > len(header_text) + len(status_text) + 2:
            self.safe_addstr(self.stdscr, 0, 0, header_text)
            self.safe_addstr(self.stdscr, 0, curses.COLS - len(status_text) - 1, status_text)
        else:
            self.safe_addstr(self.stdscr, 0, 0, header_text[:curses.COLS - 1])
        self.stdscr.attroff(curses.color_pair(1))

    def draw_main_screen(self):
        """メイン画面を描画"""
        self.stdscr.clear()
        self.draw_header()

        # メニューオプション
        self.menu_items = [
            "Edit Rule",
            "Add New Rule",
            "Edit Port Forwarding Rule",
            "Add Port Forwarding Rule",
            "---", # セパレータ
            "Save & Apply Rules to System",
            "Save Configuration",
            "Import Configuration",
            "---",
            "Show Current Rules",
            "Show Info",
            "---", # セパレータ
            f"PF Status: {self.pf_status}",
            "Enable PF",
            "Disable PF",
            "---",
            f"Startup: {self.startup_status}",
            "Enable PF on Startup",
            "Disable PF on Startup",
            "---",
            "Exit"
        ]

        y = 3
        self.safe_addstr(self.stdscr, y, 2, "Main Menu:", curses.A_BOLD)
        y += 2

        for i, item in enumerate(self.menu_items):
            if item == "---":
                self.safe_addstr(self.stdscr, y + i, 4, "─────────────")
                continue

            if i == self.current_selection:
                self.stdscr.attron(curses.color_pair(2))
                self.safe_addstr(self.stdscr, y + i, 4, f"> {item}")
                self.stdscr.attroff(curses.color_pair(2))
            else:
                self.safe_addstr(self.stdscr, y + i, 4, f"  {item}")

        # ルール一覧表示
        y += len(self.menu_items) + 2
        self.safe_addstr(self.stdscr, y, 2, "Current Rules:", curses.A_BOLD)
        y += 1

        if not self.firewall.rules:
            self.safe_addstr(self.stdscr, y + 1, 4, "No rules configured")
        else:
            #headers = ["#", "Action", "Dir", "Proto", "Source", "Dest", "Port", "Description"]
            header_line = f"{'#':<3} {'Action':<7} {'Dir':<5} {'Proto':<7} {'Source':<15} {'Dest':<15} {'Port':<10} {'Description'}"
            self.safe_addstr(self.stdscr, y + 1, 4, header_line[:curses.COLS - 5], curses.A_BOLD)

            max_rules_to_display = curses.LINES - y - 5
            if max_rules_to_display < 1: max_rules_to_display = 1

            for i, rule in enumerate(self.firewall.rules[:max_rules_to_display]):
                rule_line = f"{i+1:<3} {rule.action.value:<7} {rule.direction.value:<5} {rule.protocol:<7} {rule.source:<15} {rule.destination:<15} {rule.port:<10} {rule.description}"
                self.safe_addstr(self.stdscr, y + 2 + i, 4, rule_line[:curses.COLS-6])

            if len(self.firewall.rules) > max_rules_to_display:
                more_rules_y = y + 2 + max_rules_to_display
                if more_rules_y < curses.LINES - 2:
                    message = f"... and {len(self.firewall.rules) - max_rules_to_display} more rules. Use 'Edit Rule' to see all."
                    self.safe_addstr(self.stdscr, more_rules_y, 4, message[:curses.COLS - 5])

        # ステータスメッセージ
        if self.status_message:
            self.safe_addstr(self.stdscr, curses.LINES - 2, 2, self.status_message[:curses.COLS - 4], curses.color_pair(3))

        help_text = "Arrows: Navigate | Enter: Select | q: Quit"
        self.safe_addstr(self.stdscr, curses.LINES - 1, 2, help_text[:curses.COLS - 3])

    def draw_info_screen(self):
        """Draw the pf info screen."""
        self.stdscr.clear()
        self.draw_header()
        self.safe_addstr(self.stdscr, 2, 2, "Live PF Info (refreshes every 1s)", curses.A_BOLD)

        info_window_height = curses.LINES - 7
        info_win = self.stdscr.subwin(info_window_height, curses.COLS - 4, 4, 2)
        info_win.border()

        # Split content into lines and display
        lines = self.info_view_content.split('\n')
        for i, line in enumerate(lines):
            if i + 1 < info_window_height - 1:
                self.safe_addstr(info_win, i + 1, 2, line[:curses.COLS - 8])

        self.safe_addstr(self.stdscr, curses.LINES - 2, 2, "Press [Esc] or [q] to return to the main menu."[:curses.COLS - 3], curses.A_BOLD)
        self.stdscr.refresh()
        info_win.refresh()

    def prompt_for_import_path(self):
        """Prompt the user for the path to the import file."""
        curses.curs_set(1)
        self.mode = "main"
        self.draw_main_screen()
        self.safe_addstr(self.stdscr, curses.LINES - 3, 2, "Path to import: ")
        self.stdscr.refresh()
        edit_win = curses.newwin(1, curses.COLS - 20, curses.LINES - 3, 19)
        box = MyTextbox(edit_win, self.safe_addstr)
        self.stdscr.refresh()
        box.edit()
        path = box.gather().strip()
        curses.curs_set(0)
        if path:
            success, message = self.firewall.import_rules(path)
            self.show_dialog(message, "info" if success else "error")
        else:
            self.show_dialog("Import cancelled.", "info")
        return True

    def prompt_for_save_path(self):
        """Prompt for a filename to save the configuration, with a default."""
        curses.curs_set(1)
        self.mode = "main"
        self.draw_main_screen()

        prompt_str = "Save to path: "
        self.safe_addstr(self.stdscr, curses.LINES - 3, 2, prompt_str)

        default_filename = "rules.json"
        initial_path = os.path.join(self.firewall.config_dir, default_filename)

        edit_win_x = 2 + len(prompt_str)
        edit_win_width = curses.COLS - edit_win_x - 2
        edit_win = curses.newwin(1, edit_win_width, curses.LINES - 3, edit_win_x)

        self.safe_addstr(edit_win, 0, 0, initial_path)

        box = MyTextbox(edit_win, self.safe_addstr)
        self.stdscr.refresh()

        box.edit()
        path = box.gather().strip()
        curses.curs_set(0)

        if box.cancelled:
            self.show_dialog("Save cancelled.", "info")
            return True

        if path:
            if os.path.exists(path):
                self.show_dialog(f"File '{os.path.basename(path)}' exists. Overwrite?",
                                 "confirm",
                                 action=lambda: self.save_config_action(path))
            else:
                self.save_config_action(path)
        else:
            self.show_dialog("Save cancelled.", "info")
        return True

    def draw_log_view_screen(self):
        """Draw a generic log view screen."""
        self.stdscr.clear()
        self.draw_header()
        self.safe_addstr(self.stdscr, 2, 2, self.log_view_title, curses.A_BOLD)

        log_window_height = curses.LINES - 7
        log_win = self.stdscr.subwin(log_window_height, curses.COLS - 4, 4, 2)
        log_win.border()

        max_lines = log_window_height - 2
        start_line = max(0, len(self.log_view_content) - max_lines)

        for i, log_line in enumerate(self.log_view_content[start_line:]):
            self.safe_addstr(log_win, i + 1, 2, log_line.strip()[:curses.COLS - 8])

        self.safe_addstr(self.stdscr, curses.LINES - 2, 2, "Press [Esc] or [q] to return to the main menu."[:curses.COLS - 3], curses.A_BOLD)
        self.stdscr.refresh()
        log_win.refresh()

    def draw_add_rule_screen(self):
        """ルール追加画面を描画"""
        self.stdscr.clear()
        self.draw_header()

        self.safe_addstr(self.stdscr, 2, 2, "Add/Edit New Firewall Rule", curses.A_BOLD)

        form_fields = [
            ("Action", ["block", "pass"]),
            ("Direction", ["in", "out"]),
            ("Quick", ["Yes", "No"]),
            ("Interface", None),
            ("Protocol", ["tcp", "udp", "tcp,udp", "icmp", "any"]),
            ("Source", None),
            ("Destination", None),
            ("Port", None),
            ("Keep State", ["Yes", "No"]),
            ("Description", None)
        ]

        y = 4
        for i, (field, options) in enumerate(form_fields):
            y_pos = y + i
            is_selected = (i == self.form_field)
            field_key = field.lower().replace(' ', '_')
            current_value = self.form_data.get(field_key, self.form_defaults.get(field_key))

            # Set background for the whole line if selected
            line_attr = curses.color_pair(2) if is_selected else curses.A_NORMAL
            self.safe_addstr(self.stdscr, y_pos, 4, ' ' * (curses.COLS - 5), line_attr)

            # Draw field label
            self.safe_addstr(self.stdscr, y_pos, 4, f"{field:12}: ", line_attr)
            x_pos = 4 + 14

            if options:
                for opt in options:
                    attr = line_attr
                    if opt == current_value:
                        attr |= curses.A_REVERSE

                    self.safe_addstr(self.stdscr, y_pos, x_pos, opt[:curses.COLS - x_pos - 1], attr)
                    x_pos += len(opt) + 2
            else:
                # For free-text fields
                self.safe_addstr(self.stdscr, y_pos, x_pos, current_value[:curses.COLS - x_pos - 1], line_attr)
                #x_pos += len(current_value)
                x_pos += len(current_value) if current_value is not None else 0
                if not options and (current_value == 'any' or (field.lower() == 'description' and not current_value)):
                    hint = "  <-- Press Enter to specify"
                    #if x_pos + len(hint) < curses.COLS - 5:
                    if x_pos + len(hint or "") < curses.COLS - 5:
                         self.safe_addstr(self.stdscr, y_pos, x_pos, hint[:curses.COLS - x_pos - 1], line_attr)

        y += len(form_fields) + 2
        self.safe_addstr(self.stdscr, y, 4, "Instructions:", curses.A_BOLD)
        self.safe_addstr(self.stdscr, y + 1, 4, "Up/Down: Navigate fields"[:curses.COLS - 5])
        self.safe_addstr(self.stdscr, y + 2, 4, "Left/Right: Change value for fields with options (e.g., Action)"[:curses.COLS - 5])
        self.safe_addstr(self.stdscr, y + 3, 4, "Enter: Edit value for text fields (e.g., Source)"[:curses.COLS - 5])
        self.safe_addstr(self.stdscr, y + 4, 4, "'s': Save rule | Esc: Cancel"[:curses.COLS - 5])


        if self.status_message:
            self.safe_addstr(self.stdscr, curses.LINES - 2, 2, self.status_message[:curses.COLS - 3])

    def draw_edit_rule_screen(self):
        """ルール編集選択画面を描画"""
        self.current_screen = "edit_rules"
        self.stdscr.clear()
        self.draw_header()
        self.safe_addstr(self.stdscr, 2, 2, "Select a Rule to Edit (scroll with up/down arrows)", curses.A_BOLD)

        y = 4
        header_line = f"{'#':<3} {'Action':<7} {'Dir':<5} {'Q':<3} {'Proto':<7} {'Source':<15} {'Dest':<15} {'Port':<10} {'S':<3} {'Description'}"
        self.safe_addstr(self.stdscr, y, 8, header_line[:curses.COLS - 9], curses.A_BOLD)
        y += 1


        max_items = curses.LINES - y - 3
        if max_items < 1: max_items = 1

        # Adjust scroll offset if selection is out of view
        if self.edit_selection < self.scroll_offset:
            self.scroll_offset = self.edit_selection
        if self.edit_selection >= self.scroll_offset + max_items:
            self.scroll_offset = self.edit_selection - max_items + 1

        visible_rules = self.firewall.rules[self.scroll_offset : self.scroll_offset + max_items]

        for i, rule in enumerate(visible_rules):
            actual_index = self.scroll_offset + i
            quick_val = 'Y' if rule.quick else ''
            state_val = 'Y' if rule.keep_state else ''
            rule_line = f"{actual_index+1:<3} {rule.action.value:<7} {rule.direction.value:<5} {quick_val:<3} {rule.protocol:<7} {rule.source:<15} {rule.destination:<15} {rule.port:<10} {state_val:<3} {rule.description}"

            display_y = y + i
            if display_y >= curses.LINES - 2:
                break

            if actual_index == self.edit_selection:
                self.stdscr.attron(curses.color_pair(2))
                self.safe_addstr(self.stdscr, display_y, 6, f"> {rule_line[:curses.COLS-9]}")
                self.stdscr.attroff(curses.color_pair(2))
            else:
                self.safe_addstr(self.stdscr, display_y, 6, f"  {rule_line[:curses.COLS-9]}")

        # Show scroll position
        rule_count = len(self.firewall.rules)
        if rule_count > max_items:
            scroll_text = f"({self.edit_selection + 1}/{rule_count})"
            self.safe_addstr(self.stdscr, 2, curses.COLS - len(scroll_text) - 2, scroll_text)

        help_text = "Arrows: Navigate | Enter: Edit | d: Delete | k/j: Move Up/Down | s: Save order | Esc: Cancel"
        self.safe_addstr(self.stdscr, curses.LINES - 1, 2, help_text[:curses.COLS - 3])

    def draw_edit_rdr_rule_screen(self):
        """RDRルール編集選択画面を描画"""
        self.current_screen = "edit_rdr_rules"
        self.stdscr.clear()
        self.draw_header()
        self.safe_addstr(self.stdscr, 2, 2, "Select a Port Forwarding Rule to Edit (scroll with up/down arrows)", curses.A_BOLD)

        y = 4
        max_items = curses.LINES - y - 3
        if max_items < 1: max_items = 1

        # Adjust scroll offset if selection is out of view
        if self.edit_selection < self.scroll_offset:
            self.scroll_offset = self.edit_selection
        if self.edit_selection >= self.scroll_offset + max_items:
            self.scroll_offset = self.edit_selection - max_items + 1

        visible_rules = self.firewall.rdr_rules[self.scroll_offset : self.scroll_offset + max_items]

        for i, rule in enumerate(visible_rules):
            actual_index = self.scroll_offset + i
            rule_line = f"{actual_index+1:<3} {rule.interface:<10} {rule.protocol:<7} {rule.external_port:<10} -> {rule.internal_ip:<15}:{rule.internal_port:<10} {rule.description}"

            display_y = y + i
            if display_y >= curses.LINES - 2:
                break

            if actual_index == self.edit_selection:
                self.stdscr.attron(curses.color_pair(2))
                self.safe_addstr(self.stdscr, display_y, 4, f"> {rule_line[:curses.COLS-7]}")
                self.stdscr.attroff(curses.color_pair(2))
            else:
                self.safe_addstr(self.stdscr, display_y, 4, f"  {rule_line[:curses.COLS-7]}")

        # Show scroll position
        rule_count = len(self.firewall.rdr_rules)
        if rule_count > max_items:
            scroll_text = f"({self.edit_selection + 1}/{rule_count})"
            self.safe_addstr(self.stdscr, 2, curses.COLS - len(scroll_text) - 2, scroll_text)

        help_text = "Arrows: Navigate | Enter: Edit | d: Delete | k/j: Move Up/Down | s: Save order | Esc: Cancel"
        self.safe_addstr(self.stdscr, curses.LINES - 1, 2, help_text[:curses.COLS - 3])

        if self.status_message:
            self.safe_addstr(self.stdscr, curses.LINES - 2, 2, self.status_message[:curses.COLS - 3])

    def draw_file_browser_screen(self):
        """Draw the file browser screen."""
        self.stdscr.clear()
        self.draw_header()
        self.safe_addstr(self.stdscr, 2, 2, f"Import from: {self.browser_path}", curses.A_BOLD)

        y = 4
        try:
            files = sorted(os.listdir(self.browser_path))
        except OSError as e:
            self.show_dialog(f"Error: {e}", "error")
            self.mode = "main"
            return

        # Add a ".." entry to go up one directory
        if self.browser_path != "/":
            files.insert(0, "..")

        for i, file_name in enumerate(files):
            full_path = os.path.join(self.browser_path, file_name)
            display_name = file_name
            if os.path.isdir(full_path):
                display_name += "/"

            if i == self.browser_selection:
                self.stdscr.attron(curses.color_pair(2))
                self.safe_addstr(self.stdscr, y + i, 4, f"> {display_name}")
                self.stdscr.attroff(curses.color_pair(2))
            else:
                self.safe_addstr(self.stdscr, y + i, 4, f"  {display_name}")

        help_text = "Arrows: Navigate | Enter: Edit | Esc: Cancel"
        self.safe_addstr(self.stdscr, curses.LINES - 1, 2, help_text[:curses.COLS - 3])

    def delete_rule(self):
        if 0 <= self.edit_selection < len(self.firewall.rules):
            del self.firewall.rules[self.edit_selection]
            self.status_message = f"Rule #{self.edit_selection + 1} deleted."
            self.edit_selection = max(0, self.edit_selection - 1)
        return True

    def delete_rdr_rule(self):
        if not self.firewall.rdr_rules:
            self.status_message = "No RDR rules to delete."
            return False
        if 0 <= self.edit_selection < len(self.firewall.rdr_rules):
            del self.firewall.rdr_rules[self.edit_selection]
            self.status_message = f"RDR Rule #{self.edit_selection + 1} deleted."
            # 選択位置を修正
            if self.edit_selection >= len(self.firewall.rdr_rules):
                self.edit_selection = max(0, len(self.firewall.rdr_rules) - 1)
            return True
        self.status_message = "Invalid selection."
        return False

    def save_config_action(self, path):
        """Save the configuration to the specified path."""
        success = self.firewall.save_rules_to_path(path)
        msg = f"Configuration saved to {os.path.basename(path)}" if success else "Error saving configuration."
        self.status_message = msg
        self.mode = "main"
        return True

    def perform_save_and_apply(self):
        """Callback for the save and apply confirmation dialog."""
        if self.firewall.save_rules():
            success, message = self.firewall.apply_rules(self.stdscr)
            if success:
                self.status_message = message
            else:
                self.show_dialog(message, "error")
        else:
            self.show_dialog("Failed to save rules before applying.", "error")
        return True

    def handle_file_browser_input(self, key):
        """Handle input for the file browser screen."""
        try:
            files = sorted(os.listdir(self.browser_path))
        except OSError:
            self.mode = "main"
            return

        if self.browser_path != "/":
            files.insert(0, "..")

        num_files = len(files)

        if key == 27:  # ESC
            self.mode = "main"
            self.status_message = "Import cancelled."
        elif key == curses.KEY_UP:
            self.browser_selection = (self.browser_selection - 1 + num_files) % num_files
        elif key == curses.KEY_DOWN:
            self.browser_selection = (self.browser_selection + 1) % num_files
        elif key == ord('\n'):
            selected_file = files[self.browser_selection]
            full_path = os.path.join(self.browser_path, selected_file)

            if os.path.isdir(full_path):
                self.browser_path = os.path.abspath(full_path)
                self.browser_selection = 0
            else:
                # This is a file, so handle it based on the browser mode
                if self.browser_mode == "import":
                    success, message = self.firewall.import_rules(full_path)
                    self.show_dialog(message, "info" if success else "error")
                    self.mode = "main"
                elif self.browser_mode == "save":
                    # We are in save mode, so we should ask for a filename
                    self.show_dialog(f"Save as: {selected_file}?", "confirm", action=lambda: self.save_config_action(full_path))

    def handle_main_input(self, key):
        """メイン画面での入力処理"""
        num_items = len(self.menu_items)
        if key == 27 or key == ord('q'):  # ESC or q
            self.show_dialog("Are you sure you want to quit?", "confirm", action=lambda: False)
            return True
        elif key == curses.KEY_UP:
            self.current_selection = (self.current_selection - 1 + num_items) % num_items
            if self.menu_items[self.current_selection] == "---" or self.menu_items[self.current_selection].startswith(("Startup:", "PF Status:", "Anchor Mode:")):
                self.current_selection = (self.current_selection - 1 + num_items) % num_items
        elif key == curses.KEY_DOWN:
            self.current_selection = (self.current_selection + 1) % num_items
            if self.menu_items[self.current_selection] == "---" or self.menu_items[self.current_selection].startswith(("Startup:", "PF Status:", "Anchor Mode:")):
                self.current_selection = (self.current_selection + 1) % num_items
        elif key == ord('\n'):
            selection_text = self.menu_items[self.current_selection]

            if selection_text == "Add New Rule":
                self.mode = "add_rule"
                self.form_data = self.form_defaults.copy()
                self.form_field = 0
                self.editing_rule_index = None
            elif selection_text == "Edit Port Forwarding Rule":
                if not self.firewall.rdr_rules:
                    self.show_dialog("No RDR rules to edit. Please add rules first.", "error")
                else:
                    self.mode = "edit_rdr_rule"
                    self.edit_selection = 0
            elif selection_text == "Add Port Forwarding Rule":
                self.mode = "add_rdr_rule"
                self.form_data = self.rdr_form_defaults.copy()
                self.form_field = 0
                self.editing_rule_index = None
            elif selection_text == "Edit Rule":
                if not self.firewall.rules:
                    self.show_dialog("No rules to edit. Please add rules first.", "error")
                else:
                    self.mode = "edit_rule"
                    self.edit_selection = 0
            elif selection_text == "Show Current Rules":
                self.log_view_content = self.firewall.get_current_rules()
                if not self.log_view_content:
                    self.log_view_content = ["No active rules found."]
                self.log_view_title = "Current Live PF Rules"
                self.mode = "view_log"
            elif selection_text == "Save & Apply Rules to System":
                if not self.firewall.rules:
                    self.show_dialog("No rules to apply. Please add rules first.", "error")
                else:
                    self.show_dialog(
                        "This will save the current rules and apply them to the live system firewall. Continue?",
                        "confirm",
                        action=lambda: self.perform_save_and_apply()
                    )
            elif selection_text.startswith("PF Status:"):
                self.pf_status = self.firewall.get_pf_status(self.stdscr)
                self.show_dialog(f"Current PF status is: {self.pf_status}", "info")
            elif selection_text == "Enable PF":
                success, message = self.firewall.enable_pf(self.stdscr)
                self.pf_status = self.firewall.get_pf_status(self.stdscr)
                self.show_dialog(message, "info" if success else "error")
            elif selection_text == "Disable PF":
                success, message = self.firewall.disable_pf(self.stdscr)
                self.pf_status = self.firewall.get_pf_status(self.stdscr)
                self.show_dialog(message, "info" if success else "error")
            elif selection_text == "Enable PF on Startup":
                success, message = self.firewall.enable_pf_on_startup(self.stdscr)
                self.startup_status = self.firewall.get_startup_status()
                self.show_dialog(message, "info" if success else "error")
            elif selection_text == "Disable PF on Startup":
                success, message = self.firewall.disable_pf_on_startup(self.stdscr)
                self.startup_status = self.firewall.get_startup_status()
                self.show_dialog(message, "info" if success else "error")
            elif selection_text == "Show Current System Rules":
                self.log_view_content = self.firewall.get_current_rules()
                self.log_view_title = "Current System Firewall Rules"
                self.mode = "view_log"
            elif selection_text == "Show Info":
                self.mode = "show_info"
                self.last_info_refresh = 0 # Force immediate refresh
            elif selection_text == "Save Configuration":
                self.prompt_for_save_path()
            elif selection_text == "Import Configuration":
                self.mode = "file_browser"
                self.browser_mode = "import"
                self.browser_path = self.firewall.config_dir
                self.browser_selection = 0
            elif selection_text == "Exit":
                self.show_dialog("Are you sure you want to quit?", "confirm", action=lambda: False)
        return True

    def handle_edit_rule_input(self, key):
        """ルール編集選択画面での入力処理"""
        num_rules = len(self.firewall.rules)
        if key == 27:  # ESC
            self.mode = "main"
            self.status_message = "Cancelled rule editing"
            return

        if key == curses.KEY_UP:
            self.edit_selection = (self.edit_selection - 1 + num_rules) % num_rules
        elif key == curses.KEY_DOWN:
            self.edit_selection = (self.edit_selection + 1) % num_rules
        elif key == ord('k'):  # Move rule up
            if num_rules > 1 and self.edit_selection > 0:
                self.firewall.rules.insert(self.edit_selection - 1, self.firewall.rules.pop(self.edit_selection))
                self.edit_selection -= 1
                self.status_message = "Rule moved up."
        elif key == ord('j'):  # Move rule down
            if num_rules > 1 and self.edit_selection < num_rules - 1:
                self.firewall.rules.insert(self.edit_selection + 1, self.firewall.rules.pop(self.edit_selection))
                self.edit_selection += 1
                self.status_message = "Rule moved down."
        #elif key == ord('d'):
        #    self.show_dialog(f"Delete rule #{self.edit_selection + 1}?", "confirm", action=self.delete_rule)
        elif key == ord('d'):
            if self.current_screen == "edit_rules":
                self.show_dialog(f"Delete rule #{self.edit_selection + 1}?", "confirm", action=self.delete_rule)
            elif self.current_screen == "edit_rdr_rules":
                self.show_dialog(f"Delete RDR rule #{self.edit_selection + 1}?", "confirm", action=self.delete_rdr_rule)
        elif key == ord('s'): # Save order
            if self.firewall.save_rules():
                self.show_dialog("Rule order saved successfully.", "info")
            else:
                self.show_dialog("Failed to save rule order.", "error")
            self.mode = "main"
        elif key == ord('\n'):
            # Load selected rule into form for editing
            selected_rule = self.firewall.rules[self.edit_selection]
            self.form_data = {
                "action": selected_rule.action.value,
                "direction": selected_rule.direction.value,
                "interface": selected_rule.interface,
                "protocol": selected_rule.protocol,
                "source": selected_rule.source,
                "destination": selected_rule.destination,
                "port": selected_rule.port,
                "description": selected_rule.description,
                "quick": "Yes" if selected_rule.quick else "No",
                "keep_state": "Yes" if selected_rule.keep_state else "No"
            }
            self.form_field = 0
            self.editing_rule_index = self.edit_selection # Remember which rule we are editing
            self.mode = "add_rule"  # Reuse the add_rule screen/logic
            self.status_message = f"Editing rule #{self.edit_selection + 1}"

    def handle_edit_rdr_rule_input(self, key):
        """RDRルール編集選択画面での入力処理"""
        num_rules = len(self.firewall.rdr_rules)
        if num_rules == 0:
            self.mode = "main"
            self.status_message = "No RDR rules to edit."
            return

        if key == 27:  # ESC
            self.mode = "main"
            self.status_message = "Cancelled RDR rule editing"
            return

        if key == curses.KEY_UP:
            self.edit_selection = (self.edit_selection - 1 + num_rules) % num_rules
        elif key == curses.KEY_DOWN:
            self.edit_selection = (self.edit_selection + 1) % num_rules
        elif key == ord('k'):  # Move rule up
            if num_rules > 1 and self.edit_selection > 0:
                self.firewall.rdr_rules.insert(
                    self.edit_selection - 1,
                    self.firewall.rdr_rules.pop(self.edit_selection)
                )
                self.edit_selection -= 1
                self.status_message = "RDR rule moved up."
        elif key == ord('j'):  # Move rule down
            if num_rules > 1 and self.edit_selection < num_rules - 1:
                self.firewall.rdr_rules.insert(
                    self.edit_selection + 1,
                    self.firewall.rdr_rules.pop(self.edit_selection)
                )
                self.edit_selection += 1
                self.status_message = "RDR rule moved down."
        elif key == ord('d'):
            self.show_dialog(
                f"Delete RDR rule #{self.edit_selection + 1}?",
                "confirm",
                action=self.delete_rdr_rule
            )
        elif key == ord('s'):  # Save order
            #if self.firewall.save_rdr_rules():
            if self.firewall.save_rules():
                self.show_dialog("RDR rule order saved successfully.", "info")
            else:
                self.show_dialog("Failed to save RDR rule order.", "error")
            self.mode = "main"
        elif key == ord('\n'):
            # RDRルール編集用のロジック（もしあれば）
            selected_rule = self.firewall.rdr_rules[self.edit_selection]
            self.form_data = {
                "interface": selected_rule.interface,
                "protocol": selected_rule.protocol,
                "external_ip": selected_rule.external_ip,
                "external_port": selected_rule.external_port,
                "internal_ip": selected_rule.internal_ip,
                "internal_port": selected_rule.internal_port,
                "description": selected_rule.description
            }
            self.form_field = 0
            self.editing_rdr_rule_index = self.edit_selection
            self.mode = "add_rdr_rule"  # RDRルール編集画面に遷移
            self.status_message = f"Editing RDR rule #{self.edit_selection + 1}"


    def draw_add_rdr_rule_screen(self):
        """ポートフォワーディングルール追加画面を描画"""
        self.stdscr.clear()
        self.draw_header()

        self.safe_addstr(self.stdscr, 2, 2, "Add/Edit Port Forwarding Rule", curses.A_BOLD)

        form_fields = [
            ("Interface", ["any"]),
            ("Protocol", ["tcp", "udp"]),
            ("External IP", None),
            ("External Port", None),
            ("Internal IP", None),
            ("Internal Port", None),
            ("Description", None)
        ]

        y = 4
        for i, (field, options) in enumerate(form_fields):
            y_pos = y + i
            is_selected = (i == self.form_field)
            field_key = field.lower().replace(' ', '_')
            current_value = self.form_data.get(field_key, self.rdr_form_defaults.get(field_key, ''))

            line_attr = curses.color_pair(2) if is_selected else curses.A_NORMAL
            self.safe_addstr(self.stdscr, y_pos, 4, ' ' * (curses.COLS - 5), line_attr)
            self.safe_addstr(self.stdscr, y_pos, 4, f"{field:15}: ", line_attr)
            x_pos = 4 + 17

            if options:
                for opt in options:
                    attr = line_attr
                    if opt == current_value:
                        attr |= curses.A_REVERSE
                    self.safe_addstr(self.stdscr, y_pos, x_pos, opt, attr)
                    x_pos += len(opt) + 2
            else:
                self.safe_addstr(self.stdscr, y_pos, x_pos, current_value, line_attr)
                x_pos += len(current_value)

                hint = ""
                if not options:
                    if field == "External IP" and current_value == "any":
                        hint = "  <-- Press Enter to specify"
                    elif field == "Internal IP":
                        hint = "  <-- Press Enter to specify (e.g., 192.168.1.100)"
                    elif not current_value:
                        hint = "  <-- Press Enter to specify"

                if hint and x_pos + len(hint) < curses.COLS - 5:
                    self.safe_addstr(self.stdscr, y_pos, x_pos, hint, line_attr)

        y += len(form_fields) + 2
        self.safe_addstr(self.stdscr, y, 4, "Instructions:", curses.A_BOLD)
        self.safe_addstr(self.stdscr, y + 1, 4, "Up/Down: Navigate | Left/Right: Change value | Enter: Edit value")
        self.safe_addstr(self.stdscr, y + 2, 4, "'s': Save rule | Esc: Cancel")

    def handle_add_rdr_rule_input(self, key):
        """RDRルール追加・編集画面での入力処理"""
        form_fields_with_opts = [
            ("Interface", None),
            ("Protocol", ["tcp", "udp"]),
            ("External IP", None),
            ("External Port", None),
            ("Internal IP", None),
            ("Internal Port", None),
            ("Description", None)
        ]
        form_fields = [f[0].lower().replace(' ', '_') for f in form_fields_with_opts]

        if key == 27:  # ESC key
            self.mode = "main"
            self.status_message = "Cancelled"
            self.editing_rule_index = None # Clear editing state
            return
        elif key == curses.KEY_UP:
            self.form_field = max(0, self.form_field - 1)
        elif key == curses.KEY_DOWN:
            self.form_field = min(len(form_fields) - 1, self.form_field + 1)

        field_name, options = form_fields_with_opts[self.form_field]
        field_key = field_name.lower().replace(' ', '_')

        if options and (key == curses.KEY_LEFT or key == curses.KEY_RIGHT):
            current_value = self.form_data.get(field_key, options[0])
            try:
                current_idx = options.index(current_value)
            except ValueError:
                current_idx = 0

            if key == curses.KEY_LEFT:
                new_idx = (current_idx - 1 + len(options)) % len(options)
            else:  # KEY_RIGHT
                new_idx = (current_idx + 1) % len(options)

            self.form_data[field_key] = options[new_idx]
            self.status_message = f"Set {field_name} to: {self.form_data[field_key]}"

        elif key == ord('\n'):
            if not options:
                curses.curs_set(1)

                edit_y = 4 + self.form_field
                edit_x = 4 + 15 + 2

                current_value = self.form_data.get(field_key, "")

                edit_win = curses.newwin(1, curses.COLS - edit_x - 5, edit_y, edit_x)
                edit_win.keypad(True)
                edit_win.bkgd(' ', curses.color_pair(2))

                if current_value:
                    self.safe_addstr(edit_win, 0, 0, current_value)

                self.stdscr.refresh()

                box = MyTextbox(edit_win, self.safe_addstr)

                try:
                    box.edit()
                    if box.cancelled:
                        self.status_message = "Input cancelled"
                    else:
                        value = box.gather().strip()
                        self.form_data[field_key] = value
                        self.status_message = f"Set {field_name} to: {self.form_data[field_key]}"

                except curses.error:
                    self.status_message = "Input cancelled"
                finally:
                    curses.curs_set(0)
                    curses.noecho()
            else:
                self.status_message = f"{field_name} can be changed with Left/Right arrows."

        elif key == ord('s'):
            try:
                # Validate required fields before saving
                required_fields = {
                    'interface': "Interface cannot be empty.",
                    'external_port': "External Port cannot be empty.",
                    'internal_ip': "Internal IP cannot be empty.",
                    'internal_port': "Internal Port cannot be empty."
                }
                for field, msg in required_fields.items():
                    if not self.form_data.get(field):
                        self.show_dialog(msg, "error")
                        return

                rule = PortForwardingRule(
                    interface=self.form_data.get('interface', self.rdr_form_defaults['interface']),
                    protocol=self.form_data.get('protocol', self.rdr_form_defaults['protocol']),
                    external_ip=self.form_data.get('external_ip', self.rdr_form_defaults['external_ip']),
                    external_port=self.form_data.get('external_port', self.rdr_form_defaults['external_port']),
                    internal_ip=self.form_data.get('internal_ip', self.rdr_form_defaults['internal_ip']),
                    internal_port=self.form_data.get('internal_port', self.rdr_form_defaults['internal_port']),
                    description=self.form_data.get('description', self.rdr_form_defaults['description'])
                )

                if self.editing_rule_index is not None:
                    self.firewall.rdr_rules[self.editing_rule_index] = rule
                    self.status_message = "RDR rule updated successfully!"
                    self.editing_rule_index = None
                else:
                    if self.firewall.rdr_rule_exists(rule):
                        self.show_dialog("Error: An identical port forwarding rule already exists.", "error")
                        return
                    self.firewall.rdr_rules.append(rule)
                    self.status_message = "RDR rule added successfully!"
                self.mode = "main"
            except Exception as e:
                self.show_dialog(f"Error saving RDR rule: {str(e)}", "error")

    def handle_log_view_input(self, key):
        """Handle input for the log viewing screen."""
        if key in [27, ord('q')]:  # ESC or q
            self.mode = "main"
            self.status_message = "Closed log view."

    def handle_info_input(self, key):
        """Handle input for the info screen."""
        if key in [27, ord('q')]: # ESC or q
            self.mode = "main"
            self.status_message = "Closed info view."

    def handle_add_rule_input(self, key):
        """ルール追加・編集画面での入力処理"""
        form_fields_with_opts = [
            ("Action", ["block", "pass"]),
            ("Direction", ["in", "out"]),
            ("Quick", ["Yes", "No"]),
            ("Interface", None),
            ("Protocol", ["tcp", "udp", "tcp,udp", "icmp", "any"]),
            ("Source", None),
            ("Destination", None),
            ("Port", None),
            ("Keep State", ["Yes", "No"]),
            ("Description", None)
        ]
        form_fields = [f[0].lower().replace(' ', '_') for f in form_fields_with_opts]

        if key == 27:  # ESC key
            self.mode = "main"
            self.status_message = "Cancelled"
            self.editing_rule_index = None # Clear editing state
            return
        elif key == curses.KEY_UP:
            self.form_field = max(0, self.form_field - 1)
        elif key == curses.KEY_DOWN:
            self.form_field = min(len(form_fields) - 1, self.form_field + 1)

        field_name, options = form_fields_with_opts[self.form_field]
        field_key = field_name.lower().replace(' ', '_')

        if options and (key == curses.KEY_LEFT or key == curses.KEY_RIGHT):
            current_value = self.form_data.get(field_key, self.form_defaults.get(field_key))
            try:
                current_idx = options.index(current_value)
            except ValueError:
                current_idx = 0

            if key == curses.KEY_LEFT:
                new_idx = (current_idx - 1 + len(options)) % len(options)
            else:  # KEY_RIGHT
                new_idx = (current_idx + 1) % len(options)

            self.form_data[field_key] = options[new_idx]
            self.status_message = f"Set {field_name} to: {self.form_data[field_key]}"

        elif key == ord('\n'):
            if not options:
                # For free-text fields, allow inline editing
                curses.curs_set(1)

                edit_y = 4 + self.form_field
                edit_x = 4 + 12 + 2  # 4 (indent) + 12 (field width) + 2 (': ')

                current_value = self.form_data.get(field_key, self.form_defaults.get(field_key, ""))

                # Create a text box for editing
                edit_win = curses.newwin(1, curses.COLS - edit_x - 5, edit_y, edit_x)
                edit_win.keypad(True)
                edit_win.bkgd(' ', curses.color_pair(2))

                # Add the current value to the window before creating the textbox
                if current_value:
                    self.safe_addstr(edit_win, 0, 0, current_value)

                self.stdscr.refresh()

                box = MyTextbox(edit_win, self.safe_addstr)

                try:
                    # Let the user edit the text
                    box.edit()
                    if box.cancelled:
                        self.status_message = "Input cancelled"
                    else:
                        value = box.gather().strip()
                        self.form_data[field_key] = value if value else self.form_defaults.get(field_key, "any")
                        self.status_message = f"Set {field_name} to: {self.form_data[field_key]}"

                except curses.error:
                    self.status_message = "Input cancelled"
                finally:
                    curses.curs_set(0)
                    curses.noecho()
            else:
                self.status_message = f"{field_name} can be changed with Left/Right arrows."

        elif key == ord('s'):
            # ルール保存
            try:
                action = self.form_data.get('action', self.form_defaults['action'])
                direction = self.form_data.get('direction', self.form_defaults['direction'])

                if action not in ['block', 'pass']:
                    self.show_dialog("Invalid action. Use 'block' or 'pass'.", "error")
                    return

                if direction not in ['in', 'out']:
                    self.show_dialog("Invalid direction. Use 'in' or 'out'.", "error")
                    return

                rule = FirewallRule(
                    action=Action(action),
                    direction=Direction(direction),
                    interface=self.form_data.get('interface', self.form_defaults['interface']),
                    protocol=self.form_data.get('protocol', self.form_defaults['protocol']),
                    source=self.form_data.get('source', self.form_defaults['source']),
                    destination=self.form_data.get('destination', self.form_defaults['destination']),
                    port=self.form_data.get('port', self.form_defaults['port']),
                    description=self.form_data.get('description', self.form_defaults['description']),
                    quick=self.form_data.get('quick', self.form_defaults['quick']) == "Yes",
                    keep_state=self.form_data.get('keep_state', self.form_defaults['keep_state']) == "Yes"
                )

                if self.editing_rule_index is not None:
                    self.firewall.rules[self.editing_rule_index] = rule
                    self.status_message = "Rule updated successfully!"
                    # Keep the selection on the edited rule
                    self.edit_selection = self.editing_rule_index
                    self.editing_rule_index = None
                else:
                    if self.firewall.rule_exists(rule):
                        self.show_dialog("Error: An identical filter rule already exists.", "error")
                        return
                    self.firewall.rules.append(rule)
                    self.status_message = "Rule added successfully!"
                    # Select the newly added rule
                    self.edit_selection = len(self.firewall.rules) - 1
                self.mode = "edit_rule"
            except Exception as e:
                self.show_dialog(f"Error saving rule: {str(e)}", "error")

    def handle_dialog_input(self, key):
        """ダイアログでの入力処理"""
        if self.dialog_type == "confirm":
            if key == ord('\n'):  # Enter to confirm
                action_result = True
                if self.confirm_action:
                    action_result = self.confirm_action()

                self.mode = getattr(self, '_previous_mode', 'main')
                self.confirm_action = None
                return action_result

            elif key == 27:  # ESC to cancel
                self.mode = getattr(self, '_previous_mode', 'main')
                self.confirm_action = None
                return True
        else:
            if key == ord('\n') or key == 27:  # Enter or ESC to close
                self.mode = getattr(self, '_previous_mode', 'main')
                return True

        return True # Stay in dialog for other keys

    def main_loop(self):
        """メインループ"""
        logging.info("Starting main loop.")
        while True:
            # 1秒ごとに情報を更新
            if self.mode == "show_info":
                if time.time() - self.last_info_refresh >= 1:
                    _, self.info_view_content = self.firewall.get_pf_info(self.stdscr)
                    self.last_info_refresh = time.time()
                self.stdscr.timeout(1000)  # 1秒のタイムアウト
            else:
                self.stdscr.timeout(-1) # 通常はブロック

            # モードに応じた画面を描画
            if self.mode == "main":
                self.draw_main_screen()
            elif self.mode == "add_rule":
                self.draw_add_rule_screen()
            elif self.mode == "edit_rule":
                self.draw_edit_rule_screen()
            elif self.mode == "add_rdr_rule":
                self.draw_add_rdr_rule_screen()
            elif self.mode == "edit_rdr_rule":
                self.draw_edit_rdr_rule_screen()
            elif self.mode == "view_log":
                self.draw_log_view_screen()
            elif self.mode == "show_info":
                self.draw_info_screen()
            elif self.mode == "file_browser":
                self.draw_file_browser_screen()

            # ダイアログモードの場合は、現在の画面の上にダイアログを描画
            if self.mode == "dialog":
                self.draw_dialog()
            else:
                 self.stdscr.refresh() # ダイアログがない場合のみ画面を更新

            key = self.stdscr.getch()
            if key != -1:
                # logging.debug(f"Key pressed: {key}")
                pass

            # ステータスメッセージを一度表示したらクリア
            if self.status_message and key != -1:
                self.status_message = ""

            # モードに応じた入力ハンドラを呼び出し
            continue_running = True
            if self.mode == "main":
                continue_running = self.handle_main_input(key)
            elif self.mode == "add_rule":
                self.handle_add_rule_input(key)
            elif self.mode == "edit_rule":
                self.handle_edit_rule_input(key)
            elif self.mode == "add_rdr_rule":
                self.handle_add_rdr_rule_input(key)
            elif self.mode == "edit_rdr_rule":
                self.handle_edit_rdr_rule_input(key)
            elif self.mode == "view_log":
                self.handle_log_view_input(key)
            elif self.mode == "show_info":
                self.handle_info_input(key)
            elif self.mode == "file_browser":
                self.handle_file_browser_input(key)
            elif self.mode == "dialog":
                continue_running = self.handle_dialog_input(key)

            if not continue_running:
                logging.info("Exiting main loop.")
                break


def main():
    """メイン関数"""
    # OSチェック
    if platform.system() != "Darwin":
        print("This application can only run on macOS.")
        sys.exit(1)

    logging.info("Application starting.")
    print("macOS Personal Firewall TUI")
    print("This tool requires sudo access for pfctl operations.")

    try:
        # Set a short ESC delay to improve responsiveness of arrow keys
        os.environ.setdefault('ESCDELAY', '25')
        tui = FirewallTUI()
        curses.wrapper(tui.init_curses)
    except KeyboardInterrupt:
        logging.info("Application exited by user.")
        print("\nExiting...")
    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}", exc_info=True)
        print(f"\nAn unexpected error occurred: {e}")
        print("Please ensure you are running on macOS and have permissions to run pfctl.")
    finally:
        logging.info("Application finished.")

if __name__ == "__main__":
    main()
