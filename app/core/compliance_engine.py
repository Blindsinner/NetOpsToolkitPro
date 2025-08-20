# -*- coding: utf-8 -*-
import yaml
import os
from pathlib import Path
from typing import List, Dict, Any

class ComplianceEngine:
    """Audits device configurations against a set of rules."""

    def __init__(self, devices: List[Dict[str, Any]], backup_dir: Path):
        self.devices = devices
        self.backup_dir = backup_dir
        self.results = []

    def run_audit(self, rules_yaml: str) -> List[Dict[str, Any]]:
        """
        Runs the full audit against all devices.
        Returns a structured list of results.
        """
        try:
            ruleset = yaml.safe_load(rules_yaml)
            if not isinstance(ruleset, list):
                raise ValueError("Rules must be a YAML list.")
        except (yaml.YAMLError, ValueError) as e:
            return [{"device": "GLOBAL", "rule": "Parsing Error", "compliant": False, "reason": str(e)}]

        for device in self.devices:
            device_host = device.get("host")
            device_backup_dir = self.backup_dir / device_host
            
            if not device_backup_dir.is_dir() or not any(device_backup_dir.iterdir()):
                self.results.append({"device": device_host, "rule": "N/A", "compliant": False, "reason": "No backup found for this device."})
                continue

            # Get the most recent backup file
            latest_backup = sorted(device_backup_dir.iterdir(), key=os.path.getmtime, reverse=True)[0]
            with open(latest_backup, 'r') as f:
                config = f.read()

            # Check this device against each rule
            for rule in ruleset:
                self._check_rule(device_host, config, rule)

        return self.results

    def _check_rule(self, host: str, config: str, rule: Dict[str, Any]):
        """Checks a single device's config against a single rule."""
        rule_name = rule.get("rule_name", "Unnamed Rule")
        result = {"device": host, "rule": rule_name, "compliant": True, "reason": "Pass"}

        if "must_contain" in rule:
            for item in rule["must_contain"]:
                if item not in config:
                    result["compliant"] = False
                    result["reason"] = f"Missing required line: '{item}'"
                    break
        
        if result["compliant"] and "must_not_contain" in rule:
            for item in rule["must_not_contain"]:
                if item in config:
                    result["compliant"] = False
                    result["reason"] = f"Found forbidden line: '{item}'"
                    break
        
        self.results.append(result)