"""
ZeroGate Cloud — Phase 3 Endpoint Telemetry & Wazuh SIEM Integration Tests
Validates custom DLP detection rules (Rule 100240, Rule 100241), false positive
prevention, FIM configuration targeting confidential folders, and Sysmon XML validation.
"""

import time
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


class TestWazuhDLPDetectionRules:
    """Verifies that Wazuh SIEM evaluates and alerts on structured DLP events."""

    def test_wazuh_rule_100240_dlp_match(self):
        """Rule 100240 fires when DLP scanner quarantines a document containing PII."""
        log_event = "Oct 22 02:00:00 zerogate-dlp dlp: DLP_MATCH action=QUARANTINE file=payroll.csv detector=IN_AADHAAR severity=HIGH count=2"
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-dlp-{int(time.time()*1000)%100000}",
            "92f340a33a678b300c0cbef447d28161fc65e3f0005fb4353dee87932a2852a5",
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "id: '100240'" in output
        assert "level: '8'" in output
        assert "T1048" in output
        assert "Alert to be generated." in output

    def test_wazuh_rule_100241_critical_secret_leak(self):
        """Rule 100241 fires with Level 10 when an API key / secret credential is exposed."""
        log_event = "Oct 22 02:00:00 zerogate-dlp dlp: DLP_MATCH action=QUARANTINE file=credentials.env detector=SECRET_AWS_KEY severity=CRITICAL count=1"
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-dlp-crit-{int(time.time()*1000)%100000}",
            "92f340a33a678b300c0cbef447d28161fc65e3f0005fb4353dee87932a2852a5",
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "id: '100241'" in output
        assert "level: '10'" in output
        assert "T1552" in output
        assert "Alert to be generated." in output

    def test_wazuh_dlp_clean_event_no_alert(self):
        """Benign scan events (action=ACCEPT) do NOT trigger false-positive DLP alerts."""
        log_event = "Oct 22 02:00:00 zerogate-dlp dlp: DLP_SCAN action=ACCEPT file=readme.txt severity=INFO count=0"
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-dlp-clean-{int(time.time()*1000)%100000}",
            "92f340a33a678b300c0cbef447d28161fc65e3f0005fb4353dee87932a2852a5",
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "100240" not in output
        assert "100241" not in output
        assert "Alert to be generated." not in output


class TestEndpointAndFIMConfiguration:
    """Verifies that endpoint configuration assets and FIM definitions are structurally valid."""

    def test_sysmon_configuration_valid_xml(self):
        sysmon_file = Path("endpoint/sysmonconfig.xml")
        assert sysmon_file.exists()
        tree = ET.parse(sysmon_file)
        root = tree.getroot()
        assert root.tag == "Sysmon"
        assert root.attrib.get("schemaversion") == "4.90"

        # Verify Event 1 (ProcessCreate), Event 3 (NetworkConnect), Event 11 (FileCreate) rules exist
        rules = root.find("EventFiltering")
        assert rules is not None
        rule_groups = {rg.attrib.get("name") for rg in rules.findall("RuleGroup")}
        assert "ProcessCreation" in rule_groups
        assert "NetworkConnection" in rule_groups
        assert "FileCreation" in rule_groups

    def test_wazuh_agent_fim_configuration_targets_confidential_folder(self):
        agent_conf = Path("endpoint/agent.conf")
        assert agent_conf.exists()
        tree = ET.parse(agent_conf)
        root = tree.getroot()
        assert root.tag == "agent_config"

        syscheck = root.find("syscheck")
        assert syscheck is not None
        directories = [d.text for d in syscheck.findall("directories")]
        assert any(r"data\confidential" in d for d in directories)
        assert any("quarantine" in d for d in directories)

        # Verify nodiff is configured for secret files
        nodiffs = [nd.text for nd in syscheck.findall("nodiff")]
        assert any("*.secret" in nd for nd in nodiffs)
