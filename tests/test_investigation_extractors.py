import hashlib

from core.investigation.extractors import extract_nmap

COMPLETE = """Starting Nmap 7.94
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH 8.9p1 Ubuntu
80/tcp  open  http         Apache httpd 2.4.52
445/tcp open  microsoft-ds
Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds
"""


def test_extracts_services_and_provenance():
    result = extract_nmap(COMPLETE, asset_id="asset-1", evidence_id="evidence-1")
    assert result.evidence.execution_status == "completed"
    assert result.evidence.raw_output_sha256 == hashlib.sha256(COMPLETE.encode()).hexdigest()
    assert [(x.port, x.service) for x in result.services] == [
        (22, "ssh"),
        (80, "http"),
        (445, "microsoft-ds"),
    ]
    assert (result.services[0].product, result.services[0].version) == ("OpenSSH", "8.9p1")


def test_complete_empty_scan_is_valid_negative_evidence():
    output = "All scanned ports are closed\nNmap done: 1 IP address scanned\n"
    result = extract_nmap(output, asset_id="asset-1")
    assert result.evidence.complete is True
    assert result.evidence.facts["open_service_count"] == 0


def test_timeout_is_inconclusive():
    result = extract_nmap("Starting Nmap\n", asset_id="asset-1", timed_out=True)
    assert result.evidence.execution_status == "timeout"
    assert result.evidence.complete is False


def test_missing_completion_marker_is_partial():
    result = extract_nmap("80/tcp open http Apache httpd 2.4.52\n", asset_id="asset-1")
    assert result.evidence.execution_status == "partial"
    assert result.services[0].port == 80


def test_truncated_output_is_partial():
    result = extract_nmap(COMPLETE, asset_id="asset-1", truncated=True)
    assert result.evidence.execution_status == "partial"
    assert result.evidence.truncated is True


def test_nonzero_exit_is_failed():
    result = extract_nmap("QUITTING!\n", asset_id="asset-1", exit_code=1)
    assert result.evidence.execution_status == "failed"
    assert result.services == []
