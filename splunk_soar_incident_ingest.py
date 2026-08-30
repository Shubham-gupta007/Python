"""
Ingest an incident into Splunk SOAR (Phantom) via its REST API.

This creates a Container (incident) and attaches an Artifact whose CEF
dictionary carries:
  - the standard network/event details for the alert (source/destination,
    ports, timestamps, etc.), and
  - the BMC Remedy CRM incident fields, using the *exact* field names/keys
    the downstream BSM Remedy REST API expects (First_Name, Last_Name,
    "Internet E-mail", Impact, Urgency, "CRM SR Number", z1D_Action, ...).

The idea: the CEF fields referenced below must already exist as CEF field
definitions in SOAR (Administration > Event Settings > CEF). Once the
artifact lands with these cef.* values populated, a playbook can trigger
off the artifact and read container.artifact:*.cef.<Field_Name> directly
to build the BMC Remedy incident-creation payload, with no re-mapping.

Configuration is via environment variables:
  SOAR_BASE_URL      e.g. https://soar.example.com
  SOAR_AUTH_TOKEN    ph-auth-token for a SOAR automation user
  SOAR_VERIFY_SSL    "true"/"false" (default: true)

Usage:
  python splunk_soar_incident_ingest.py
"""

import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

import requests
import urllib3

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("soar_ingest")


class SoarClient:
    """Thin wrapper around the Splunk SOAR REST API for container/artifact ingestion."""

    def __init__(self, base_url: str, auth_token: str, verify_ssl: bool = True, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "ph-auth-token": auth_token,
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/rest/{endpoint}"
        resp = self.session.post(url, data=json.dumps(payload), timeout=self.timeout)
        if not resp.ok:
            logger.error("POST %s failed (%s): %s", url, resp.status_code, resp.text)
        resp.raise_for_status()
        return resp.json()

    def _get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}/rest/{endpoint}"
        resp = self.session.get(url, params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def find_container_by_sdi(self, source_data_identifier: str) -> Optional[int]:
        """Look up an existing container by source_data_identifier to avoid duplicate ingestion."""
        params = {
            "_filter_source_data_identifier": json.dumps(source_data_identifier),
            "page_size": 1,
        }
        result = self._get("container", params=params)
        data = result.get("data") or []
        return data[0]["id"] if data else None

    def create_container(
        self,
        name: str,
        description: str,
        label: str,
        severity: str,
        source_data_identifier: str,
        sensitivity: str = "amber",
        status: str = "new",
        tags: Optional[List[str]] = None,
    ) -> int:
        payload = {
            "name": name,
            "description": description,
            "label": label,
            "severity": severity,
            "sensitivity": sensitivity,
            "status": status,
            "source_data_identifier": source_data_identifier,
            "tags": tags or [],
        }
        result = self._post("container", payload)
        container_id = result["id"]
        logger.info("Created container %s (id=%s)", name, container_id)
        return container_id

    def add_artifact(
        self,
        container_id: int,
        cef: Dict[str, Any],
        name: str = "CEF Artifact",
        label: str = "event",
        severity: str = "medium",
        source_data_identifier: Optional[str] = None,
        cef_types: Optional[Dict[str, List[str]]] = None,
        run_automation: bool = True,
    ) -> int:
        payload = {
            "container_id": container_id,
            "name": name,
            "label": label,
            "severity": severity,
            "cef": cef,
            "run_automation": run_automation,
        }
        if source_data_identifier:
            payload["source_data_identifier"] = source_data_identifier
        if cef_types:
            payload["cef_types"] = cef_types
        result = self._post("artifact", payload)
        artifact_id = result["id"]
        logger.info("Added artifact %s to container %s (artifact id=%s)", name, container_id, artifact_id)
        return artifact_id


def build_cef_fields() -> Dict[str, Any]:
    """
    CEF fields for the FortiGate Vertical Port Scan Perimeter alert.

    Includes the network/event details plus the BMC Remedy CRM incident
    fields, keyed exactly as the BSM Remedy REST API payload expects so a
    playbook can forward them verbatim.
    """
    detailed_description = (
        "Dear Team,\n\n"
        "We have observed an alert for the UC: FortiGate Vertical Port Scan Perimeter.\n\n"
        "Please find the details below:\n\n"
        "A security alert for Vertical Port Scan Perimeter was triggered after external IP "
        "1.2.3.4 attempted connections to a large number of destination ports on an "
        "internet-facing asset within a short time window. The activity was detected in "
        "FortiGate traffic logs and matched reconnaissance behavior consistent with network "
        "service enumeration.\n\n"
        "Source IP: 1.2.3.4\n"
        "Detection Window: 08/16/2026 12:40:00\n"
        "Unique Ports Scanned: 50\n"
        "Total Events: 94\n"
        "Actions Observed: allowed, teardown\n"
        "Application Classification: unscanned\n"
        "Hostname: ABC.ABC.ae\n"
        "IP Address: 5.6.7.8 (NAT/internal representation in logs)\n"
        "Exposure: Internet-facing service\n\n"
        "The source IP 1.2.3.4 initiated connection attempts against numerous service ports "
        "on the target host within a single 10-minute interval.\n\n"
        "Observed ports include:\n"
        "15002, 15003, 15004, 1503, 15660, 15742, 16001, 16010, 16012, 16016, 16018, 16080, "
        "16113, 16992, 16993, 17000, 1719, 1720, 17877, 17988, 18040, 18081, 18101, 1863, "
        "18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 24444, 24800, 25734, 25735, "
        "26214, 27000, 27015, 27017, 27352, 27353, 27355, 27715, 28201, 3479, 5060, 5061, "
        "5222, 8443\n\n"
        "The scan targeted numerous VoIP, collaboration, management, remote access, and "
        "high-numbered application ports, indicating an attempt to enumerate exposed services "
        "rather than interact with a specific application.\n\n"
        "The observed behavior is consistent with:\n"
        "- Internet-wide reconnaissance\n"
        "- Service discovery scanning\n"
        "- Exposure mapping\n"
        "- Attack surface enumeration\n\n"
        "Connection results were primarily: server-rst, timeout, deny and client-rst, "
        "indicating that connection attempts were unsuccessful or terminated immediately "
        "after service identification.\n\n"
        "IP Analysis:\n"
        "1.2.3.4 was found in our database.\n"
        "This IP was reported 4 times.\n"
        "Confidence of Abuse is 29%.\n"
        "ISP: Google LLC\n"
        "Usage Type: Data Center/Web Hosting/Transit\n"
        "ASN: AS396982\n"
        "Hostname(s): 1.2.3.4.bc.googleusercontent.com\n"
        "Domain Name: google.com\n"
        "Country: Belgium\n"
        "City: Brussels, Brussels Capital\n\n"
        "Recommendation:\n"
        "- Verify that only authorized services are exposed through policy and review any "
        "externally accessible ports.\n"
        "- Consider implementing a temporary perimeter block or threat-feed enforcement for "
        "the source IP if operationally appropriate.\n"
        "- Continue periodic external attack surface assessments to identify and remediate "
        "unnecessary exposed services.\n\n"
        "Detection Logic:\n"
        "Source IP is external (non-RFC1918/public IP).\n"
        "Destination IP is an internal asset.\n"
        "A single source IP connects to multiple unique destination ports on the same "
        "destination IP.\n"
        "Activity occurs within a 10-minute time window.\n"
        "Alert when the number of unique destination ports exceeds the defined threshold.\n\n"
        "Source Event ID: 9d6ca5f9-1356-497a-ad9e-f801535d9daa@@notable@@time1786870219\n"
        "Source GUID: 9d6ca5f9-1356-497a-ad9e-f801535d9daa\n"
        "Security Domain: threat\n"
        "Severity: medium\n"
        "Source IP: 1.2.3.4\n"
        "Unique Ports: 50"
    )

    cef: Dict[str, Any] = {
        # --- Network / event detail CEF fields ---
        "sourceAddress": "1.2.3.4",
        "destinationAddress": "5.6.7.8",
        "destinationHostName": "ABC.ABC.ae",
        "deviceProduct": "FortiGate",
        "signature": "Vertical Port Scan Perimeter",
        "destinationPortList": (
            "15002,15003,15004,1503,15660,15742,16001,16010,16012,16016,16018,16080,16113,"
            "16992,16993,17000,1719,1720,17877,17988,18040,18081,18101,1863,18988,19101,19283,"
            "19315,19350,19780,19801,19842,24444,24800,25734,25735,26214,27000,27015,27017,"
            "27352,27353,27355,27715,28201,3479,5060,5061,5222,8443"
        ),
        "uniquePortsScanned": 50,
        "totalEvents": 94,
        "actionsObserved": "allowed,teardown",
        "startTime": "08/16/2026 12:40:00",
        "sourceEventId": "9d6ca5f9-1356-497a-ad9e-f801535d9daa@@notable@@time1786870219",
        "sourceGuid": "9d6ca5f9-1356-497a-ad9e-f801535d9daa",
        "securityDomain": "threat",
        "severity": "medium",

        # --- BMC Remedy CRM incident fields (keyed exactly as the Remedy REST payload) ---
        "First_Name": "svc",
        "Last_Name": "soaritsmuat",
        "Internet E-mail": "svc.soaritsmuat@tax.gov.ae",
        "Description": "BMC REST API: CRM Incident Creation Sample123",
        "Detailed_Decription": detailed_description,
        "Impact": "3-Moderate/Limited",
        "Urgency": "3-Medium",
        "Status": "Assigned",
        "Reported Source": "CRM",
        "Service_Type": "User Service Restoration",
        "CRM SR Number": "SR_123",
        "CRM TRN Number": "TRN_123",
        "CRM Application/Bundle Number": "CRM_App",
        "Assigned Support Company": "Federal Tax Authority",
        "Assigned Support Organization": "Security",
        "Assigned Group": "Information Security",
        "z1D_Action": "CREATE",
    }
    return cef


def main() -> int:
    base_url = os.environ.get("SOAR_BASE_URL")
    auth_token = os.environ.get("SOAR_AUTH_TOKEN")
    verify_ssl = os.environ.get("SOAR_VERIFY_SSL", "true").strip().lower() != "false"

    if not base_url or not auth_token:
        logger.error("SOAR_BASE_URL and SOAR_AUTH_TOKEN environment variables are required.")
        return 1

    client = SoarClient(base_url=base_url, auth_token=auth_token, verify_ssl=verify_ssl)

    cef = build_cef_fields()
    source_data_identifier = cef["sourceGuid"]

    existing_container_id = client.find_container_by_sdi(source_data_identifier)
    if existing_container_id:
        logger.info(
            "Container already exists for source_data_identifier=%s (id=%s); adding artifact only.",
            source_data_identifier, existing_container_id,
        )
        container_id = existing_container_id
    else:
        container_id = client.create_container(
            name=f"{cef['signature']} - {cef['sourceAddress']}",
            description=cef["Description"],
            label="events",
            severity=cef["severity"],
            source_data_identifier=source_data_identifier,
        )

    client.add_artifact(
        container_id=container_id,
        cef=cef,
        name=cef["signature"],
        label="event",
        severity=cef["severity"],
        source_data_identifier=source_data_identifier,
        cef_types={
            "sourceAddress": ["ip"],
            "destinationAddress": ["ip"],
            "destinationHostName": ["host name"],
        },
        run_automation=True,
    )

    logger.info("Incident ingestion complete (container_id=%s).", container_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
