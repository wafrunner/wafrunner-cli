import json
from datetime import datetime
from typing import Any, Dict, Optional

from rich import print


def transform_vulnerability(
    vuln_source_data: Dict[str, Any], existing_vulnID: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Transforms vulnerability data from NIST format to the API payload format.
    If existing_vulnID is provided, it's included for an update operation.
    """
    cve = vuln_source_data.get("cve", {})
    cveID = cve.get("id", "")
    if not cveID:
        print(
            f"[bold red]Error:[/bold red] Source data is missing 'cve.id'. VulnID (if any): {existing_vulnID}."
        )
        return None

    # Description
    descriptions_list = cve.get("descriptions", []) or []
    description_en = "No description provided."
    if isinstance(descriptions_list, list):
        for d in descriptions_list:
            if (
                isinstance(d, dict)
                and d.get("lang") == "en"
                and isinstance(d.get("value"), str)
            ):
                description_en = d["value"]
                break

    # Dates
    now_date_str = datetime.now().strftime("%Y-%m-%d")
    published_date_full = cve.get("published")
    last_updated_date_full = cve.get("lastModified")
    published_date = (
        published_date_full[:10] if published_date_full else now_date_str
    )
    last_updated_date = (
        last_updated_date_full[:10] if last_updated_date_full else now_date_str
    )

    # CWEs
    cwe_ids_list = []
    weaknesses = cve.get("weaknesses", []) or []
    if isinstance(weaknesses, list):
        for w_entry in weaknesses:
            if isinstance(w_entry, dict):
                w_descs = w_entry.get("description", []) or []
                if isinstance(w_descs, list):
                    for d_entry in w_descs:
                        if isinstance(d_entry, dict) and d_entry.get("lang") == "en":
                            val = d_entry.get("value")
                            if isinstance(val, str) and val.strip().startswith("CWE-"):
                                cwe_ids_list.append(val.strip())
    cweIDs_payload = sorted(list(set(cwe_ids_list))) if cwe_ids_list else ["N/A"]

    # CVSS Score
    nist_base_score = 0.0
    metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics"), dict) else {}
    priority = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    for f_name in priority:
        m_list = metrics.get(f_name, []) or []
        if isinstance(m_list, list) and m_list:
            p_metric = next(
                (m for m in m_list if isinstance(m, dict) and m.get("type") == "Primary"),
                m_list[0],
            )
            if isinstance(p_metric, dict):
                cvss_d = (
                    p_metric.get("cvssData", {})
                    if isinstance(p_metric.get("cvssData"), dict)
                    else {}
                )
                s = cvss_d.get("baseScore")
                if isinstance(s, (float, int)):
                    nist_base_score = float(s)
                    break
            elif isinstance(p_metric, dict) and f_name == "cvssMetricV2":
                s = p_metric.get("baseScore")
                if isinstance(s, (float, int)):
                    nist_base_score = float(s)
                    break
        if nist_base_score > 0.0:
            break

    # Tags
    raw_tags = cve.get("cveTags", []) or []
    tags_l = []
    if isinstance(raw_tags, list):
        for t_item in raw_tags:
            if isinstance(t_item, str) and t_item.strip():
                tags_l.append(t_item.strip())
            elif (
                isinstance(t_item, dict)
                and "value" in t_item
                and isinstance(t_item["value"], str)
                and t_item["value"].strip()
            ):
                tags_l.append(t_item["value"].strip())
    tags_payload = sorted(list(set(tags_l))) if tags_l else ["Auto-Generated"]

    # Build the payload
    payload = {
        "cveID": cveID,
        "name": f"Vulnerability {cveID}" if cveID else "Unknown Vulnerability",
        "description": description_en,
        "mitigation": "No mitigation available.",
        "last_updated_date": last_updated_date,
        "published_date": published_date,
        "nist_base_score": nist_base_score,
        "cweIDs": cweIDs_payload,
        "tags": tags_payload,
        "affected_systems": ["Unknown"],
        # Serialize raw_data to ensure it's JSON-compatible (handles Decimals, etc.)
        "raw_data": json.loads(json.dumps(vuln_source_data, default=str)),
    }

    if existing_vulnID:
        payload["vulnID"] = existing_vulnID

    return payload