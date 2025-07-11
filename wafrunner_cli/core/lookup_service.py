import re
from wafrunner_cli.core.database import Database

# Regex for CVE ID format (e.g., CVE-2024-12345)
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# Regex for UUID format (e.g., a1ddadd4-1b9d-4fab-90fe-64c1c763cd58)
VULN_ID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def get_vuln_id(cve_id: str) -> str | None:
    """Gets the vulnID for a given CVE ID."""
    if not CVE_REGEX.match(cve_id):
        return None
    db = Database()
    db.cursor.execute(
        "SELECT vuln_id FROM cve_lookup WHERE cve_id = ?", (cve_id.upper(),)
    )
    result = db.cursor.fetchone()
    db.close()
    return result[0] if result else None


def get_cve_id(vuln_id: str) -> str | None:
    """Gets the CVE ID for a given vulnID."""
    if not VULN_ID_REGEX.match(vuln_id):
        return None
    db = Database()
    db.cursor.execute("SELECT cve_id FROM cve_lookup WHERE vuln_id = ?", (vuln_id,))
    result = db.cursor.fetchone()
    db.close()
    return result[0] if result else None


def lookup_ids(identifier: str) -> dict[str, str] | None:
    """
    Looks up both CVE ID and vulnID from either a CVE ID or a vulnID.

    Args:
        identifier: The CVE ID or vulnID to look up.

    Returns:
        A dictionary with 'cve_id' and 'vuln_id' keys, or None if not found.
    """
    if CVE_REGEX.match(identifier):
        cve_id = identifier.upper()
        vuln_id = get_vuln_id(cve_id)
        if vuln_id:
            return {"cve_id": cve_id, "vuln_id": vuln_id}
    elif VULN_ID_REGEX.match(identifier):
        vuln_id = identifier
        cve_id = get_cve_id(vuln_id)
        if cve_id:
            return {"cve_id": cve_id, "vuln_id": vuln_id}

    return None
