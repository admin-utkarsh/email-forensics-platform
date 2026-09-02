"""
header_analysis.py
Parses raw email headers, reconstructs the SMTP relay chain, extracts
originating IPs, and validates SPF/DKIM/DMARC alignment.

This works on real RFC 5322 headers -- no mock data. Feed it a real .eml
file and it will trace the actual Received: chain.
"""
import re
from email import message_from_string, message_from_bytes
from email.utils import parseaddr, getaddresses
from typing import List, Dict, Optional

IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')
# Require at least 4 groups (3+ colons) so we don't false-match timestamps
# like "10:14:15" as IPv6 addresses.
IPV6_RE = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}\b')

# Private/reserved ranges we should not treat as "the attacker's IP"
PRIVATE_PREFIXES = ('10.', '127.', '192.168.', '169.254.')
def _is_private_ip(ip: str) -> bool:
    if ip.startswith(PRIVATE_PREFIXES):
        return True
    if ip.startswith('172.'):
        try:
            second = int(ip.split('.')[1])
            if 16 <= second <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return False


def parse_email(raw: bytes) -> Dict:
    """Parse raw email bytes/string into a structured dict of headers + body."""
    try:
        msg = message_from_bytes(raw)
    except TypeError:
        msg = message_from_string(raw)

    headers = {k: v for k, v in msg.items()}

    # Extract plain-text body (first text/plain part, or full payload)
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    pass
        if not body:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        html = part.get_payload(decode=True).decode(errors="ignore")
                        body += re.sub('<[^<]+?>', ' ', html)
                    except Exception:
                        pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            body = payload.decode(errors="ignore") if payload else str(msg.get_payload())
        except Exception:
            body = str(msg.get_payload())

    return {
        "headers": headers,
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "date": msg.get("Date", ""),
        "received": msg.get_all("Received", []) or [],
        "auth_results": msg.get_all("Authentication-Results", []) or [],
        "body": body[:5000],  # cap for downstream NLP
        "attachments": _list_attachments(msg),
        "urls": _extract_urls(body),
    }


def _list_attachments(msg) -> List[Dict]:
    out = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                out.append({
                    "filename": part.get_filename() or "unnamed",
                    "content_type": part.get_content_type(),
                })
    return out


def _extract_urls(text: str) -> List[str]:
    url_re = re.compile(r'https?://[^\s<>"\')\]]+')
    return list(dict.fromkeys(url_re.findall(text or "")))[:25]


def extract_relay_chain(received_headers: List[str]) -> List[Dict]:
    """
    Received headers are prepended by each hop, so the LAST one in the list
    is the earliest/closest to the true origin. We parse each hop for the
    'from <host> (...)' and any embedded IP, in reverse (origin-first) order.
    """
    chain = []
    for idx, hop in enumerate(reversed(received_headers)):
        ips_v4 = IPV4_RE.findall(hop)
        ips_v6 = IPV6_RE.findall(hop)
        candidate_ip = None
        for ip in ips_v4:
            if not _is_private_ip(ip):
                candidate_ip = ip
                break
        if not candidate_ip and ips_v6:
            candidate_ip = ips_v6[0]

        from_match = re.search(r'from\s+([^\s\(\)]+)', hop)
        by_match = re.search(r'by\s+([^\s\(\)]+)', hop)
        ts_match = re.search(r';\s*(.+)$', hop.strip())

        chain.append({
            "hop": idx + 1,
            "from_host": from_match.group(1) if from_match else None,
            "by_host": by_match.group(1) if by_match else None,
            "ip": candidate_ip,
            "all_ips_seen": ips_v4,
            "timestamp": ts_match.group(1).strip() if ts_match else None,
            "raw": hop.strip(),
        })
    return chain


def probable_origin_ip(chain: List[Dict]) -> Optional[str]:
    """Earliest hop with a public IP is our best guess at true origin."""
    for hop in chain:
        if hop["ip"]:
            return hop["ip"]
    return None


def parse_auth_results(auth_headers: List[str]) -> Dict:
    """Extract SPF / DKIM / DMARC verdicts from Authentication-Results headers."""
    joined = " ".join(auth_headers)
    result = {"spf": "none", "dkim": "none", "dmarc": "none", "raw": joined}
    spf_m = re.search(r'spf=(\w+)', joined, re.I)
    dkim_m = re.search(r'dkim=(\w+)', joined, re.I)
    dmarc_m = re.search(r'dmarc=(\w+)', joined, re.I)
    if spf_m:
        result["spf"] = spf_m.group(1).lower()
    if dkim_m:
        result["dkim"] = dkim_m.group(1).lower()
    if dmarc_m:
        result["dmarc"] = dmarc_m.group(1).lower()
    return result


def check_alignment(parsed: Dict) -> Dict:
    """Compare From:, Return-Path:, and Reply-To: domains for mismatches --
    a classic spoofing / BEC indicator."""
    from_addr = parseaddr(parsed.get("from", ""))[1]
    return_path = parseaddr(parsed.get("return_path", ""))[1]
    reply_to = parseaddr(parsed.get("reply_to", ""))[1]

    def domain(addr):
        return addr.split("@")[-1].lower() if addr and "@" in addr else None

    from_dom, rp_dom, rt_dom = domain(from_addr), domain(return_path), domain(reply_to)

    issues = []
    if rp_dom and from_dom and rp_dom != from_dom:
        issues.append(f"Return-Path domain ({rp_dom}) differs from From domain ({from_dom})")
    if rt_dom and from_dom and rt_dom != from_dom:
        issues.append(f"Reply-To domain ({rt_dom}) differs from From domain ({from_dom}) -- replies route elsewhere")

    return {
        "from_domain": from_dom,
        "return_path_domain": rp_dom,
        "reply_to_domain": rt_dom,
        "mismatches": issues,
    }
