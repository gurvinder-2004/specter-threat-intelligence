"""
IOC Relationship AI — Clustering Engine
Groups IOCs that likely belong to the same threat campaign.

Clustering signals:
- IP subnet proximity (/24 block → same hosting provider or C2 pool)
- Domain registrar/pattern similarity (same registrar, similar naming scheme)
- TTP overlap (IOCs sharing 3+ techniques likely share an operator)
- Source proximity (all from same threat intel pulse)
- Temporal correlation (seen within same time window)
"""
import re
import ipaddress
from collections import defaultdict
from loguru import logger
from llm.summarizer import _complete


def _ip_subnet(ip: str) -> str:
    """Extract /24 subnet."""
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return ""


def _domain_pattern(domain: str) -> str:
    """
    Extract structural pattern for clustering similar domains.
    'malicious-bank-login.xyz' → pattern: 'word-word-word.xyz'
    'c2-443-beacon.top' → pattern: 'word-num-word.top'
    """
    # Get TLD
    parts = domain.rsplit(".", 1)
    tld   = parts[-1] if len(parts) > 1 else ""
    name  = parts[0] if len(parts) > 1 else domain

    # Replace words with 'W' and numbers with 'N'
    pattern = re.sub(r"\d+", "N", name)
    pattern = re.sub(r"[a-zA-Z]+", "W", pattern)
    return f"{pattern}.{tld}"


def _ttp_set(ioc: dict) -> frozenset:
    return frozenset(ioc.get("ttp_tags", []) or [])


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


async def cluster_iocs(iocs: list[dict]) -> list[dict]:
    """
    Group IOCs into likely-related clusters.
    Returns list of cluster objects with AI-generated campaign description.
    """
    if not iocs:
        return []

    clusters: dict[str, list[dict]] = defaultdict(list)

    ip_iocs     = [i for i in iocs if i.get("ioc_type") == "ip"]
    domain_iocs = [i for i in iocs if i.get("ioc_type") == "domain"]
    hash_iocs   = [i for i in iocs if i.get("ioc_type") in ("sha256", "md5")]

    # ── IP clustering by /24 subnet ──────────────────────────────────────────
    for ioc in ip_iocs:
        subnet = _ip_subnet(ioc.get("value", ""))
        if subnet:
            clusters[f"subnet:{subnet}"].append(ioc)

    # ── Domain clustering by naming pattern ──────────────────────────────────
    domain_pattern_map: dict[str, list[dict]] = defaultdict(list)
    for ioc in domain_iocs:
        pat = _domain_pattern(ioc.get("value", ""))
        domain_pattern_map[pat].append(ioc)

    for pat, group in domain_pattern_map.items():
        if len(group) >= 2:
            clusters[f"domain_pattern:{pat}"].append(*group) if isinstance(clusters[f"domain_pattern:{pat}"], list) else None
            clusters[f"domain_pattern:{pat}"] = group

    # ── Hash clustering by TTP overlap ───────────────────────────────────────
    processed = set()
    for i, ioc_a in enumerate(hash_iocs):
        if i in processed:
            continue
        group = [ioc_a]
        ttps_a = _ttp_set(ioc_a)
        for j, ioc_b in enumerate(hash_iocs[i+1:], i+1):
            if j in processed:
                continue
            if _jaccard(ttps_a, _ttp_set(ioc_b)) >= 0.6:
                group.append(ioc_b)
                processed.add(j)
        if len(group) >= 2:
            cluster_key = f"ttp_cluster:{','.join(sorted(list(ttps_a))[:3])}"
            clusters[cluster_key] = group
        processed.add(i)

    # ── Source clustering (same threat intel pulse) ──────────────────────────
    source_map: dict[str, list[dict]] = defaultdict(list)
    for ioc in iocs:
        src = ioc.get("source", "")
        if src:
            source_map[src].append(ioc)
    for src, group in source_map.items():
        if len(group) >= 3:
            clusters[f"source:{src}"] = group

    # ── Filter: only keep clusters with >= 2 members ─────────────────────────
    meaningful = {k: v for k, v in clusters.items() if len(v) >= 2}

    if not meaningful:
        return []

    # ── Generate AI description per cluster ──────────────────────────────────
    result = []
    for cluster_key, members in list(meaningful.items())[:10]:  # max 10 clusters
        # Collect shared TTPs
        all_ttps = []
        for m in members:
            all_ttps.extend(m.get("ttp_tags", []) or [])
        ttp_counts = {}
        for t in all_ttps:
            ttp_counts[t] = ttp_counts.get(t, 0) + 1
        shared_ttps = [t for t, c in sorted(ttp_counts.items(), key=lambda x: -x[1]) if c >= 2][:5]

        ioc_list = ", ".join(m.get("value", "")[:30] for m in members[:5])
        avg_score = sum(m.get("confidence_score", 0) for m in members) / len(members)

        # Infer cluster type label
        if cluster_key.startswith("subnet:"):
            cluster_type = "IP Infrastructure Block"
            cluster_label = cluster_key.replace("subnet:", "")
        elif cluster_key.startswith("domain_pattern:"):
            cluster_type = "Domain Generation Pattern"
            cluster_label = cluster_key.replace("domain_pattern:", "")
        elif cluster_key.startswith("ttp_cluster:"):
            cluster_type = "Shared TTP Signature"
            cluster_label = "Matching TTPs: " + cluster_key.replace("ttp_cluster:", "")
        else:
            cluster_type = "Common Source"
            cluster_label = cluster_key.replace("source:", "")

        # AI campaign hypothesis
        ai_hypothesis = ""
        try:
            ai_hypothesis = await _complete(
                "You are a threat intel analyst. In 1 sentence, describe what campaign or "
                "threat actor group these IOCs likely belong to, based on the pattern. "
                "Be specific. No filler words.",
                f"Cluster type: {cluster_type}\n"
                f"IOCs: {ioc_list}\n"
                f"Shared TTPs: {', '.join(shared_ttps) or 'none'}\n"
                f"Average confidence: {avg_score:.0f}/100"
            )
        except Exception as e:
            logger.debug(f"Cluster AI failed: {e}")

        result.append({
            "cluster_id":   cluster_key,
            "cluster_type": cluster_type,
            "cluster_label": cluster_label,
            "member_count": len(members),
            "members":      [m.get("value", "") for m in members[:10]],
            "shared_ttps":  shared_ttps,
            "avg_score":    round(avg_score, 1),
            "ai_hypothesis": ai_hypothesis,
        })

    result.sort(key=lambda x: x["member_count"], reverse=True)
    logger.info(f"IOC clustering: {len(result)} clusters from {len(iocs)} IOCs")
    return result
