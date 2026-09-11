"""Mirror an upstream Happ-native auto-select profile without rewriting nodes."""

import copy
import datetime
import json
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "subscription_happ_free.txt"
REPORT = ROOT / "happ_free_report.json"
SOURCE = (
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
    "Export/Happ/GLOBAL/BLACK_SS%2BAll_RUS_Happ_global.json"
)


def main():
    request = urllib.request.Request(
        SOURCE,
        headers={"User-Agent": "VPN_BEST Happ mirror", "Cache-Control": "no-cache"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read()

    document = json.loads(payload.decode("utf-8-sig"))
    required = {"_meta", "inbounds", "outbounds", "observatory", "routing"}
    if not required <= set(document):
        raise RuntimeError("Upstream Happ document is missing required sections")
    if document["_meta"].get("client") != "Happ":
        raise RuntimeError("Upstream document is not marked for Happ")

    selectors = document["observatory"].get("subjectSelector", [])
    proxy_nodes = [
        item
        for item in document["outbounds"]
        if any(str(item.get("tag", "")).startswith(prefix) for prefix in selectors)
    ]
    if len(proxy_nodes) < 10:
        raise RuntimeError(f"Refusing unexpectedly small profile: {len(proxy_nodes)} proxies")
    if not document["routing"].get("balancers"):
        raise RuntimeError("Happ auto-select balancer is missing")

    profiles = []
    primary = json.loads((ROOT / "subscription.txt").read_text(encoding="utf-8"))
    germany = next(
        (item for item in primary if "Германия" in item.get("remarks", "")), None
    )
    if germany is None:
        raise RuntimeError("Known working Germany profile is missing from primary subscription")
    germany = copy.deepcopy(germany)
    germany["remarks"] = "✅ Германия | подтверждена в Happ на LTE"
    profiles.append(germany)

    support_outbounds = [
        item
        for item in document["outbounds"]
        if item.get("tag") in {"direct", "block", "dns-out"}
    ]
    for index, node in enumerate(proxy_nodes, start=1):
        profile = copy.deepcopy(document)
        profile.pop("_meta", None)
        profile.pop("observatory", None)
        selected = copy.deepcopy(node)
        selected["tag"] = "proxy"
        profile["outbounds"] = [selected] + copy.deepcopy(support_outbounds)
        profile["routing"].pop("balancers", None)
        for rule in profile["routing"].get("rules", []):
            if "balancerTag" in rule:
                rule.pop("balancerTag")
                rule["outboundTag"] = "proxy"
        protocol = str(node.get("protocol", "proxy")).upper()
        profile["remarks"] = f"FREE {index:02d} | {protocol}"
        profiles.append(profile)

    # Expose every server as a normal Happ row. This also avoids relying on an
    # upstream observatory that may select a node unable to reach Telegram.
    OUTPUT.write_text(
        json.dumps(profiles, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    REPORT.write_text(
        json.dumps(
            {
                "mirrored_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source": SOURCE,
                "source_name": document["_meta"].get("name"),
                "source_datetime": document["_meta"].get("source_datetime"),
                "proxies": len(proxy_nodes),
                "profiles": len(profiles),
                "first_profile": germany["remarks"],
                "probe_url": document["observatory"].get("probeURL"),
                "probe_interval": document["observatory"].get("probeInterval"),
                "format": "Individual Happ JSON profiles; upstream connection settings are preserved",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"published {len(profiles)} Happ profiles")


if __name__ == "__main__":
    main()
