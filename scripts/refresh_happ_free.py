"""Mirror an upstream Happ-native auto-select profile without rewriting nodes."""

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

    # Happ subscription URLs expect a JSON array of full Xray profiles. The
    # upstream file is a single native profile; importing the bare object makes
    # Happ expose only its first outbound as "JSON 0".
    document["remarks"] = "⚡ DIMKA_FREE | Автовыбор"
    OUTPUT.write_text(
        json.dumps([document], ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    REPORT.write_text(
        json.dumps(
            {
                "mirrored_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source": SOURCE,
                "source_name": document["_meta"].get("name"),
                "source_datetime": document["_meta"].get("source_datetime"),
                "proxies": len(proxy_nodes),
                "probe_url": document["observatory"].get("probeURL"),
                "probe_interval": document["observatory"].get("probeInterval"),
                "format": "Upstream Happ-native JSON; connection settings are not rewritten",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"mirrored {len(proxy_nodes)} Happ proxies")


if __name__ == "__main__":
    main()
