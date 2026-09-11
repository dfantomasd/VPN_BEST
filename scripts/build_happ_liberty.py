"""Build a complete Happ feed from the refreshed Liberty catalog."""

import copy
import datetime
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "whitelist_configs_combined.json"
OUTPUT = ROOT / "subscription_happ_liberty.txt"
REPORT = ROOT / "happ_liberty_report.json"

FORCE_PROXY_DOMAINS = [
    "domain:telegram.org",
    "domain:t.me",
    "domain:telegram.me",
    "domain:telegram.dog",
    "domain:telegra.ph",
    "domain:instagram.com",
    "domain:cdninstagram.com",
    "domain:fbcdn.net",
]
FORCE_PROXY_IPS = ["91.108.0.0/16", "149.154.160.0/20"]


def proxy_target(config):
    balancers = config.get("routing", {}).get("balancers", [])
    if balancers:
        return {"balancerTag": balancers[0]["tag"]}
    candidates = [
        item.get("tag")
        for item in config.get("outbounds", [])
        if item.get("protocol") not in {"freedom", "blackhole", "dns"}
    ]
    if not candidates:
        raise RuntimeError(f"{config.get('remarks')}: proxy outbound is missing")
    return {"outboundTag": candidates[0]}


def force_apps_through_proxy(config):
    rules = config.setdefault("routing", {}).setdefault("rules", [])
    target = proxy_target(config)
    rules[0:0] = [
        {"type": "field", "domain": FORCE_PROXY_DOMAINS, **target},
        {"type": "field", "ip": FORCE_PROXY_IPS, **target},
    ]


def profile_class(config):
    name = config.get("remarks", "")
    outbounds = [
        item
        for item in config.get("outbounds", [])
        if item.get("protocol") not in {"freedom", "blackhole", "dns"}
    ]
    if "Россия" in name or "Russia" in name or "🇷🇺" in name:
        return 5
    if len(outbounds) > 1 or config.get("routing", {}).get("balancers"):
        return 4
    protocol = outbounds[0].get("protocol") if outbounds else ""
    network = outbounds[0].get("streamSettings", {}).get("network", "tcp") if outbounds else ""
    if protocol == "vless" and network == "tcp":
        return 0
    if protocol == "vless":
        return 1
    if protocol == "hysteria":
        return 3
    return 2


def connection_label(config):
    outbounds = [
        item
        for item in config.get("outbounds", [])
        if item.get("protocol") not in {"freedom", "blackhole", "dns"}
    ]
    if len(outbounds) != 1:
        return "СОСТАВНОЙ"
    item = outbounds[0]
    return (
        str(item.get("protocol", "proxy")).upper()
        + " · "
        + str(item.get("streamSettings", {}).get("network", "tcp")).upper()
    )


def build(catalog):
    individuals = [
        copy.deepcopy(item)
        for item in catalog
        if not item.get("remarks", "").startswith("🇪🇺 🚀Авто")
    ]
    individuals.sort(
        key=lambda item: (
            0 if item.get("remarks") == "🇩🇪⚡Германия" else 1,
            profile_class(item),
            catalog.index(next(source for source in catalog if source.get("remarks") == item.get("remarks"))),
        )
    )
    for index, item in enumerate(individuals, start=1):
        original = item.get("remarks", "Без имени")
        status = "✅ LTE" if original == "🇩🇪⚡Германия" else "◻️"
        item["remarks"] = f"{index:02d} {status} | {original} | {connection_label(item)}"
        force_apps_through_proxy(item)
    return individuals


def main():
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    profiles = build(catalog)
    if len(profiles) < 20:
        raise RuntimeError(f"Refusing unexpectedly small Liberty feed: {len(profiles)}")
    OUTPUT.write_text(json.dumps(profiles, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    REPORT.write_text(
        json.dumps(
            {
                "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source": "owner-configured Liberty catalog",
                "source_profiles": len(catalog),
                "published_profiles": len(profiles),
                "excluded": ["upstream auto profile"],
                "sort": [
                    "Germany confirmed by owner in Happ on LTE",
                    "single VLESS TCP profiles",
                    "other single VLESS profiles",
                    "other protocols",
                    "Hysteria",
                    "composite whitelist profiles",
                    "Russian profiles",
                ],
                "forced_proxy_domains": FORCE_PROXY_DOMAINS,
                "forced_proxy_ips": FORCE_PROXY_IPS,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"published_profiles={len(profiles)}")


if __name__ == "__main__":
    main()
