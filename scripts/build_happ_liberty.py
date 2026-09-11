"""Build a complete Happ feed from the refreshed Liberty catalog."""

import copy
import datetime
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "whitelist_configs_combined.json"
OUTPUT = ROOT / "subscription_happ_liberty.txt"
REPORT = ROOT / "happ_liberty_report.json"
MEASUREMENTS = ROOT / "happ_liberty_measurements.json"

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
RUSSIA_DIRECT_DOMAINS = [
    "domain:ru", "domain:su", "domain:xn--p1ai", "geosite:category-ru",
    "regexp:.*\\.ru$", "regexp:.*\\.su$", "regexp:.*\\.xn--p1ai$",
]
RUSSIA_DIRECT_IPS = ["geoip:ru"]


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


def ensure_russia_direct(config):
    rules = config.setdefault("routing", {}).setdefault("rules", [])
    if not any(item.get("tag") == "direct" for item in config.get("outbounds", [])):
        raise RuntimeError(f"{config.get('remarks')}: direct outbound is missing")
    # Insert after Telegram/Instagram proxy rules and before upstream rules.
    rules[2:2] = [
        {"type": "field", "domain": RUSSIA_DIRECT_DOMAINS, "outboundTag": "direct"},
        {"type": "field", "ip": RUSSIA_DIRECT_IPS, "outboundTag": "direct"},
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


def build(catalog, measurements):
    by_index = {item["source_index"]: item for item in measurements.get("results", [])}
    individuals = [
        (source_index, copy.deepcopy(item))
        for source_index, item in enumerate(catalog)
        if not item.get("remarks", "").startswith("🇪🇺 🚀Авто")
        and "Россия" not in item.get("remarks", "")
        and "Russia" not in item.get("remarks", "")
        and "🇷🇺" not in item.get("remarks", "")
    ]
    individuals.sort(key=lambda pair: (
        0 if by_index.get(pair[0], {}).get("status") == "ok" else 1,
        -by_index.get(pair[0], {}).get("speed_mbps", 0),
        pair[0],
    ))
    profiles = []
    for index, (source_index, item) in enumerate(individuals, start=1):
        original = item.get("remarks", "Без имени")
        metric = by_index.get(source_index, {})
        result = f"≈{metric['speed_mbps']:.2f} Мбит/с" if metric.get("status") == "ok" else "нет замера"
        item["remarks"] = f"{index:02d} | {result} | {original} | {connection_label(item)}"
        force_apps_through_proxy(item)
        ensure_russia_direct(item)
        profiles.append(item)
    return profiles


def main():
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    measurements = json.loads(MEASUREMENTS.read_text(encoding="utf-8")) if MEASUREMENTS.exists() else {"results": []}
    profiles = build(catalog, measurements)
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
                "excluded": ["upstream auto profile", "Russian VPN exit profiles"],
                "sort": "successful profiles by measured Mbps descending; unavailable profiles last",
                "measurements_at": measurements.get("measured_at"),
                "measurement_vantage": measurements.get("vantage"),
                "forced_proxy_domains": FORCE_PROXY_DOMAINS,
                "forced_proxy_ips": FORCE_PROXY_IPS,
                "russia_direct_domains": RUSSIA_DIRECT_DOMAINS,
                "russia_direct_ips": RUSSIA_DIRECT_IPS,
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
