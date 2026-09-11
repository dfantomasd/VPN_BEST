import unittest

from scripts import build_happ_liberty as liberty


class HappLibertyTests(unittest.TestCase):
    def test_forced_apps_precede_existing_rules(self):
        config = {
            "remarks": "Test",
            "outbounds": [{"tag": "proxy", "protocol": "vless"}],
            "routing": {"rules": [{"type": "field", "outboundTag": "direct", "domain": ["domain:ru"]}]},
        }
        liberty.force_apps_through_proxy(config)
        self.assertEqual(config["routing"]["rules"][0]["outboundTag"], "proxy")
        self.assertIn("domain:telegram.org", config["routing"]["rules"][0]["domain"])
        self.assertIn("149.154.160.0/20", config["routing"]["rules"][1]["ip"])

    def test_balanced_profile_uses_balancer(self):
        config = {
            "remarks": "Test",
            "outbounds": [{"tag": "node", "protocol": "vless"}],
            "routing": {"balancers": [{"tag": "auto"}], "rules": []},
        }
        liberty.force_apps_through_proxy(config)
        self.assertEqual(config["routing"]["rules"][0]["balancerTag"], "auto")

    def test_russia_routes_after_forced_apps(self):
        config = {
            "remarks": "Test",
            "outbounds": [
                {"tag": "proxy", "protocol": "vless"},
                {"tag": "direct", "protocol": "freedom"},
            ],
            "routing": {"rules": []},
        }
        liberty.force_apps_through_proxy(config)
        liberty.ensure_russia_direct(config)
        rules = config["routing"]["rules"]
        self.assertIn("domain:telegram.org", rules[0]["domain"])
        self.assertIn("domain:ru", rules[2]["domain"])
        self.assertEqual(rules[3]["ip"], ["geoip:ru"])
