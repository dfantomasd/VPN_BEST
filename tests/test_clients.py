import base64
import copy
import ipaddress
import json
import re
import unittest
import urllib.parse

from scripts import build_clients as clients


def parse_generated_yaml(text):
    # Generator writes YAML block lists with JSON flow values. Independent
    # format validation is also performed with Ruby Psych / Mihomo locally.
    result = {}
    key = None
    for line in text.splitlines():
        if line.startswith('  - '):
            result[key].append(json.loads(line[4:]))
        else:
            key, value = line.split(':', 1)
            result[key] = json.loads(value) if value.strip() else []
    return result


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outputs = clients.build()
        cls.catalog = clients.read_json(clients.ROOT / 'whitelist_configs_combined.json')
        cls.policy = json.loads(cls.outputs['routing_russia.json'])
        cls.karing = parse_generated_yaml(cls.outputs['subscription_karing.txt'])

    def test_artifacts_current(self):
        for name, expected in self.outputs.items():
            self.assertEqual((clients.ROOT / name).read_text(encoding='utf-8'), expected)

    def test_happ_russia_enabled(self):
        lines = self.outputs['subscription.txt'].splitlines()
        routing = [line for line in lines if line.startswith('happ://routing/onadd/')]
        self.assertEqual(len(routing), 1)
        decoded = json.loads(base64.b64decode(routing[0].split('/onadd/')[1], validate=True))
        self.assertEqual(decoded, self.policy)
        self.assertEqual(decoded['Name'], 'Russia')
        self.assertEqual(decoded['GlobalProxy'], 'true')
        self.assertIn('geosite:category-ru', decoded['DirectSites'])
        self.assertIn('geoip:ru', decoded['DirectIp'])
        self.assertNotIn('happ://routing/off', self.outputs['subscription.txt'])
        self.assertIn('#subscription-ping-onopen-enabled: 0', lines)
        self.assertIn('#subscriptions-sort-type: ping', lines)
        self.assertIn('#profile-update-interval: 1', lines)

    def test_happ_credentials_preserved(self):
        exported = [line for line in self.outputs['subscription.txt'].splitlines()
                    if line.startswith(('vless://', 'hysteria2://'))]
        selected, _ = clients.foreign_nodes(self.catalog)
        selected = clients.ranked_nodes(selected)
        self.assertEqual(len(exported), len(selected))
        for (name, outbound), link in zip(selected, exported):
            url = urllib.parse.urlsplit(link)
            query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
            self.assertEqual(urllib.parse.unquote(url.fragment), name)
            if outbound['protocol'] == 'vless':
                peer = outbound['settings']['vnext'][0]
                self.assertEqual(url.hostname, peer['address'])
                self.assertEqual(url.port, peer['port'])
                self.assertEqual(url.username, peer['users'][0]['id'])
                stream = outbound['streamSettings']
                if stream['network'] == 'xhttp':
                    self.assertEqual(query['mode'][0], stream['xhttpSettings']['mode'])
                    self.assertEqual(json.loads(query['extra'][0]), stream['xhttpSettings']['extra'])

    def test_karing_groups_and_default(self):
        self.assertEqual(self.karing['mode'], 'rule')
        self.assertEqual(self.karing['rules'][-1], 'MATCH,VPN_BEST')
        names = [p['name'] for p in self.karing['proxies']]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(self.karing['proxy-groups'][0]['proxies'][1:]), set(names))
        self.assertEqual(self.karing['proxy-groups'][1]['type'], 'url-test')
        self.assertEqual(set(self.karing['proxy-groups'][1]['proxies']), set(names))
        self.assertNotIn('DIRECT', self.karing['proxy-groups'][0]['proxies'])
        self.assertNotIn('dns', self.karing)  # Karing ignores subscription DNS

    def test_domain_routes(self):
        def karing_route(domain):
            for line in self.karing['rules']:
                parts = line.split(',')
                if parts[0] == 'DOMAIN' and domain == parts[1]:
                    return parts[2]
                if parts[0] == 'DOMAIN-SUFFIX' and (domain == parts[1] or domain.endswith('.' + parts[1])):
                    return parts[2]
            return 'VPN_BEST'
        for domain in ('sberbank.ru', 'online.sberbank.ru', 'tbank.ru', 'vtb.com',
                       'alfabank.ru', 'gosuslugi.ru', 'mos.ru', 'nspk.ru', 'ya.ru',
                       'ozon.ru', 'example.su', 'example.xn--p1ai'):
            with self.subTest(domain=domain):
                self.assertEqual(karing_route(domain), 'DIRECT')
        for domain in ('youtube.com', 'googlevideo.com', 'openai.com', 'github.com',
                       'ipinfo.io', 'ifconfig.me', 'browserleaks.com', 'steampowered.com',
                       'sberbank.ru.attacker.example'):
            with self.subTest(domain=domain):
                self.assertEqual(karing_route(domain), 'VPN_BEST')

    def test_geodata_coverage(self):
        rules = set(self.karing['rules'])
        geo = clients.read_json(clients.ROOT / 'rules/category-ru.json')
        for group in geo['rules']:
            for domain in group.get('domain', []):
                if domain not in clients.REMOVE_DIRECT:
                    self.assertIn('DOMAIN,' + domain + ',DIRECT', rules)
            for suffix in group.get('domain_suffix', []):
                suffix = suffix.lstrip('.')
                if suffix not in clients.REMOVE_DIRECT:
                    self.assertIn('DOMAIN-SUFFIX,' + suffix + ',DIRECT', rules)
        for group in clients.read_json(clients.ROOT / 'rules/geoip-ru.json')['rules']:
            for cidr in group['ip_cidr']:
                kind = 'IP-CIDR6' if ipaddress.ip_network(cidr).version == 6 else 'IP-CIDR'
                self.assertIn(kind + ',' + cidr + ',DIRECT', rules)

    def test_no_legacy_foreign_direct_rules(self):
        for domain in clients.REMOVE_DIRECT:
            self.assertNotIn('domain:' + domain, self.policy['DirectSites'])
        for expression in self.policy['DirectSites']:
            if expression.startswith('regexp:'):
                re.compile(expression[7:])

    def test_chains_fail_closed(self):
        name, outbound = clients.nodes(self.catalog)[0]
        outbound = copy.deepcopy(outbound)
        outbound['proxySettings'] = {'tag': 'another'}
        with self.assertRaises(ValueError):
            clients.connection(name, outbound)

    def test_no_tls_verification_disabled(self):
        for proxy in self.karing['proxies']:
            self.assertFalse(proxy.get('skip-cert-verify', False))
        for line in self.outputs['subscription.txt'].splitlines():
            self.assertNotIn('insecure=1', line)

    def test_no_russian_servers(self):
        selected, excluded = clients.foreign_nodes(self.catalog)
        self.assertTrue(any('Россия' in node['name'] for node in excluded))
        self.assertTrue(any('GeoIP RU' in node['reason'] for node in excluded))
        self.assertTrue(any('RDAP RU' in node['reason'] for node in excluded))
        for name, _ in selected:
            self.assertNotIn('Россия', name)
            self.assertNotIn('🇷🇺', name)
        denied_hosts = {entry['server'] for entry in excluded}
        for proxy in self.karing['proxies']:
            self.assertNotIn(proxy['server'], denied_hosts)
        for line in self.outputs['subscription.txt'].splitlines():
            if line.startswith(('vless://', 'hysteria2://')):
                self.assertNotIn(urllib.parse.urlsplit(line).hostname, denied_hosts)

    def test_subscriptions_vless_only(self):
        links = [line for line in self.outputs['subscription.txt'].splitlines()
                 if line and not line.startswith(('#', 'happ://routing/'))]
        self.assertTrue(links)
        self.assertTrue(all(link.startswith('vless://') for link in links))
        self.assertTrue(all(proxy['type'] == 'vless' for proxy in self.karing['proxies']))

    def test_non_vless_filtered_before_conversion(self):
        vless = {'protocol': 'vless', 'tag': 'proxy'}
        catalog = [{'remarks': 'mixed', 'outbounds': [vless, {'protocol': 'hysteria'},
                    {'protocol': 'trojan'}, {'protocol': 'vmess'}, {'protocol': 'shadowsocks'}]}]
        self.assertEqual(clients.nodes(catalog), [('mixed', vless)])


if __name__ == '__main__':
    unittest.main()
