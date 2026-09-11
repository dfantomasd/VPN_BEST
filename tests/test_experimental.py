import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).resolve().parents[1]/'scripts/experimental.py'
s=importlib.util.spec_from_file_location('experimental',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class ExperimentalTests(unittest.TestCase):
    uri='vless://00000000-0000-4000-8000-000000000001@example.com:443?security=reality&type=tcp&pbk=test&sni=example.org'
    def test_preserves_connection(self):
        o=m.parse(self.uri);self.assertEqual(o['streamSettings']['realitySettings']['serverName'],'example.org');self.assertEqual(o['settings']['vnext'][0]['port'],443)
    def test_rejects_lossy_conversion(self):
        for suffix in ['&extra=abc','&allowInsecure=1','&encryption=other','&type=ws']:
            with self.assertRaises(ValueError):m.parse(self.uri+suffix)
    def test_all_traffic_uses_proxy(self):
        c=m.config(m.parse(self.uri));self.assertEqual(c['routing']['rules'],[{'type':'field','network':'tcp,udp','outboundTag':'proxy'}])

    def test_export_has_local_socks_listener(self):
        c=m.config(m.parse(self.uri));self.assertEqual(c["inbounds"][0]["protocol"],"socks");self.assertEqual(c["inbounds"][0]["listen"],"127.0.0.1");self.assertEqual(c["inbounds"][0]["port"],10808)
