"""Run with python3 -m unittest discover -s ... -p test_exchange_discover.py."""
import unittest
from exchange_discover import parse, secure_url, domain, related, choose_oab, valid_oab_manifest

class ExchangeDiscoveryTests(unittest.TestCase):
    def test_external_first(self):
        xml = b"""<Autodiscover xmlns="urn:test"><Response><Account><Action>settings</Action>
        <Protocol><Type>EXCH</Type><EwsUrl>https://internal.example.test/EWS/Exchange.asmx</EwsUrl></Protocol>
        <Protocol><Type>EXPR</Type><EwsUrl>https://mail.example.test/EWS/Exchange.asmx</EwsUrl>
        <OABUrl>https://mail.example.test/OAB/123/</OABUrl></Protocol></Account></Response></Autodiscover>"""
        result = parse(xml)
        self.assertEqual(result["ews"], "https://mail.example.test/EWS/Exchange.asmx")
        self.assertEqual(result["oab"], "https://mail.example.test/OAB/123/oab.xml")
    def test_external_oab_503_falls_back_to_external_ews_guid_path(self):
        xml = b"""<Autodiscover><Response><Account><Action>settings</Action>
        <Protocol><Type>EXCH</Type><EwsUrl>https://internal.example.test/EWS/Exchange.asmx</EwsUrl>
        <OABUrl>https://internal.example.test/OAB/12345678-1234-1234-1234-123456789abc/</OABUrl></Protocol>
        <Protocol><Type>EXPR</Type><EwsUrl>https://ex2.example.test/EWS/Exchange.asmx</EwsUrl>
        <OABUrl>https://ex1.example.test/OAB/</OABUrl></Protocol></Account></Response></Autodiscover>"""
        result = parse(xml)
        expected = "https://ex2.example.test/OAB/12345678-1234-1234-1234-123456789abc/oab.xml"
        self.assertEqual(result["oab"], "https://ex1.example.test/OAB/oab.xml")
        self.assertIn(expected, result["oab_candidates"])
        attempted = []
        def probe(url):
            attempted.append(url)
            return "ok" if url == expected else "unavailable"
        self.assertEqual(choose_oab(result["oab_candidates"], lambda u: True, probe), (expected, True))
        self.assertEqual(attempted, [result["oab"], expected])
        self.assertEqual(choose_oab(result["oab_candidates"], lambda u: False, probe), (None, False))
    def test_oab_manifest_is_not_just_http_200(self):
        self.assertFalse(valid_oab_manifest(b"<html>login page</html>"))
        self.assertTrue(valid_oab_manifest(b'<OAB><OAL><Full size="123" SHA="abcd">full.lzx</Full></OAL></OAB>'))
    def test_redirects(self):
        self.assertEqual(parse(b"<Autodiscover><Response><Account><Action>redirectAddr</Action><RedirectAddr>a@other.test</RedirectAddr></Account></Response></Autodiscover>")["address"], "a@other.test")
        self.assertEqual(parse(b"<Autodiscover><Response><Account><Action>redirectUrl</Action><RedirectUrl>https://other.test/autodiscover/autodiscover.xml</RedirectUrl></Account></Response></Autodiscover>")["status"], "redirect_url")
    def test_security(self):
        self.assertIsNone(secure_url("http://example.test/EWS/Exchange.asmx"))
        self.assertIsNone(secure_url("https://user:secret@example.test/EWS/Exchange.asmx"))
        self.assertFalse(related("evil-example.test", "example.test"))
        self.assertIsNone(domain("a@foo..test"))
        self.assertIsNone(parse(b"<!DOCTYPE a><a/>"))
    def test_cloud(self):
        self.assertEqual(parse(b"<Autodiscover><Response><Account><MicrosoftOnline>true</MicrosoftOnline></Account></Response></Autodiscover>")["status"], "cloud")
if __name__ == "__main__":
    unittest.main()
