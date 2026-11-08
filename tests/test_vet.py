import unittest

from jarvis_origin import vet


class SharedInfrastructureTests(unittest.TestCase):
    def test_vendor_service_domains_are_not_attacker_indicators(self):
        for domain in (
            "chatgpt.com",
            "ab.chatgpt.com",
            "assets.claude.ai",
            "cloudflare-dns.com",
            "canary.netmon.azure.com",
        ):
            with self.subTest(domain=domain):
                self.assertIsNone(vet.vet_domain(domain)[0])

    def test_cloudflare_anycast_address_is_not_tenant_specific(self):
        value, reason = vet.vet_ipv4("188.114.97.3")

        self.assertIsNone(value)
        self.assertIn("Cloudflare", reason)

    def test_unrelated_public_address_remains_eligible(self):
        value, reason = vet.vet_ipv4("45.67.89.10")

        self.assertEqual(value, "45.67.89.10")
        self.assertEqual(reason, "")


if __name__ == "__main__":
    unittest.main()
