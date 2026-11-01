"""Mutations reproducing stale-release and final-minute RSS blind spots."""
import unittest
from soak_checks import check_release, payload, resource_report


class SoakChecks(unittest.TestCase):
    host = "one.pathward.test"

    def headers(self, release):
        return {"x-robots-tag": f"release-{release}", "strict-transport-security": "max-age=60",
                "content-length": str(len(payload(self.host, release)))}

    def test_fresh_content_head_redirect_and_revocation(self):
        for release, live, revoked in (("A", "/a", "/b"), ("B", "/b", "/a")):
            h = self.headers(release)
            for target in ("/", live):
                check_release(200, h, payload(self.host, release), self.host, release, "GET", target)
                check_release(200, h, b"", self.host, release, "HEAD", target)
            check_release(404, h, b"", self.host, release, "GET", revoked)
            h["location"] = f"https://{self.host}{live}?q=%0d%0a"
            check_release(308, h, b"", self.host, release, "GET", "/legacy?q=%0d%0a")

    def test_old_response_after_acknowledgement_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "stale release header"):
            check_release(200, self.headers("A"), payload(self.host, "A"), self.host, "B", "GET", "/")
        with self.assertRaisesRegex(AssertionError, "stale or mixed"):
            check_release(200, self.headers("B"), payload(self.host, "A"), self.host, "B", "GET", "/")
        with self.assertRaisesRegex(AssertionError, "stale redirect"):
            check_release(308, dict(self.headers("B"), location=f"https://{self.host}/a"), b"", self.host, "B", "GET", "/legacy")

    def test_revoked_url_cannot_keep_serving_with_current_headers(self):
        with self.assertRaisesRegex(AssertionError, "revoked"):
            check_release(200, self.headers("B"), payload(self.host, "B"), self.host, "B", "GET", "/a")

    def test_final_minute_growth_fails_even_when_all_periodic_checks_pass(self):
        samples = [{"elapsed": t, "rss_kib": 6000 if t <= 3540 else 27000, "fds": 27, "threads": 12}
                   for t in range(0, 3600, 2)]
        for checkpoint in range(0, 3600, 60):
            intermediate = resource_report([s for s in samples if s["elapsed"] <= checkpoint])
            self.assertLessEqual(intermediate.get("rss_growth_kib", 0), 16384)
        with self.assertRaisesRegex(AssertionError, "final RSS growth"):
            resource_report(samples, final=True)
        self.assertEqual(resource_report(samples[:20], final=True)["rss_growth_kib"], 0)

    def test_missing_warm_samples_and_resource_peaks_cannot_pass(self):
        for samples in ([], [{"elapsed": 0, "rss_kib": 6000, "fds": 1, "threads": 1}]):
            with self.assertRaises(AssertionError):
                resource_report(samples, final=True)
        for field, value in (("fds", 129), ("threads", 33), ("rss_kib", 131073)):
            with self.assertRaises(AssertionError):
                resource_report([dict(elapsed=20, rss_kib=6000, fds=1, threads=1) | {field: value}], final=True)


if __name__ == "__main__":
    unittest.main()
