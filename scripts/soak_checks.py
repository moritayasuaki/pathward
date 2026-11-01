"""Dependency-free response/resource oracles shared by the soak and regressions."""
import statistics


def payload(host, release):
    return (f"PUBLIC:{host}:{release}:".encode() * 3000)[:65536]


def check_release(code, headers, body, host, expected, method, target):
    """Expected release comes from the acknowledged command for post-commit probes."""
    assert expected in ("A", "B")
    assert headers["x-robots-tag"] == f"release-{expected}", "stale release header"
    assert headers["strict-transport-security"] == "max-age=60"
    published = "/a" if expected == "A" else "/b"
    path, mark, query = target.partition("?")
    if path in ("/", published):
        expected_body = payload(host, expected)
        assert code == 200 and int(headers["content-length"]) == len(expected_body)
        assert body == (b"" if method == "HEAD" else expected_body), "stale or mixed release content"
    elif path == "/legacy":
        assert code == 308 and body == b""
        assert headers["location"] == f"https://{host}{published}{mark}{query}", "stale redirect"
    else:
        assert code == 404 and body == b"", "revoked/unlisted publication still served"
    assert b"FORBIDDEN_" not in body, "unpublished content leaked"


def resource_report(samples, final=False):
    if not samples:
        assert not final, "missing final resource samples"
        return {}
    data = {"resources": {field: {"min": min(s[field] for s in samples),
                                  "max": max(s[field] for s in samples), "last": samples[-1][field]}
                           for field in ("rss_kib", "threads", "fds")}}
    warm = [s["rss_kib"] for s in samples if 20 <= s["elapsed"] <= 40]
    if warm:
        data["rss_growth_kib"] = statistics.median(s["rss_kib"] for s in samples[-10:]) - statistics.median(warm)
    if final:
        assert warm, "missing warm-window resource samples"
        assert data["rss_growth_kib"] <= 16384, "final RSS growth exceeded 16 MiB"
        for field, ceiling in (("rss_kib", 131072), ("threads", 32), ("fds", 128)):
            assert data["resources"][field]["max"] <= ceiling, "final resource ceiling"
    return data
