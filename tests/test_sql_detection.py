from attack_detection import AttackDetector


def run_tests() -> None:
    detector = AttackDetector()
    malicious = {
        "encoded OR": "GET /?id=1%20OR%201%3D1 HTTP/1.1\r\nHost: test\r\n\r\n",
        "raw OR": "GET /?id=1 OR 1=1 HTTP/1.1\r\nHost: test\r\n\r\n",
        "quoted OR": "GET /?u=admin' OR '1'='1 HTTP/1.1\r\nHost: test\r\n\r\n",
        "encoded UNION": "GET /?q=1%20UNION%20SELECT%20name%20FROM%20users HTTP/1.1\r\nHost: test\r\n\r\n",
        "encoded SLEEP": "GET /?id=1%20AND%20SLEEP%285%29 HTTP/1.1\r\nHost: test\r\n\r\n",
    }
    benign = {
        "normal search": "GET /?search=hello+world HTTP/1.1\r\nHost: test\r\n\r\n",
        "ordinary or": "GET /?q=tea+or+coffee HTTP/1.1\r\nHost: test\r\n\r\n",
    }

    for name, request in malicious.items():
        results = detector.detect_attacks(request, {})
        assert any(item["type"] == "SQL Injection" for item in results), name

    for name, request in benign.items():
        results = detector.detect_attacks(request, {})
        assert not any(item["type"] == "SQL Injection" for item in results), name

    print(f"Passed {len(malicious) + len(benign)} SQL detection tests.")


if __name__ == "__main__":
    run_tests()
