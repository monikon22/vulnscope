from vulnscope.scanner.payloads import profile_payloads


def test_payloads_do_not_depend_on_profile_name() -> None:
    default_payloads = profile_payloads("default")

    assert default_payloads
    assert profile_payloads("headers") == default_payloads
    assert profile_payloads("custom-juice-shop") == default_payloads
