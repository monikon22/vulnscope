from vulnscope.domain.enums import ScopeMode
from vulnscope.domain.models import Target
from vulnscope.scanner.scope import ScopePolicy
from vulnscope.utils.urls import normalize_url


def test_url_normalization_adds_scheme_and_path() -> None:
    assert normalize_url("Example.COM") == "https://example.com/"


def test_same_host_scope_blocks_other_hosts() -> None:
    policy = ScopePolicy(Target(url="https://app.example.com/"))
    assert policy.allowed("https://app.example.com/login")
    assert not policy.allowed("https://api.example.com/login")


def test_same_domain_scope_allows_subdomain() -> None:
    policy = ScopePolicy(Target(url="https://app.example.com/", scope_mode=ScopeMode.SAME_DOMAIN))
    assert policy.allowed("https://api.example.com/login")

