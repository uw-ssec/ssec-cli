from ssec_cli.tools.versions import is_below, extract_version, parse_version


def test_is_below_basic():
    assert is_below("26.2.1", "26.2.2") is True
    assert is_below("26.2.2", "26.2.2") is False
    assert is_below("26.10", "26.9.4") is False
    assert is_below("2025.8.3", "2026.10.19") is True


def test_is_below_edge_cases():
    assert is_below("26.2.2.post1", "26.2.2") is False
    assert is_below("26.2.2rc1", "26.2.2") is True  # pre-release of the minimum is below it
    assert is_below("0.13.4+local", "0.13.4") is False
    assert is_below("26.2", "26.2.0") is False  # zero-padding
    assert is_below("garbage", "1.0") is None


def test_extract_version():
    assert extract_version("pip 26.2.2 from /x/site-packages/pip (python 3.12)") == "26.2.2"
    assert extract_version("uv 0.13.4 (Homebrew 2026-10-21)") == "0.13.4"
    assert extract_version("") is None


def test_parse_version():
    assert parse_version("26.2.2rc1") == ((26, 2, 2), True)
    assert parse_version("1.0.dev3") == ((1, 0), True)
    assert parse_version("1.0.post1") == ((1, 0), False)
    assert parse_version("v1.2") == ((1, 2), False)
    assert parse_version("garbage") is None
