from ssec_cli.tools.advisories import load_advisories, minimums_by_package, normalize_name


def test_bundled_file_loads_and_has_emsign():
    advs = load_advisories()
    assert advs[0].id == "2026-10-emudhra-emsign"
    mins = minimums_by_package(advs)
    assert mins["pip"].min_version == "26.2.2"
    assert mins["pip"].fix_sha256 and len(mins["pip"].fix_sha256) == 64
    assert mins["certifi"].min_version == "2026.10.19"
    assert all(m.min_version != "VERIFY" for m in mins.values())


def test_highest_minimum_wins(tmp_path):
    f = tmp_path / "a.toml"
    f.write_text(
        'schema_version = 1\n'
        '[[advisory]]\nid="a"\ntitle="A"\ndate="2026-01-01"\nurls=[]\n'
        '[[advisory.minimum]]\npackage="certifi"\nmin_version="1.0"\n'
        '[[advisory]]\nid="b"\ntitle="B"\ndate="2026-02-01"\nurls=[]\n'
        '[[advisory.minimum]]\npackage="Certifi"\nmin_version="2.0"\n'
    )
    mins = minimums_by_package(load_advisories(f))
    assert mins["certifi"].min_version == "2.0"
    assert mins["certifi"].advisory_id == "b"


def test_normalize_name():
    assert normalize_name("Ca_Certificates") == "ca-certificates"
