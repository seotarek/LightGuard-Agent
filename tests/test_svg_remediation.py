from lightguard.multimodal import MultimodalShield


def test_svg_strips_external_href_and_src():
    shield = MultimodalShield()
    svg = """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
        <image href="http://evil.com/exfil.png" width="100" height="100" />
        <image xlink:href="https://attacker.com/leak.jpg" width="50" height="50" />
    </svg>"""

    res = shield.sanitize_svg(svg)
    assert res["is_sanitized"] is True
    assert any("external resource" in t.lower() for t in res["threats"])
    assert "evil.com" not in res["sanitized_svg"]
    assert "attacker.com" not in res["sanitized_svg"]


def test_svg_preserves_internal_fragment_references():
    shield = MultimodalShield()
    svg = """<svg xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="grad1">
                <stop offset="0%" stop-color="red" />
            </linearGradient>
        </defs>
        <use href="#grad1" />
    </svg>"""

    res = shield.sanitize_svg(svg)
    assert "#grad1" in res["sanitized_svg"]


def test_svg_strips_external_css_urls():
    shield = MultimodalShield()
    svg = """<svg xmlns="http://www.w3.org/2000/svg">
        <rect width="100" height="100" style="background: url('https://evil.com/bg.png'); stroke: blue;" />
    </svg>"""

    res = shield.sanitize_svg(svg)
    assert res["is_sanitized"] is True
    assert "evil.com" not in res["sanitized_svg"]
    assert "stroke: blue" in res["sanitized_svg"]
