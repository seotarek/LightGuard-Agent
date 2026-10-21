from lightguard.fast_matcher import FastPatternMatcher


def test_fast_matcher_basic():
    matcher = FastPatternMatcher(["ignore previous instructions", "system override", "drop database"])
    assert matcher.pattern_count == 3

    text = "Hello, please Ignore Previous Instructions now."
    assert matcher.contains_any(text) is True

    matches = matcher.search(text)
    assert len(matches) == 1
    start, end, kw = matches[0]
    assert kw == "ignore previous instructions"
    assert text[start:end].lower() == kw


def test_fast_matcher_multiple_and_overlapping():
    matcher = FastPatternMatcher(["he", "she", "his", "hers"])
    matches = matcher.search("ushers")
    found_keywords = {m[2] for m in matches}
    assert "he" in found_keywords
    assert "she" in found_keywords
    assert "hers" in found_keywords


def test_fast_matcher_benign():
    matcher = FastPatternMatcher(["malicious", "attack", "exploit"])
    assert matcher.contains_any("This is a completely harmless user request.") is False
    assert matcher.search("This is a completely harmless user request.") == []


def test_fast_matcher_empty():
    matcher = FastPatternMatcher([])
    assert matcher.pattern_count == 0
    assert matcher.contains_any("any text") is False
    assert matcher.search("any text") == []
