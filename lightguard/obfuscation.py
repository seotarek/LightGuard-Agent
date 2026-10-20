import base64
import binascii
import math
import re
import time
import unicodedata
from typing import Any, ClassVar


class Tier0ObfuscationShield:
    """
    Tier 0: Steganography, Obfuscation, and Adversarial Evasion Normalizer.
    Eliminates zero-width invisible characters, normalizes cross-script homoglyphs,
    recursively decodes Base64/Hex steganography, standardizes leetspeak, and calculates
    Shannon entropy to detect obfuscated injection payloads before Tier 1 & 2 evaluation.
    """

    # Invisible unicode codepoints used for token smuggling & prompt injection
    INVISIBLE_CHARS: ClassVar[re.Pattern] = re.compile(
        r"[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF\u00AD\u034F\u180E]"
    )

    # Common Cyrillic & Greek homoglyphs mapped to ASCII equivalents
    HOMOGLYPH_MAP: ClassVar[dict[str, str]] = {
        # Cyrillic small
        "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
        "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
        # Cyrillic capital
        "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J",
        "К": "K", "М": "M", "О": "O", "Р": "P", "Т": "T", "Х": "X", "Ү": "Y",
        # Greek
        "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
        "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    }

    # Leetspeak common substitutions
    LEET_MAP: ClassVar[dict[str, str]] = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i",
    }

    # Potential base64 pattern (length at least 12, alphanumeric + / + =)
    BASE64_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})"
    )

    # Hex escaped or continuous hex patterns: \x65\x78... or 48656c6c6f...
    HEX_ESCAPED_PATTERN: ClassVar[re.Pattern] = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
    HEX_CONTINUOUS_PATTERN: ClassVar[re.Pattern] = re.compile(r"\b[0-9a-fA-F]{16,}\b")

    @classmethod
    def strip_invisible(cls, text: str) -> tuple[str, bool]:
        """Removes zero-width characters and invisible control code points."""
        cleaned, count = cls.INVISIBLE_CHARS.subn("", text)
        return cleaned, count > 0

    @classmethod
    def normalize_homoglyphs(cls, text: str) -> tuple[str, bool]:
        """Maps non-Latin homoglyphs and compatibility forms to standard ASCII."""
        # Standard NFKD decomposition folds font variants (mathematical bold, fullwidth, etc.)
        nfkd = unicodedata.normalize("NFKD", text)
        converted = []
        replaced = False
        for ch in nfkd:
            if ch in cls.HOMOGLYPH_MAP:
                converted.append(cls.HOMOGLYPH_MAP[ch])
                replaced = True
            else:
                converted.append(ch)
        return "".join(converted), replaced

    @classmethod
    def normalize_leetspeak(cls, text: str) -> str:
        """Translates leetspeak characters in token contexts."""
        words = text.split()
        normalized_words = []
        for word in words:
            # If word is mixed letters and leet numbers/symbols
            has_letters = any(c.isalpha() for c in word)
            has_leet = any(c in cls.LEET_MAP for c in word)
            if has_letters and has_leet:
                trans = "".join(cls.LEET_MAP.get(c, c) for c in word)
                normalized_words.append(trans)
            else:
                normalized_words.append(word)
        return " ".join(normalized_words)

    @classmethod
    def decode_steganography(cls, text: str) -> tuple[list[str], bool]:
        """Recursively decodes hidden Base64 or Hex encoded payloads."""
        decoded_payloads: list[str] = []
        found = False

        # Check Hex Escapes: \x69\x67\x6e\x6f\x72\x65...
        for match in cls.HEX_ESCAPED_PATTERN.findall(text):
            try:
                hex_str = match.replace("\\x", "")
                decoded = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                if len(decoded.strip()) >= 4 and sum(c.isprintable() for c in decoded) / len(decoded) > 0.8:
                    decoded_payloads.append(decoded)
                    found = True
            except Exception:
                pass

        # Check Continuous Hex strings: 69676e6f7265...
        for match in cls.HEX_CONTINUOUS_PATTERN.findall(text):
            if len(match) % 2 == 0:
                try:
                    decoded = bytes.fromhex(match).decode("utf-8", errors="ignore")
                    if len(decoded.strip()) >= 6 and sum(c.isprintable() for c in decoded) / len(decoded) > 0.85:
                        decoded_payloads.append(decoded)
                        found = True
                except Exception:
                    pass

        # Check Base64 strings
        for match in cls.BASE64_PATTERN.findall(text):
            # Exclude trivial tokens
            if len(match) < 12:
                continue
            try:
                raw_bytes = base64.b64decode(match, validate=True)
                decoded = raw_bytes.decode("utf-8", errors="ignore")
                # Ensure it decodes to meaningful text rather than arbitrary binary
                if len(decoded.strip()) >= 6 and sum(c.isprintable() for c in decoded) / len(decoded) > 0.80:
                    decoded_payloads.append(decoded)
                    found = True
                    # Check recursive Base64 (nested encoding)
                    for sub_match in cls.BASE64_PATTERN.findall(decoded):
                        try:
                            sub_raw = base64.b64decode(sub_match, validate=True)
                            sub_decoded = sub_raw.decode("utf-8", errors="ignore")
                            if len(sub_decoded.strip()) >= 6 and sum(c.isprintable() for c in sub_decoded) / len(sub_decoded) > 0.80:
                                decoded_payloads.append(sub_decoded)
                        except Exception:
                            pass
            except (binascii.Error, ValueError):
                continue

        return decoded_payloads, found

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        Calculates Shannon entropy: H(X) = - sum(p * log2(p)).
        High entropy in short snippets indicates potential encryption or packed obfuscation.
        """
        if not text:
            return 0.0
        frequencies: dict[str, int] = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1

        entropy = 0.0
        length = len(text)
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def normalize(cls, raw_text: str) -> dict[str, Any]:
        """
        Executes complete Tier 0 normalization and de-obfuscation pipeline.
        Returns normalized text, decoded payload artifacts, and risk indicators.
        """
        start_t = time.perf_counter()

        # Step 1: Strip zero-width & invisible characters
        stripped_text, has_invisible = cls.strip_invisible(raw_text)

        # Step 2: Normalize homoglyphs
        homoglyph_clean, has_homoglyphs = cls.normalize_homoglyphs(stripped_text)

        # Step 3: Decode hidden steganographic layers (Base64 / Hex)
        decoded_payloads, has_steganography = cls.decode_steganography(homoglyph_clean)

        # Step 4: Normalize leetspeak
        normalized_text = cls.normalize_leetspeak(homoglyph_clean)

        # Step 5: Shannon Entropy evaluation
        entropy = cls.calculate_shannon_entropy(raw_text)
        high_entropy = entropy > 4.8 and len(raw_text) > 30

        was_obfuscated = has_invisible or has_homoglyphs or has_steganography or high_entropy

        # Append decoded payloads so downstream Tiers 1 and 2 inspect them
        inspection_buffer = normalized_text
        if decoded_payloads:
            inspection_buffer += "\n" + "\n".join(decoded_payloads)

        elapsed_ms = (time.perf_counter() - start_t) * 1000.0

        return {
            "normalized_text": normalized_text,
            "inspection_buffer": inspection_buffer,
            "decoded_payloads": decoded_payloads,
            "was_obfuscated": was_obfuscated,
            "has_invisible": has_invisible,
            "has_homoglyphs": has_homoglyphs,
            "has_steganography": has_steganography,
            "high_entropy": high_entropy,
            "entropy": entropy,
            "elapsed_ms": elapsed_ms,
        }
