# 🖼️ Multimodal & Document Metadata Shield

Adversarial actors embed indirect prompt injections inside non-text media channels, including:
1. **EXIF / IPTC Image Metadata:** Injected instructions inside `ImageDescription`, `UserComment`, or `Artist` tags.
2. **SVG Vector Steganography:** Executable `<script>` tags or hidden text (`display="none"`, `opacity="0"`).
3. **PDF / Document Text Streams:** Hidden annotations and delimiter escapes.

`MultimodalShield` inspects and neutralizes these vectors without requiring heavy computer vision dependencies.

---

## 🚀 Quick Example

```python
from lightguard import MultimodalShield

shield = MultimodalShield()

# Sanitize SVG vector graphic
svg_result = shield.sanitize_svg(raw_svg_string)
clean_svg = svg_result["sanitized_svg"]

# Sanitize image metadata dictionary
meta_result = shield.scan_metadata_strings(image_exif_dict)
clean_metadata = meta_result["clean_metadata"]
```
