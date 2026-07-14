# A286 — Four-target ChaCha20-R20 panel retained

Evidence stage: **FULLROUND_R20_FOUR_OF_FOUR_CROSS_MATERIAL_RECOVERIES_INDEPENDENTLY_CONFIRMED**

- Fresh, independently frozen public-material targets: **4**
- Full-round recoveries: **4/4**
- Third-reference output bits recomputed: **16,384**
- Applicable frozen-order ranks: **[254, 55, 107]**
- Discovery modes: **['fallback', 'top128', 'top128', 'global']**
- Complete residual-domain enumeration used: **False**
- Reader refits / target labels used: **0 / 0**
- One-bit controls rejected: **4/4**

The failed A285 aggregate gate was a header-width finalization bug: the requested nine-byte API id was truncated by the format's eight-byte field. It did not affect any target execution or scientific result. A286 preserves that diagnostic artifact and emits the corrected aggregate graph.

## Authentic AI-native Causal readback

- Terminal: **A286:retained_four_target_panel**
- Next gap: **prospectively_frozen_W24_cross_material_transfer**

Result SHA-256: `c171c61c1ce90c9e19faa06784205a7c9a24c2ddcb58db5ba74ecd00f1e32464`
