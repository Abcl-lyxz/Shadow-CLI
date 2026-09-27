# Embedded report font

`NotoSansThai-Regular.ttf` is a static instance of the Google Fonts
`NotoSansThai[wdth,wght].ttf` at `wdth=100`, `wght=400`. It covers the Latin and
Thai glyphs used by the PDF report. The original font and `OFL.txt` were fetched
from the [Google Fonts Noto Sans Thai family](https://github.com/google/fonts/tree/main/ofl/notosansthai)
on 2026-09-27. The static instance was produced with fontTools 4.62.1:

```text
fontTools.varLib.instancer.instantiateVariableFont(font, {'wdth': 100, 'wght': 400}, inplace=True)
```

The checked-in static font SHA-256 is
`eefc4557c7bf96ff99c508f95b32e3e01a63a8822937f81bed09eada45092220`.
The included OFL license SHA-256 is
`96ac951c8caddd87d8a66fe0d02342127696131d3e935ce4a936dc68cf032e33`.
The generated PDF embeds the font; unsupported glyphs cause export to fail.
