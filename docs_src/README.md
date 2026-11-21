# Document sources

HTML + CSS sources for the quick-reference PDFs served on the site's Documents tab
(`docs/`). Kept so the PDFs can be regenerated and restyled rather than re-authored.

`style.css` reproduces the house style of the original one-pagers — palette and type
scale were extracted from `What_is_a_CTF.pdf`:

| Token | Value |
|---|---|
| Body text | `#1a1a1a` |
| Headings / accent | `#0a3d62` |
| Green accent | `#1e5e2c` |
| Amber accent | `#5a3e00` |
| Red accent | `#c0392b` |
| Panel background | `#f4f7fa` · warn `#fff8e1` · good `#f2f8f3` |
| Borders | `#d0d7de`, `#e1e6eb` |
| Title / section / panel / body / small | 21.33 / 13.33 / 11.33 / 10.66 / 9.33 pt |

## Regenerate

```bash
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CHROME" --headless --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="../docs/Getting_Started_with_Wireshark.pdf" "file://$PWD/wireshark.html"
```

Repeat for each source:

| Source | Output |
|---|---|
| `wireshark.html` | `Getting_Started_with_Wireshark.pdf` |
| `phishing.html` | `Analysts_Guide_to_Phishing_Emails.pdf` |
| `space.html` | `Space_and_Satellite_Hacking.pdf` |
| `automotive.html` | `Car_and_Automotive_Hacking.pdf` |

After rendering, check pagination — Chrome will strand an `<h2>` at the foot of a
page when the table that follows it is too tall to fit. `style.css` sets
`break-after: avoid` on headings, which is not always enough; wrap the heading and
its table in a `<div style="break-inside:avoid">` when it happens.

Fonts resolve to Helvetica/Arial on macOS and Liberation Sans on Linux — both
metric-compatible, so output is consistent either way.

Filenames matter: `/docs` derives each document's displayed title from the filename,
turning `_` and `-` into spaces.
