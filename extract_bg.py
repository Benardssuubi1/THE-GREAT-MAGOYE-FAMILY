from pathlib import Path

html = Path('index.html').read_text(encoding='utf-8')
needle = "background-image: url('"
start = html.find(needle)
if start < 0:
    raise SystemExit('needle not found')
start += len(needle)
end = html.find("')", start)
if end < 0:
    raise SystemExit('end not found')
Path('hero-bg-uri.txt').write_text(html[start:end], encoding='utf-8')
print('done')
