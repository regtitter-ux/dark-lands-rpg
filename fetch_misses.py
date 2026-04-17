import urllib.request, os, re, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

OUT = 'server/public/assets/icons'
CANDIDATES = {
    'cancel':        [('cancel','skoll'),('stop-sign','delapouite'),('broken-shield','lorc'),('broken-bone','lorc'),('crossed-bones','lorc')],
    'heart-plus':    [('heart-bottle','lorc'),('hearts','lorc'),('regeneration','lorc'),('healing','delapouite')],
    'withered-tree': [('oak-leaf','lorc'),('maple-leaf','delapouite'),('dandelion-flower','delapouite'),('vanilla-flower','lorc'),('rose','delapouite')],
}

BG_RE = re.compile(r'<path fill="#000"[^/]*h512v512H0z"/>')

def fetch(slug, author):
    url = f'https://game-icons.net/icons/ffffff/000000/1x1/{author}/{slug}.svg'
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode('utf-8')
    except Exception:
        return None

for target, cands in CANDIDATES.items():
    path = os.path.join(OUT, f'{target}.svg')
    if os.path.exists(path): print(f'exists {target}'); continue
    got = None
    for slug, author in cands:
        c = fetch(slug, author)
        if c: got = (slug, author, c); break
    if got:
        slug, author, c = got
        c = BG_RE.sub('', c)
        with open(path, 'w', encoding='utf-8') as f: f.write(c)
        print(f'OK    {target} <- {author}/{slug}')
    else:
        print(f'FAIL  {target}')
