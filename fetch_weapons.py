import urllib.request, os, sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

OUT = 'assets/icons'
os.makedirs(OUT, exist_ok=True)

SLUGS = [
    # warrior
    'broadsword','gladius','scythe','halberd','morning-star','stone-axe',
    'war-pick','bloody-sword','winged-sword','relic-blade','barbed-spear',
    'spiked-mace','cleaver','saber-and-pistol','axe-sword','katana','mace-head',
    # mage
    'crystal-wand','fire-wand','fairy-wand','scroll-unfurled','spell-book',
    'magic-trident','frost-staff','bolt-spellcast','gem-pendant','orb-wand',
    'magic-swirl','wizard-staff-icon','gooey-eyed-sun',
    # rogue
    'curvy-knife','stiletto','kunai','arrow-flights','bow-arrow','crossbow',
    'throwing-knife','sai','butterfly-knife','bow',
    'thrown-daggers','switchblade','poison-bottle','fangs','sting',
]
AUTHORS = ['lorc','delapouite']

def fetch(slug, author):
    url = f'https://game-icons.net/icons/ffffff/000000/1x1/{author}/{slug}.svg'
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode('utf-8')
    except Exception:
        return None

BG_RE = re.compile(r'<path(?: fill="#000")? d="M0 0h512v512H0z"/>')

ok, fail = [], []
for slug in SLUGS:
    path = os.path.join(OUT, f'{slug}.svg')
    if os.path.exists(path):
        ok.append(slug); continue
    content = None
    for a in AUTHORS:
        content = fetch(slug, a)
        if content: break
    if not content:
        fail.append(slug); continue
    content = BG_RE.sub('', content)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    ok.append(slug)

print(f'OK ({len(ok)}): ' + ' '.join(ok))
print(f'FAIL ({len(fail)}): ' + ' '.join(fail))
