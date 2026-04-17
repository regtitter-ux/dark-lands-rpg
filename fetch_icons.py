import urllib.request, os, sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

OUT = 'server/public/assets/icons'
os.makedirs(OUT, exist_ok=True)

# emoji -> (slug, [authors to try])
MAP = {
    '\u2605':        ('star-formation',   ['lorc','delapouite']),          # star
    '\u2694':        ('crossed-swords',   ['lorc','delapouite']),          # swords
    '\u2726':        ('sparkles',         ['lorc','delapouite']),          # sparkle
    '\U0001F4B0':    ('two-coins',        ['lorc','delapouite']),          # gold
    '\U0001F6E1':    ('round-shield',     ['lorc','delapouite']),          # shield
    '\U0001F6D2':    ('shopping-cart',    ['delapouite','lorc']),          # cart
    '\u2713':        ('check-mark',       ['delapouite','lorc']),          # check
    '\u2620':        ('death-skull',      ['lorc','delapouite']),          # skull
    '\U0001F48D':    ('diamond-ring',     ['lorc','delapouite']),          # ring
    '\U0001F525':    ('flame',            ['lorc','delapouite']),          # fire
    '\U0001F9D9':    ('wizard-face',      ['lorc','delapouite']),          # wizard
    '\U0001F5E1':    ('plain-dagger',     ['lorc','delapouite']),          # dagger
    '\u2744':        ('snowflake-1',      ['lorc','delapouite']),          # snowflake
    '\u2728':        ('sparkles',         ['lorc','delapouite']),          # sparkles
    '\U0001F409':    ('dragon-head',      ['lorc','delapouite']),          # dragon
    '\U0001F432':    ('dragon-spiral',    ['lorc','delapouite']),          # dragon
    '\U0001F4FF':    ('prayer-beads',     ['delapouite','lorc']),          # prayer beads
    '\u2B50':        ('polar-star',       ['lorc','delapouite']),          # star
    '\U0001F9EA':    ('round-bottom-flask',['lorc','delapouite']),         # test tube
    '\U0001F48E':    ('cut-diamond',      ['lorc','delapouite']),          # gem
    '\U0001F400':    ('rat',              ['delapouite','lorc']),          # rat
    '\U0001F480':    ('skull-crossed-bones',['lorc','delapouite']),        # skull
    '\U0001F43A':    ('wolf-head',        ['lorc','delapouite']),          # wolf
    '\U0001F5FF':    ('stone-tower',      ['lorc','delapouite']),          # golem
    '\u2693':        ('anchor',           ['lorc','delapouite']),          # anchor
    '\U0001F3C3':    ('run',              ['lorc','delapouite']),          # runner
    '\U0001F3F0':    ('castle',           ['delapouite','lorc']),          # castle
    '\u2715':        ('cancel',           ['delapouite','lorc']),          # cross
    '\U0001FA84':    ('magic-palm',       ['lorc','delapouite']),          # wand
    '\U0001FA93':    ('battle-axe',       ['lorc','delapouite']),          # axe
    '\U0001F528':    ('flat-hammer',      ['lorc','delapouite']),          # hammer
    '\U0001F94B':    ('kimono',           ['delapouite','lorc']),          # gi
    '\U0001F9F4':    ('potion-ball',      ['lorc','delapouite']),          # lotion
    '\U0001F376':    ('glass-shot',       ['delapouite','lorc']),          # sake
    '\U0001F499':    ('hearts',           ['delapouite','lorc']),          # blue heart
    '\U0001F9EC':    ('dna1',             ['delapouite','lorc']),          # dna
    '\U0001F4A3':    ('unlit-bomb',       ['lorc','delapouite']),          # bomb
    '\u2764':        ('heart-plus',       ['delapouite','lorc']),          # heart
    '\U0001FAB6':    ('feather',          ['lorc','delapouite']),          # feather
    '\u26A1':        ('lightning-bolt',   ['lorc','delapouite']),          # lightning
    '\U0001F328':    ('frozen-orb',       ['lorc','delapouite']),          # blizzard
    '\U0001F311':    ('moon',             ['lorc','delapouite']),          # moon
    '\U0001F4A8':    ('wind-slap',        ['delapouite','lorc']),          # wind
    '\U0001F4A2':    ('angry-eyes',       ['lorc','delapouite']),          # anger
    '\U0001F300':    ('vortex',           ['lorc','delapouite']),          # vortex
    '\U0001F479':    ('ogre',             ['delapouite','lorc']),          # ogre
    '\U0001F577':    ('spider-face',      ['lorc','delapouite']),          # spider
    '\U0001F40D':    ('snake',            ['lorc','delapouite']),          # snake
    '\U0001F9DA':    ('fairy',            ['delapouite','lorc']),          # fairy
    '\U0001F9DF':    ('shambling-zombie', ['delapouite','lorc']),          # zombie
    '\U0001F977':    ('ninja-head',       ['lorc','delapouite']),          # ninja
    '\U0001F9B9':    ('bandit',           ['delapouite','lorc']),          # villain
    '\U0001F974':    ('vomiting',         ['lorc','delapouite']),          # dizzy
    '\U0001F47A':    ('goblin-head',      ['lorc','delapouite']),          # goblin
    '\U0001F47B':    ('ghost',            ['lorc','delapouite']),          # ghost
    '\U0001F9DE':    ('djinn',            ['delapouite','lorc']),          # genie
    '\U0001F47F':    ('daemon-skull',     ['lorc','delapouite']),          # devil
    '\U0001F98D':    ('gorilla',          ['delapouite','lorc']),          # gorilla
    '\U0001F608':    ('imp-laugh',        ['lorc','delapouite']),          # devil
    '\U0001F98E':    ('lizardman',        ['lorc','delapouite']),          # lizard
    '\U0001F976':    ('yeti',             ['delapouite','lorc']),          # cold
    '\U0001F985':    ('eagle-emblem',     ['lorc','delapouite']),          # eagle
    '\U0001F3D8':    ('village',          ['delapouite','lorc']),          # village
    '\U0001F332':    ('pine-tree',        ['lorc','delapouite']),          # tree
    '\U0001F940':    ('withered-tree',    ['lorc','delapouite']),          # wilted
    '\U0001F573':    ('hole',             ['lorc','delapouite']),          # hole
    '\u26B0':        ('coffin',           ['lorc','delapouite']),          # coffin
    '\U0001F3DB':    ('greek-temple',     ['delapouite','lorc']),          # temple
    '\U0001F3D4':    ('mountains',        ['delapouite','lorc']),          # mountain
    '\U0001F30B':    ('volcano',          ['delapouite','lorc']),          # volcano
    '\U0001F4AA':    ('muscle-up',        ['lorc','delapouite']),          # muscle
    '\U0001F9E0':    ('brain',            ['lorc','delapouite']),          # brain
    '\U0001F392':    ('knapsack',         ['delapouite','lorc']),          # backpack
    '\U0001F4A4':    ('sleepy',           ['delapouite','lorc']),          # sleep
    '\U0001F37A':    ('beer-stein',       ['delapouite','lorc']),          # beer
    '\U0001F5FA':    ('treasure-map',     ['lorc','delapouite']),          # map
    '\U0001F4A5':    ('explosion-rays',   ['lorc','delapouite']),          # boom
}

def fetch(slug, author):
    url = f'https://game-icons.net/icons/ffffff/000000/1x1/{author}/{slug}.svg'
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode('utf-8')
    except Exception as e:
        return None

# Strip the black background rect so icon is white-on-transparent
BG_RE = re.compile(r'<path(?: fill="#000")? d="M0 0h512v512H0z"/>')

ok, fail = [], []
for emoji, (slug, authors) in MAP.items():
    fname = f'{slug}.svg'
    path = os.path.join(OUT, fname)
    if os.path.exists(path):
        ok.append((emoji, slug))
        continue
    content = None
    used_slug = slug
    for a in authors:
        content = fetch(slug, a)
        if content: break
    if not content:
        fail.append((emoji, slug))
        continue
    content = BG_RE.sub('', content)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    ok.append((emoji, slug))

print(f'OK: {len(ok)}  FAIL: {len(fail)}')
for e, s in fail:
    print(f'  MISS {s}  for U+{ord(e[0]):04X}')
