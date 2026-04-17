import re, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

MAP = {
    '\u2605':       'star-formation',
    '\u2694':       'crossed-swords',
    '\u2726':       'sparkles',
    '\U0001F4B0':   'two-coins',
    '\U0001F6E1':   'round-shield',
    '\U0001F6D2':   'shopping-cart',
    '\u2713':       'check-mark',
    '\u2620':       'death-skull',
    '\U0001F48D':   'diamond-ring',
    '\U0001F525':   'flame',
    '\U0001F9D9':   'wizard-face',
    '\U0001F5E1':   'plain-dagger',
    '\u2744':       'snowflake-1',
    '\u2728':       'sparkles',
    '\U0001F409':   'dragon-head',
    '\U0001F432':   'dragon-spiral',
    '\U0001F4FF':   'prayer-beads',
    '\u2B50':       'polar-star',
    '\U0001F9EA':   'round-bottom-flask',
    '\U0001F48E':   'cut-diamond',
    '\U0001F400':   'rat',
    '\U0001F480':   'skull-crossed-bones',
    '\U0001F43A':   'wolf-head',
    '\U0001F5FF':   'stone-tower',
    '\u2693':       'anchor',
    '\U0001F3C3':   'run',
    '\U0001F3F0':   'castle',
    '\u2715':       'cancel',
    '\U0001FA84':   'magic-palm',
    '\U0001FA93':   'battle-axe',
    '\U0001F528':   'flat-hammer',
    '\U0001F94B':   'kimono',
    '\U0001F9F4':   'potion-ball',
    '\U0001F376':   'glass-shot',
    '\U0001F499':   'hearts',
    '\U0001F9EC':   'dna1',
    '\U0001F4A3':   'unlit-bomb',
    '\u2764':       'heart-plus',
    '\U0001FAB6':   'feather',
    '\u26A1':       'lightning-bolt',
    '\U0001F328':   'frozen-orb',
    '\U0001F311':   'moon',
    '\U0001F4A8':   'wind-slap',
    '\U0001F4A2':   'angry-eyes',
    '\U0001F300':   'vortex',
    '\U0001F479':   'ogre',
    '\U0001F577':   'spider-face',
    '\U0001F40D':   'snake',
    '\U0001F9DA':   'fairy',
    '\U0001F9DF':   'shambling-zombie',
    '\U0001F977':   'ninja-head',
    '\U0001F9B9':   'bandit',
    '\U0001F974':   'vomiting',
    '\U0001F47A':   'goblin-head',
    '\U0001F47B':   'ghost',
    '\U0001F9DE':   'djinn',
    '\U0001F47F':   'daemon-skull',
    '\U0001F98D':   'gorilla',
    '\U0001F608':   'imp-laugh',
    '\U0001F98E':   'lizardman',
    '\U0001F976':   'yeti',
    '\U0001F985':   'eagle-emblem',
    '\U0001F3D8':   'village',
    '\U0001F332':   'pine-tree',
    '\U0001F940':   'withered-tree',
    '\U0001F573':   'hole',
    '\u26B0':       'coffin',
    '\U0001F3DB':   'greek-temple',
    '\U0001F3D4':   'mountains',
    '\U0001F30B':   'volcano',
    '\U0001F4AA':   'muscle-up',
    '\U0001F9E0':   'brain',
    '\U0001F392':   'knapsack',
    '\U0001F4A4':   'sleepy',
    '\U0001F37A':   'beer-stein',
    '\U0001F5FA':   'treasure-map',
    '\U0001F4A5':   'explosion-rays',
}

with open('server/public/index.html','r',encoding='utf-8') as f:
    t = f.read()

# Replace each emoji with <img> tag.
# Also strip variation selectors (FE0F) and ZWJ (200D) that may cling to emojis.
def repl(m):
    e = m.group(0)
    # strip VS/ZWJ if attached
    base = e[0]
    if base in MAP:
        return f'<img class="gi" src="assets/icons/{MAP[base]}.svg" alt="">'
    return e

# Build regex of all keys, consuming optional trailing VS/ZWJ chars
keys = sorted(MAP.keys(), key=lambda x: -len(x))
pat = '(?:' + '|'.join(re.escape(k) for k in keys) + ')[\uFE0F\u200D]*'
t2 = re.sub(pat, repl, t)

# Fix the two textContent assignments that write ico
t2 = t2.replace("$('hero-ico').textContent = P.ico;",
                "$('hero-ico').innerHTML = P.ico;")
t2 = t2.replace("$('scene-art').textContent = loc.ico;",
                "$('scene-art').innerHTML = loc.ico;")

# Inject CSS class .gi right before closing </style>
CSS = """
  .gi { display: inline-block; width: 1em; height: 1em; vertical-align: -0.15em;
        filter: brightness(0) saturate(100%) invert(86%) sepia(22%) saturate(1160%) hue-rotate(3deg) brightness(101%) contrast(93%);
        object-fit: contain; }
  .scene-box .gi { width: 42px; height: 42px; vertical-align: middle; filter: brightness(0) saturate(100%) invert(86%) sepia(22%) saturate(1160%) hue-rotate(3deg) brightness(101%) contrast(93%) drop-shadow(0 0 6px rgba(244,208,63,0.5)); }
  .equip-slot .gi { width: 22px; height: 22px; }
  .modal .cls .gi { width: 36px; height: 36px; }
  .shop-card .gi { width: 32px; height: 32px; filter: brightness(0) saturate(100%) invert(86%) sepia(22%) saturate(1160%) hue-rotate(3deg) brightness(101%) contrast(93%) drop-shadow(0 0 4px rgba(244,208,63,0.4)); }
  .portrait .gi { width: 2.2em; height: 2.2em; }
  .stage-bar .gi { width: 14px; height: 14px; }
  .gi.good { filter: brightness(0) saturate(100%) invert(72%) sepia(40%) saturate(610%) hue-rotate(55deg) brightness(95%) contrast(88%); }
  .gi.bad  { filter: brightness(0) saturate(100%) invert(45%) sepia(82%) saturate(3000%) hue-rotate(340deg) brightness(90%) contrast(95%); }
  .gi.magic{ filter: brightness(0) saturate(100%) invert(68%) sepia(30%) saturate(800%) hue-rotate(165deg) brightness(95%) contrast(90%); }
"""
t2 = t2.replace('</style>', CSS + '</style>', 1)

with open('server/public/index.html','w',encoding='utf-8') as f:
    f.write(t2)

print('done, len', len(t2))
