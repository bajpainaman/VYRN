# Writes .github/assets/og-dark.png, the README header in the dark theme, from site/public/og.png.
# Run: uv run --with numpy --with pillow python site/scripts/og-dark.py site/public/og.png .github/assets/og-dark.png
# The light->dark pairs are the --color-* tokens in app/globals.css (canary, pink, ink, stamp, ink-soft).
# Map og.png onto the site's dark tokens. Each pixel is the nearest blend a*(1-t)+b*t of two palette
# colours (anti-aliasing mixes at most two); it is redrawn as the same blend of their dark pairs.
import sys, numpy as np
from PIL import Image
P = {"f2d447":"272107","f4b7c2":"2e1d23","191b26":"ebe6d2","5a2d91":"c4a6f7","4a4318":"d6c26a"}
h = lambda s: np.array([int(s[i:i+2],16) for i in (0,2,4)], float)
L = np.array([h(k) for k in P]); D = np.array([h(v) for v in P.values()])
img = np.asarray(Image.open(sys.argv[1]).convert("RGB"), float); px = img.reshape(-1,3)
best = np.full(len(px), np.inf); out = np.zeros_like(px)
n = len(L)
for i in range(n):
    for j in range(n):
        a, b = L[i], L[j]; d = b - a; dd = d @ d
        t = np.zeros(len(px)) if dd == 0 else np.clip(((px - a) @ d) / dd, 0, 1)
        err = ((a + t[:,None]*d - px)**2).sum(1)
        m = err < best; best[m] = err[m]
        out[m] = D[i] + t[m,None]*(D[j]-D[i])
print("max residual", np.sqrt(best.max()), "p99", np.sqrt(np.percentile(best, 99)))
Image.fromarray(out.reshape(img.shape).round().clip(0,255).astype(np.uint8)).save(sys.argv[2], optimize=True)
