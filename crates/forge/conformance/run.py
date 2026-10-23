#!/usr/bin/env python3
"""Gitea conformance scenario runner (stdlib only; run as `python3 -I run.py ...`).

  record  run every scenario against a real Gitea and write normalized fixtures
  check   run the same scenarios against any server and compare with fixtures
  diff    compare two fixture directories offline (A = expected, B = actual)
  show    print a one-line-per-exchange digest of a fixture directory

See README.md. Scenarios are the functions at the bottom of this file.
"""
import argparse
import base64
import hashlib
import io
import json as J
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

TRACKED_HEADERS = ("content-type", "x-total-count", "link", "www-authenticate", "location")
# Every scalar in a recorded body is compared by value after normalization, except DEFAULT_VOLATILE (below) and
# the dotted paths a call lists in `volatile=[...]` (`$text` for a text body).
TOKEN_KEYS = {"sha1", "token", "token_last_eight", "password"}
SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")
SHORT_RE = re.compile(r"\b[0-9a-f]{7,12}\.\.\.?[0-9a-f]{7,12}\b")
TS_RE = re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z| ?[+-]\d\d:?\d\d)?")
RFC_RE = re.compile(r"[A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d [+-]\d{4}")
USERS = ("alice", "bot", "carol", "dave")


class SetupError(Exception):
    """A call a scenario relies on did not behave as the scenario needs."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # surface 3xx as-is
        return None


OPENER = urllib.request.build_opener(_NoRedirect)


class R:
    def __init__(self, status, headers, data):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.data = data
        self.text = data.decode("utf-8", "replace")
        self.json, self.is_json = None, False
        if data.strip()[:1] in (b"{", b"[") or data.strip() == b"null":
            try:
                self.json, self.is_json = J.loads(data), True
            except ValueError:
                pass


PH_RE = re.compile(r"<(sha|id:[^#<>]*)#(\d+)>")
ID_RE = re.compile(r"^<id:[^#<>]*#\d+>$")


def sort_keys(v):
    if isinstance(v, dict):
        return {k: sort_keys(v[k]) for k in sorted(v)}
    return [sort_keys(x) for x in v] if isinstance(v, list) else v


def jtype(v):
    if isinstance(v, str) and ID_RE.match(v):
        return "number"
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    return "array" if isinstance(v, list) else "object"


class Bij:
    """Placeholder identity per scenario: `<sha#2>` in the fixture must always be the same actual value
    as each other `<sha#2>`, and two different placeholders must stay different values."""

    def __init__(self):
        self.f, self.r = {}, {}
        self.lf, self.lr = {}, {}

    def new_exchange(self):
        self.lf, self.lr = {}, {}

    def pair(self, kind, e, a):
        # body ids of different entities can coincide numerically, so they only keep identity inside one exchange
        f, r = (self.f, self.r) if kind == "sha" or kind.startswith("id:path:") else (self.lf, self.lr)
        return f.setdefault((kind, e), a) == a and r.setdefault((kind, a), e) == e


def eq_str(exp, act, bij, d, shown):
    skel = lambda x: PH_RE.sub(lambda m: "<%s>" % m.group(1), x)  # noqa: E731
    if skel(exp) != skel(act):
        d.append(("fail", f"{shown}: value {exp!r} expected, got {act!r}"))
        return False
    for me, ma in zip(PH_RE.finditer(exp), PH_RE.finditer(act)):
        if not bij.pair(me.group(1), me.group(2), ma.group(2)):
            d.append(("fail", f"{shown}: identity mismatch, {me.group(0)} expected but {ma.group(0)} is a different "
                              f"value than it was paired with earlier"))
            return False
    return True


# Keys compared by type only, at any depth. Everything else is compared by value, including `url`/`*_url`
# (after the base URL became <base>), commit/review `message`, `body` and status `description`.
#   avatar_url            hash of the e-mail or a generated avatar; differs per server
#   mergeable             flips while Gitea re-checks a PR after every base change
#   language              repo language stats are computed asynchronously
#   open_pr_counter, open_issues_count   async counters in embedded repo objects
#   size (repo objects only, detected by `full_name`)   disk size of the bare repo
# Per-call/per-departure entries (`volatile=`, `ignore_fields`) are dotted paths and match only that path.
# The top-level `message`/`errors` of an HTTP error response are compared as text by cmp_exchange instead.
DEFAULT_VOLATILE = {"avatar_url", "mergeable", "language", "open_pr_counter", "open_issues_count"}


def is_volatile(key, dotted, parent, volatile):
    if "!" + dotted in volatile:  # a call that settled this key asks for a by-value comparison
        return False
    if dotted in volatile or key in DEFAULT_VOLATILE:
        return True
    return key == "size" and isinstance(parent, dict) and "full_name" in parent


def cmp_json(exp, act, path, d, volatile, bij, key=None, parent=None):
    te, ta = jtype(exp), jtype(act)
    shown = path or "$"
    if te != ta:
        d.append(("fail", f"{shown}: type {te} expected, got {ta}"))
        return
    dotted = re.sub(r"\[\d+\]", "", path).lstrip(".")
    if is_volatile(key, dotted, parent, volatile):
        return
    if te == "object":
        for k, v in exp.items():
            if k not in act:
                d.append(("fail", f"{path}.{k}: key missing"))
            else:
                cmp_json(v, act[k], f"{path}.{k}", d, volatile, bij, k, exp)
    elif te == "array":
        if len(exp) != len(act):
            d.append(("fail", f"{shown}: array length {len(exp)} expected, got {len(act)}"))
        for i, (a, b) in enumerate(zip(exp, act)):
            cmp_json(a, b, f"{path}[{i}]", d, volatile, bij, key, parent)
    elif isinstance(exp, str):
        eq_str(exp, act, bij, d, shown)
    elif exp != act:
        d.append(("fail", f"{shown}: value {exp!r} expected, got {act!r}"))


def msg_text(ex):
    b = ex.get("body")
    if isinstance(b, dict) and isinstance(b.get("message"), str):
        return b["message"]
    if "body" in ex:
        return J.dumps(b)
    return ex.get("body_text") or ex.get("output") or ""


TRAIL_STRIP = (re.compile(r"\s*\[uid: [^\]]*\]\s*$"), re.compile(r"\s*\[id: [^\]]*rel_path: [^\]]*\]\s*$"))
ID_PAIRS = re.compile(r"\b(?:id|issue_id|head_repo_id|base_repo_id): \d+,?\s*")


def norm_msg(t):
    """Error text for comparison: lower case, trailing `[uid: .., name: ..]` and `[id: .., rel_path: ..]` details
    and numeric `id:` pairs dropped. Other brackets stay: `[name: alice]` and `[write:user]` are meaningful.
    Placeholders such as `<sha#3>` stay too, so eq_str can check which value a message names."""
    t = (t or "").lower()
    for r in TRAIL_STRIP:
        t = r.sub("", t)
    t = ID_PAIRS.sub("", t)
    return re.sub(r"\s+", " ", t).strip(" .:\n")


def eq_val(ev, av, bij):
    """Equality of note/pin values; strings are compared with placeholder identity (`<sha#2>`)."""
    if isinstance(ev, str) and isinstance(av, str):
        return eq_str(ev, av, bij, [], "")
    if isinstance(ev, list) and isinstance(av, list):
        return len(ev) == len(av) and all(eq_val(x, y, bij) for x, y in zip(ev, av))
    if isinstance(ev, dict) and isinstance(av, dict):
        return ev.keys() == av.keys() and all(eq_val(ev[k], av[k], bij) for k in ev)
    return ev == av


def msg_equal(exp_text, act_text, bij):
    tmp = []
    return eq_str(norm_msg(exp_text), norm_msg(act_text), bij, tmp, "")


def err_text(v):
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return " ".join(x for x in v if isinstance(x, str))
    return ""


NOISE = re.compile(r"processed|processing|references in total|create a new pull request|resolving|counting|compressing")


def refusal_lines(text):
    """The lines of a failed git command that say why it failed (remote:/fatal:/error:/! lines), normalized."""
    out = []
    for raw in text.splitlines():
        l = raw.strip()
        if not re.match(r"^(remote:|fatal:|error:|!)", l):
            continue
        l = re.sub(r"\s+", " ", re.sub(r"<[^<>]*>", "", l).lower()).strip()
        if l in ("remote:", "error:", "!", "remote: error:") or NOISE.search(l) or l in out:
            continue
        out.append(l)
    return out


def cmp_request(exp, act, bij):
    """The request side of an HTTP exchange: the principal it authenticated as and the normalized JSON body."""
    d = []
    if exp.get("auth") != act.get("auth"):
        d.append(("fail", f"request authenticated as {act.get('auth')!r}, the fixture says {exp.get('auth')!r}"))
    er, ar = exp.get("request"), act.get("request")
    if er is None and ar is None:
        return d
    if er is None or ar is None:
        d.append(("fail", f"request body {er!r} expected, got {ar!r}"))
        return d
    sub = []
    cmp_json(er, ar, "", sub, set(), bij)
    d += [("fail", "request body" + x[1]) for x in sub]
    return d


def cmp_exchange(exp, act, bij, extra_volatile=(), status_override=None, skip_headers=()):
    """Return [(level, text)] where level is 'fail' or 'warn'. Empty list means match."""
    d = []
    bij.new_exchange()
    if exp["kind"] != act["kind"]:
        return [("fail", f"kind {exp['kind']} expected, got {act['kind']}")]
    if ("web" in exp.get("tags", [])) != ("web" in act.get("tags", [])):
        return [("fail", f"web tag differs: fixture {exp.get('tags', [])}, scenario {act.get('tags', [])}")]
    if act.get("skipped"):  # a web-tagged exchange, not run without --include-web
        return []
    if exp["kind"] == "note":
        if exp["key"] != act["key"]:
            d.append(("fail", f"note {exp['key']} expected, got {act['key']}"))
        elif exp.get("strict", True):  # strict=False notes are informational
            ev, av = exp["value"], act["value"]
            if not eq_val(ev, av, bij):
                d.append(("fail", f"note {exp['key']}: {ev!r} expected, got {av!r}"))
        return d
    if exp["kind"] == "git":
        if exp["name"] != act["name"]:
            return [("fail", f"git step {exp['name']} expected, got {act['name']}")]
        # the command line too: a scenario that keeps its step name but changes the arguments (or the
        # credentials form) must not keep matching its fixture; placeholders keep shas and hosts by identity
        if exp.get("cmd") is not None and not eq_str(exp["cmd"], act["cmd"], bij, [], ""):
            return [("fail", f"git command {exp['cmd']!r} expected, got {act['cmd']!r}")]
        if exp["ok"] != act["ok"]:
            d.append(("fail", f"git ok={exp['ok']} expected, got {act['ok']}: {act['output'][:200]!r}"))
        elif not exp["ok"]:
            have = act.get("refusal") or refusal_lines(act["output"])
            for line in exp.get("refusal", []):
                if line not in have:
                    d.append(("fail", f"git refusal {line!r} expected, got {have[:4]!r}"))
    else:
        if exp["method"] != act["method"] or not eq_str(exp["path"], act["path"], bij, [], ""):
            return [("fail", f"request {exp['method']} {exp['path']} expected, got {act['method']} {act['path']}")]
        d += cmp_request(exp, act, bij)
        es = exp["status"] if status_override is None else status_override
        if es != act["status"]:
            d.append(("fail", f"status {es} expected, got {act['status']}: {msg_text(act)[:200]!r}"))
        elif es >= 400 and isinstance(exp.get("body"), dict) and status_override is None:
            ab = act.get("body") if isinstance(act.get("body"), dict) else None
            for key in ("message", "errors"):
                if key not in exp["body"]:
                    continue
                ev = err_text(exp["body"][key])
                av = err_text(ab.get(key)) if ab is not None else (msg_text(act) if key == "message" else "")
                if key == "errors":
                    if exp["body"][key] is None:
                        continue
                    if exp["body"][key] == [] and av:
                        d.append(("fail", f"errors expected empty, got {av!r}"))
                        continue
                    if not ev:
                        continue
                if not msg_equal(ev, av, bij):
                    d.append(("fail", f"{key} {ev!r} expected, got {av!r}"))
        if act.get("unsettled"):
            d.append(("fail", "repo state did not settle (8 equal reads) within 25 s"))
        if act.get("first_read_differs"):
            d.append(("fail", f"first read {act['first_read_differs']['first']} differs from the settled "
                              f"{act['first_read_differs']['settled']} (--strict-first-read)"))
        for h, v in exp.get("headers", {}).items():
            if h in skip_headers:
                continue
            got = act.get("headers", {}).get(h)
            if got is None:
                d.append(("fail", f"header {h}: expected {v!r}, missing"))
            else:
                eq_str(v, got, bij, d, f"header {h}")
        volatile = set(exp.get("volatile", [])) | set(extra_volatile) | {"!" + k for k in exp.get("strict_keys", [])}
        if es >= 400 or act["status"] >= 400:
            volatile |= {"message", "errors"}  # top-level error text: compared above (or by a departure)
        if "body" in exp:
            if "body" not in act:
                d.append(("fail", f"expected JSON body, got {act.get('body_text', '')[:120]!r}"))
            else:
                cmp_json(exp["body"], act["body"], "", d, volatile, bij)
        elif "body_text" in exp and "$text" not in volatile:
            if "body_text" not in act:
                d.append(("fail", f"expected text body, got JSON {J.dumps(act.get('body'))[:120]}"))
            else:
                eq_str(exp["body_text"], act["body_text"], bij, d, "text body")
        if "body_prefix_hex" in exp and exp["body_prefix_hex"] != act.get("body_prefix_hex"):
            d.append(("fail", f"body prefix {exp['body_prefix_hex']} expected, got {act.get('body_prefix_hex')}"))
        if "archive" in exp:
            if not act.get("archive"):
                d.append(("fail", f"archive entries expected, got {act.get('archive_error', 'none')}"))
            else:
                ea, aa = exp["archive"], act["archive"]
                if len(ea) != len(aa):
                    d.append(("fail", f"archive has {len(aa)} entries, {len(ea)} expected: "
                                      f"{[x['name'] for x in aa][:6]}"))
                for x, y in zip(ea, aa):
                    if not eq_str(x["name"], y["name"], bij, [], ""):
                        d.append(("fail", f"archive entry {x['name']!r} expected, got {y['name']!r}"))
                    elif (x["size"], x["sha256"]) != (y["size"], y["sha256"]):
                        d.append(("fail", f"archive entry {x['name']!r}: size/hash {x['size']}/{(x['sha256'] or '')[:8]} "
                                          f"expected, got {y['size']}/{(y['sha256'] or '')[:8]}"))
    text = msg_text(act).lower()
    for w in exp.get("must_contain", []):
        if w.lower() not in text:
            d.append(("fail", f"message lacks {w!r}: {text[:200]!r}"))
    return d


# ---- departures: reviewed, intentional differences from the recorded Gitea behaviour

def dep_indexes(spec, expected):
    if isinstance(spec, bool):
        return []
    if isinstance(spec, int):
        return [spec]
    if isinstance(spec, list):
        return [i for x in spec for i in dep_indexes(x, expected)]
    m = re.fullmatch(r"(\d+)-(\d+)", str(spec))
    if m:
        return list(range(int(m.group(1)), int(m.group(2)) + 1))
    return [i for i, e in enumerate(expected) if e.get("name") == spec or e.get("key") == spec]


EXPECT_KEYS = {
    "http": {"status", "message_contains", "fields", "ignore_fields", "ignore_headers", "ignore_body", "skip"},
    "git": {"ok", "message_contains", "skip"},
    "note": {"value", "value_prefix", "skip"},
}


def ex_ident(ex):
    """What an exchange is: `METHOD /path/template`, the git step name, or the note key."""
    if ex["kind"] == "http":
        return f"{ex['method']} {ex['path']}"
    return ex["name"] if ex["kind"] == "git" else ex["key"]


def load_departures(path, scenario_ids):
    """Read and validate departures.json; any problem is a load error (SystemExit)."""
    deps = J.load(open(path))
    seen, errs = {}, []
    if not isinstance(deps, list):
        raise SystemExit(f"{path}: expected a JSON list")
    for n, d in enumerate(deps):
        where = f"{path}[{n}]"
        if d.get("scenario") not in scenario_ids:
            errs.append(f"{where}: unknown scenario {d.get('scenario')!r}")
            continue
        e = d.get("expect")
        if not isinstance(e, dict) or not e:
            errs.append(f"{where}: expect must be a non-empty object")
            continue
        kind = d.get("kind")
        allowed = EXPECT_KEYS.get(kind, set().union(*EXPECT_KEYS.values()))
        if set(e) - allowed:
            errs.append(f"{where}: expect key(s) {sorted(set(e) - allowed)} do not apply to a {kind} exchange "
                        f"(allowed: {sorted(allowed)})")
        if not d.get("reason"):
            errs.append(f"{where}: reason is required")
        if d.get("kind") not in ("http", "git", "note"):
            errs.append(f"{where}: kind must be http, git or note")
        sts = e.get("status")
        sts = sts if isinstance(sts, list) else ([sts] if sts is not None else [])
        if (any(x >= 400 for x in sts) or e.get("ok") is False) and not e.get("message_contains"):
            errs.append(f"{where}: an expected refusal (status >= 400 or git ok:false) needs message_contains")
        spec = d.get("exchange")
        idx = None
        if isinstance(spec, int) and not isinstance(spec, bool):
            idx = [spec]
            m = d.get("match")
            if not m:
                errs.append(f"{where}: a single-index entry needs `match` (METHOD /path, git step name or note key)")
            elif d.get("kind") == "http" and not re.match(r"^[A-Z]+ /", m):
                errs.append(f"{where}: http `match` must look like 'METHOD /path'")
        elif isinstance(spec, (list, str)) and (isinstance(spec, list) or re.fullmatch(r"\d+-\d+", spec)):
            idx = dep_indexes(spec, [])
            if len(d.get("matches") or []) != len(idx):
                errs.append(f"{where}: a range or list needs `matches` with one entry per exchange ({len(idx)})")
        elif not isinstance(spec, str):
            errs.append(f"{where}: bad exchange {spec!r}")
        elif d.get("kind") == "http":
            errs.append(f"{where}: a name can only select a git step or a note")
        for i in idx or []:
            if (d["scenario"], i) in seen:
                errs.append(f"{where}: duplicate entry for {d['scenario']}#{i} (also {seen[(d['scenario'], i)]})")
            seen[(d["scenario"], i)] = where
    if errs:
        raise SystemExit("departures.json is invalid:\n  " + "\n  ".join(errs))
    return deps


def dget(b, path):
    for part in path.split("."):
        if isinstance(b, list):
            b = b[int(part)] if part.isdigit() and int(part) < len(b) else None
        elif isinstance(b, dict):
            b = b.get(part)
        else:
            return None
    return b


def apply_override(exp, act, ov, bij, match=None):
    """Check `act` against a departure instead of the recorded exchange.

    The exchange must be the one the entry names (kind and `match`), skip included. Targeted checks (status,
    message_contains, ok, value, fields) run next; message_contains applies to refusals (status >= 400, or any
    git output) and `fields` to successful bodies. The recorded body is still compared strictly when the entry
    only names `ignore_fields`/`fields`, so a departure never widens more than it says."""
    e, why, d = ov["expect"], ov.get("reason", ""), []
    match = match if match is not None else ov.get("match")
    if act["kind"] != ov["kind"] or (match and not eq_str(match, ex_ident(act), bij, [], "")):
        return [("fail", f"departure for {ov['kind']} {match!r} applied to a different exchange: {ex_ident(act)!r}")]
    if e.get("skip"):
        return [("honoured", f"skipped: {why}")]
    if act["kind"] == "note":
        if "value" in e and not eq_val(e["value"], act["value"], bij):
            d.append(("fail", f"unexpected: note {act['key']} {e['value']!r} expected, got {act['value']!r}"))
        if "value_prefix" in e and not (isinstance(act["value"], str) and act["value"].startswith(e["value_prefix"])):
            d.append(("fail", f"unexpected: note {act['key']} should start with {e['value_prefix']!r}, got {act['value']!r}"))
    elif act["kind"] == "git":
        # a departure replaces the outcome, never the command: the step must still run the recorded line
        bij.new_exchange()
        if exp.get("cmd") is not None and not eq_str(exp["cmd"], act["cmd"], bij, [], ""):
            return [("fail", f"git command {exp['cmd']!r} expected, got {act['cmd']!r}")]
        if "ok" in e and act["ok"] != e["ok"]:
            d.append(("fail", f"unexpected: git ok={e['ok']} expected, got {act['ok']}: {act['output'][:160]!r}"))
        txt = act["output"].lower()
        for w in e.get("message_contains", []):
            if w.lower() not in txt:
                d.append(("fail", f"unexpected: output lacks {w!r}: {txt[-160:]!r}"))
    else:
        sts = e.get("status")
        sts = sts if isinstance(sts, list) else ([sts] if sts is not None else None)
        if sts is not None and act["status"] not in sts:
            d.append(("fail", f"unexpected: status {sts} expected, got {act['status']}: {msg_text(act)[:160]!r}"))
        txt = msg_text(act).lower()
        if act["status"] >= 400:
            for w in e.get("message_contains", []):
                if w.lower() not in txt:
                    d.append(("fail", f"unexpected: message lacks {w!r}: {txt[:160]!r}"))
        if act["status"] < 400:
            for k, v in (e.get("fields") or {}).items():
                body = act.get("body")
                got = len(body) if k == "$len" and isinstance(body, list) else dget(body, k)
                if got != v:
                    d.append(("fail", f"unexpected: {k} {v!r} expected, got {got!r}"))
        pins = list((e.get("fields") or {}))
        status_ok = sts is None or act["status"] in sts
        if status_ok:
            # everything the entry does not replace is still compared: headers (minus `ignore_headers`), the body
            # minus `ignore_fields` and the pinned keys, or no body at all only with an explicit `ignore_body`
            if e.get("ignore_body"):
                saved = exp
                exp = {k: v for k, v in exp.items() if k not in ("body", "body_text", "body_prefix_hex", "archive")}
            skip = list(e.get("ignore_fields") or []) + [k for k in pins if k != "$len"]
            d += [x for x in cmp_exchange(exp, act, bij, extra_volatile=skip,
                                          status_override=act["status"] if sts is not None else None,
                                          skip_headers=tuple(e.get("ignore_headers") or [])) if x[0] == "fail"]
    return d or [("honoured", why)]


# --------------------------------------------------------------------------- context

class Ctx:
    def __init__(self, base, admin_token, mode):
        self.base = base.rstrip("/")
        self.hostport = urllib.parse.urlparse(self.base).netloc
        self.mode = mode
        self.secrets = {admin_token}
        self.pw = {}
        self.vars = {}
        self.tmp = None
        self.admin_user = "siteadmin"
        bad = secrets.token_hex(20)
        self.secrets.add(bad)
        self.principals = {
            "none": None,
            "bad": {"kind": "token", "user": "nobody", "secret": bad},
            "admin": {"kind": "token", "user": "siteadmin", "secret": admin_token},
        }
        self.recording = True
        self.reset_scenario()
        self.ex = []
        self.expected = []
        self.cursor = 0
        self.diffs = []  # (scenario, index, label, [(level, text)])
        self.overrides = {}  # fixture index -> departure entry, check mode only
        self.defers = {}  # fixture index -> exchange identity: runs, but a mismatch waits for a later slice
        self.verbose = False
        self.base_ready = False
        self.first_read = None
        self.strict_first_read = False
        self.include_web = False
        self.web_skipped = 0
        r = self.call("GET", "/user", rec=False)
        if r.status != 200 or not r.json:
            raise SystemExit(f"admin token rejected by {self.base}: {r.status} {r.text[:200]}")
        self.admin_user = r.json["login"]
        self.principals["admin"]["user"] = self.admin_user
        self.principals["admin-basic"] = dict(self.principals["admin"], kind="basic")
        self.principals["admin-bearer"] = dict(self.principals["admin"], kind="bearer")
        # last: nothing above may exit with a temp dir to leak (cmd_run removes it in a finally)
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="sc-conf-"))
        os.makedirs(self.tmp + "/home")

    # -- normalization
    def sha_ph(self, h):
        return "<sha#%d>" % self.sha_ord.setdefault(h, len(self.sha_ord) + 1)

    def id_ph(self, space, v):
        m = (self.id_ord if space.startswith("path:") else self.id_local).setdefault(space, {})
        return "<id:%s#%d>" % (space, m.setdefault(v, len(m) + 1))

    def scrub(self, s):
        for sec in sorted(self.secrets, key=len, reverse=True):
            if sec:
                s = s.replace(sec, "<token>")
        s = s.replace(self.base, "<base>").replace(self.hostport, "<host>")
        if self.tmp:
            s = s.replace(self.tmp, "<tmp>")
        return re.sub(r"\b%s\b" % re.escape(self.admin_user), "<admin>", s)

    def ns(self, s):
        s = re.sub(r"https?(://)[^/@\s\"':?#]*:[^/@\s\"'?#]*@", r"http\1<creds>@", self.scrub(s))  # user:password@ only (ssh://git@ stays); https checks like http
        # pkt-line adverts glue a 4-hex length in front of the id ("0146<sha> HEAD"), so \b misses it
        s = re.sub(r"[0-9a-f]{40}(?= (?:HEAD|refs/|capabilities))", lambda m: self.sha_ph(m.group(0)), s)
        s = SHA_RE.sub(lambda m: self.sha_ph(m.group(0)), s)
        s = SHORT_RE.sub("<short>..<short>", s)
        # the SSH authority is derived from the server's own SSH config (ssh://git@localhost:2222/x.git or
        # git@host:x.git); keep the repo path, drop the host, so a server without SSH compares equal
        s = re.sub(r"ssh://[^/\s\"']+/", "ssh://<ssh-authority>/", s)
        s = re.sub(r"(?<![\w/@.-])[\w.-]+@[\w.-]+:(?=[\w.-]+/[\w.-]+\.git\b)", "<ssh-authority>:", s)
        # database counters inside URL fragments (`#issuecomment-7`) depend on everything created before
        s = re.sub(r"#(issuecomment|issue|event)-(\d+)", lambda m: f"#{m.group(1)}-" + self.id_ph("fragment:" + m.group(1), int(m.group(2))), s)
        return RFC_RE.sub("<ts>", TS_RE.sub("<ts>", s))

    def nj(self, v):
        # register shas/ids in sorted-key order first so numbering does not depend on key order;
        # body ids are numbered per call (see Bij), path ids and shas per scenario
        self.id_local = {}
        self._nj(sort_keys(v), (), None)
        return self._nj(v, (), None)

    def _nj(self, v, path, key):
        if isinstance(v, dict):
            return {k: self._nj(x, path + (k,), k) for k, x in v.items()}
        if isinstance(v, list):
            return [self._nj(x, path, key) for x in v]
        if isinstance(v, str):
            return "<token>" if key in TOKEN_KEYS else self.ns(v)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and key and (key in ("id", "uid") or key.endswith("_id")):
            return self.id_ph(".".join(path), v)
        return v

    def np(self, p):
        path, _, q = p.partition("?")
        segs, out = path.split("/"), []
        for i, s in enumerate(segs):
            m = re.fullmatch(r"(\d+)(\.[a-z]+)?", s)
            if m and not SHA_RE.fullmatch(s):
                out.append(self.id_ph("path:" + (segs[i - 1] if i else ""), int(m.group(1))) + (m.group(2) or ""))
            else:
                out.append(self.ns(s))
        return "/".join(out) + ("?" + self.ns(q) if q else "")

    def reset_scenario(self):
        self.sha_ord, self.id_ord, self.id_local, self.bij = {}, {}, {}, Bij()

    # -- recording
    def push_ex(self, ex):
        if not self.recording:
            return
        i = len(self.ex)
        self.ex.append(ex)
        if self.mode == "check":
            if i >= len(self.expected):
                self.diffs.append((i, ex_label(ex), [("fail", "extra exchange not present in fixture")]))
            else:
                exp = self.expected[i]
                if i in self.overrides:
                    ds = apply_override(exp, ex, self.overrides[i], self.bij)
                else:
                    ds = cmp_exchange(exp, ex, self.bij)
                if i in self.defers:
                    bad = [x for x in ds if x[0] == "fail"]
                    if ex_ident(exp) != ex_ident(ex) or exp["kind"] != ex["kind"]:
                        # a deferral waits for a later slice's *answer*; the call itself stays pinned
                        ds = [("fail", f"deferred exchange is {ex_ident(exp)!r} in the fixture but the scenario made {ex_ident(ex)!r}")]
                    else:
                        ds = ([("honoured", "deferred: this route belongs to a later slice")] if bad else
                              [("fail", "deferred exchange now passes: remove it from the pending file")])
                self.diffs.append((i, ex_label(ex), ds))

    def note(self, key, value, strict=True):
        self.push_ex({"kind": "note", "key": key, "value": value, "strict": strict})

    def new_password(self):
        p = secrets.token_hex(12)
        self.secrets.add(p)
        return p

    # -- HTTP
    def call(self, method, path, json=None, as_="admin", expect=None, must_contain=None,
             volatile=None, headers=None, data=None, api=True, binary=False, rec=True, track=(),
             retry_while=None, retry_s=90, no_retry=False, settle_keys=None, tags=(), strict_keys=()):
        full = ("/api/v1" + path) if api else path
        if "web" in tags and self.mode == "check" and not self.include_web and rec:
            # Gitea web UI route (sc-forge has no web UI): keep the slot so exchange indexes stay aligned
            self.web_skipped += 1
            self.push_ex({"kind": "http", "method": method, "path": self.np(full), "auth": as_, "status": 0,
                          "headers": {}, "tags": list(tags), "skipped": True})
            return R(0, {}, b"")
        hdrs = {"Accept": "application/json", "User-Agent": "sc-forge-conformance"}
        p = self.principals[as_]
        if p:
            if p["kind"] == "token":
                hdrs["Authorization"] = "token " + p["secret"]
            elif p["kind"] == "bearer":
                hdrs["Authorization"] = "Bearer " + p["secret"]
            elif p["kind"] == "basic-nopass":  # the token as the Basic user name, empty password
                hdrs["Authorization"] = "Basic " + base64.b64encode(f"{p['secret']}:".encode()).decode()
            else:
                hdrs["Authorization"] = "Basic " + base64.b64encode(f"{p['user']}:{p['secret']}".encode()).decode()
        if json is not None:
            data = J.dumps(json).encode()
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        if retry_while is None and method == "POST" and path.endswith("/merge") and not no_retry:
            retry_while = ["try again later"]
        def send():
            req = urllib.request.Request(self.base + full, data=data, method=method, headers=hdrs)
            try:
                with OPENER.open(req, timeout=120) as resp:
                    return R(resp.status, dict(resp.headers), resp.read())
            except urllib.error.HTTPError as e:
                return R(e.code, dict(e.headers), e.read())

        deadline = time.time() + retry_s
        while True:
            r = send()
            # `retry_while`: re-send while the response text has one of these markers, and record only the
            # last response (used for Gitea's "Please try again later" while a PR is being checked)
            if not retry_while or time.time() >= deadline or not any(w in r.text.lower() for w in retry_while):
                break
            time.sleep(1)
        unsettled, first_differs = False, None
        if settle_keys and r.status == 200 and r.is_json:
            # Gitea updates some repo fields (empty, default_branch) asynchronously after a push: record the
            # value that is stable on 8 consecutive reads (4 s, <= 25 s); the first read is left in `first_read`
            def proj(x):
                def get(b, k):
                    for part in k.split("."):
                        b = b.get(part) if isinstance(b, dict) else None
                    return b
                return [get(x.json, k) for k in settle_keys] if x.is_json else None
            hist = [proj(r)]
            self.first_read = dict(zip(settle_keys, hist[0]))
            end = time.time() + 25
            stable = lambda: len(hist) >= 8 and all(h == hist[-1] for h in hist[-8:])  # noqa: E731
            while time.time() < end and not stable():
                time.sleep(0.5)
                r = send()
                hist.append(proj(r))
            unsettled = not stable()
            if self.strict_first_read and hist[0] != hist[-1]:
                first_differs = {"first": dict(zip(settle_keys, hist[0])), "settled": dict(zip(settle_keys, hist[-1]))}
        if rec:
            ex = {"kind": "http", "method": method, "path": self.np(full), "auth": as_,
                  "status": r.status}
            if json is not None:
                ex["request"] = self.nj(json)
            hd = {h: self.ns(r.headers[h]).replace(" ", "").lower() if h == "content-type" else self.ns(r.headers[h])
                  for h in TRACKED_HEADERS + tuple(track) if h in r.headers}
            ex["headers"] = hd
            if r.is_json and (not binary or r.status >= 300):
                ex["body"] = self.nj(r.json)
            elif binary:
                ex["body_prefix_hex"] = r.data[:4].hex()
                if r.status == 200:
                    ex.update(self.archive_entries(r.data))
            else:
                ex["body_text"] = self.ns(r.text[:3000]).replace("\x00", "\\0")
            for k, v in (("must_contain", must_contain), ("volatile", volatile)):
                if v:
                    ex[k] = list(v)
            if tags:
                ex["tags"] = list(tags)
            if strict_keys:  # keys of DEFAULT_VOLATILE that this (settled) exchange asserts by value
                ex["strict_keys"] = list(strict_keys)
            if unsettled:
                ex["unsettled"] = True
            if first_differs:
                ex["first_read_differs"] = first_differs
            self.push_ex(ex)
            if unsettled and self.mode == "record":
                raise SetupError(f"{method} {full}: value did not settle within 25 s")
        # `expect` guards the scenario's own preconditions. A recorded exchange is the thing under test, so in
        # check mode a different answer is a diff to report, never an abort.
        if expect is not None and (self.mode == "record" or not rec):
            ok = expect if isinstance(expect, (list, tuple, set)) else [expect]
            if r.status not in ok:
                raise SetupError(f"{method} {full}: expected {sorted(ok)}, got {r.status}: {r.text[:300]}")
        return r

    def archive_entries(self, data):
        """Normalized entry names, sizes and content hashes of a zip or tar.gz, so a bare signature fails."""
        try:
            if data[:2] == b"PK":
                z = zipfile.ZipFile(io.BytesIO(data))
                ents = [(i.filename, 0 if i.is_dir() else i.file_size, None if i.is_dir() else hashlib.sha256(z.read(i)).hexdigest())
                        for i in z.infolist()]
            elif data[:2] == b"\x1f\x8b":
                t = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
                ents = [(m.name, 0 if m.isdir() else m.size, None if m.isdir() else hashlib.sha256(t.extractfile(m).read()).hexdigest())
                        for m in t.getmembers() if m.isfile() or m.isdir()]
            else:
                return {"archive_error": "not a zip or tar.gz"}
        except Exception as e:  # noqa: BLE001
            return {"archive_error": f"unreadable archive: {type(e).__name__}"}
        return {"archive": sorted(({"name": self.ns(n), "size": sz, "sha256": h} for n, sz, h in ents), key=lambda x: x["name"])}

    # -- git
    def git_url(self, repo, who="admin", user=None, secret=None, org="acme"):
        p = self.principals[who]
        u, s = (p["user"] if user is None else user), (secret if secret is not None else p["secret"])
        host = self.base.split("://", 1)
        auth = f"{urllib.parse.quote(u, safe='')}:{urllib.parse.quote(s, safe='')}@" if (u or s) else ""
        return f"{host[0]}://{auth}{host[1]}/{org}/{repo}.git"

    def git(self, args, cwd=None, name=None, rec=True, ok=None, must_contain=None, extra_header=None,
            env_extra=None, note_stdout=False):
        pre = ["-c", "credential.helper=", "-c", "advice.detachedHead=false", "-c", "init.defaultBranch=main",
               "-c", "user.name=Conf", "-c", "user.email=conf@example.invalid", "-c", "commit.gpgsign=false"]
        if extra_header:
            pre += ["-c", "http.extraHeader=" + extra_header[1]]
            self.secrets.update({extra_header[1], extra_header[1].split()[-1]})
        env = {"PATH": os.environ.get("PATH", ""), "HOME": self.tmp + "/home", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
        env.update(env_extra or {})
        try:
            p = subprocess.run(["git"] + pre + args, cwd=cwd, env=env, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired:  # str(e) would carry the command line with credentials
            raise SetupError(f"git {' '.join(self.ns(a) for a in args)}: timed out after 180 s") from None
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        if rec:
            cmd = "git " + (f"-c http.extraHeader=<{extra_header[0]}> " if extra_header else "") + " ".join(args)
            ex = {"kind": "git", "name": name or args[0], "cmd": self.ns(cmd), "ok": p.returncode == 0,
                  "output": self.ns(out.strip()[-2000:])}
            if must_contain:
                ex["must_contain"] = list(must_contain)
            if p.returncode != 0:
                ex["refusal"] = refusal_lines(ex["output"])
            self.push_ex(ex)
            if note_stdout:
                self.note(f"{ex['name']}_stdout", self.ns(p.stdout.decode("utf-8", "replace").strip()))
        want = ok if ok is not None else (None if rec else True)
        if want is not None and (p.returncode == 0) != want:
            raise SetupError(f"git {' '.join(self.ns(a) for a in args)}: exit {p.returncode}: {self.ns(out)[-400:]}")
        return p.returncode == 0, out.strip()

    def wc(self, repo, who="admin", org="acme"):
        path = f"{self.tmp}/wc-{org}-{repo}-{who}"  # one clone per principal: `origin` embeds that principal's token
        if not os.path.isdir(path):
            self.git(["clone", self.git_url(repo, who, org=org), path], rec=False)
        return path

    def push_branch(self, repo, branch, files, base="origin/main", msg=None, who="admin", org="acme"):
        """Commit `files` on `branch` (from rev `base`, or from nothing when None) and push it. Returns the sha."""
        p = self.wc(repo, who, org)
        self.git(["fetch", "origin"], cwd=p, rec=False)
        if base is None:
            self.git(["symbolic-ref", "HEAD", f"refs/heads/{branch}"], cwd=p, rec=False)
        else:
            self.git(["checkout", "-q", "-B", branch, base], cwd=p, rec=False)
        for rel, content in files.items():
            fp = os.path.join(p, rel)
            os.makedirs(os.path.dirname(fp), exist_ok=True)
            with open(fp, "w") as f:
                f.write(content)
        self.git(["add", "-A"], cwd=p, rec=False)
        self.git(["commit", "-q", "-m", msg or f"commit on {branch}"], cwd=p, rec=False)
        self.git(["push", "-q", "-f", "origin", f"{branch}:{branch}"], cwd=p, rec=False)
        return self.git(["rev-parse", "HEAD"], cwd=p, rec=False)[1]

    def head(self, repo, branch="main", org="acme"):
        return self.call("GET", f"/repos/{org}/{repo}/branches/{branch}", rec=False, expect=200).json["commit"]["id"]

    def mk_user(self, name, rec=False):
        pw = self.new_password()
        r = self.call("POST", "/admin/users", {"username": name, "email": f"{name}@example.invalid", "password": pw,
                                               "must_change_password": False}, expect=201, rec=rec)
        self.pw[name] = pw
        return r

    def mk_token(self, user, name, scopes, principal, rec=False):
        self.principals[f"{user}-basic"] = {"kind": "basic", "user": user, "secret": self.pw[user]}
        r = self.call("POST", f"/users/{user}/tokens", {"name": name, "scopes": scopes}, as_=f"{user}-basic",
                      expect=201, rec=rec)
        tok = r.json["sha1"]
        self.secrets.add(tok)
        self.principals[principal] = {"kind": "token", "user": user, "secret": tok}
        return r

    def mk_repo(self, name, auto_init=True, org="acme", collab=None, rec=False, default_branch="main"):
        body = {"name": name, "private": True, "auto_init": auto_init, "default_branch": default_branch}
        if auto_init:
            body["readme"] = "Default"
        self.call("POST", f"/orgs/{org}/repos", body, expect=201, rec=rec)
        for u, perm in (collab or {"bot": "write", "alice": "write", "carol": "read"}).items():
            self.call("PUT", f"/repos/{org}/{name}/collaborators/{u}", {"permission": perm}, expect=204, rec=False)

    def api_file(self, repo, path, content, msg="api commit", branch="main", org="acme"):
        r = self.call("POST", f"/repos/{org}/{repo}/contents/{path}", {
            "content": base64.b64encode(content.encode()).decode(), "message": msg, "branch": branch},
            expect=201, rec=False)
        return r.json["commit"]["sha"]


def ex_label(ex):
    if ex["kind"] == "http":
        return f"{ex['method']} {ex['path']} -> {ex['status']}"
    if ex["kind"] == "git":
        return f"git {ex['name']}: {ex['cmd'][:100]}"
    return f"note {ex['key']}"


def ensure_base(c):
    """Idempotent, unrecorded: users, org and tokens that most scenarios need."""
    if c.base_ready:
        return
    for u in USERS:
        if u not in c.pw:
            if c.call("GET", f"/users/{u}", rec=False).status == 404:
                c.mk_user(u)
            else:
                raise SetupError(f"user {u} exists with an unknown password: use a fresh server")
    if c.call("GET", "/orgs/acme", rec=False).status == 404:
        c.call("POST", "/orgs", {"username": "acme", "full_name": "Acme", "visibility": "private"}, expect=201, rec=False)
    for u in USERS:
        if u not in c.principals:
            c.mk_token(u, "conf-all", ["all"], u)
    if "bot-scoped" not in c.principals:
        c.mk_token("bot", "conf-scoped", ["read:user", "read:organization", "write:repository"], "bot-scoped")
    if "alice-ro" not in c.principals:
        c.mk_token("alice", "conf-ro", ["read:repository"], "alice-ro")
    # token-as-Basic-password principals for git smart HTTP endpoints (`<name>-tokbasic`)
    for who in ("admin", "bad") + USERS:
        c.principals[f"{who}-tokbasic"] = dict(c.principals[who], kind="basic")
    c.principals["oauth2-tokbasic"] = dict(c.principals["admin"], kind="basic", user="oauth2")
    c.base_ready = True


# --------------------------------------------------------------------------- runner

SCENARIOS = []


def scenario(sid, slug, base=True):
    def deco(fn):
        SCENARIOS.append((sid, slug, base, fn))
        return fn
    return deco


SECRET_PATTERNS = (re.compile(r"://[^/@\s\"']+:[^/@\s\"']*@"), re.compile(r"Authorization: ?(?:Basic|Bearer|token) +[A-Za-z0-9+/=_.-]{6,}", re.I),
                   re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])"))


def scan_fixtures(out, secret_values):
    """Fail on anything credential-shaped in the recorded files: URL userinfo, auth headers, raw 40-hex ids, known secrets."""
    hits = []
    for f in sorted(os.listdir(out)):
        if not f.endswith(".json"):
            continue
        text = open(os.path.join(out, f)).read()
        for pat in SECRET_PATTERNS:
            m = pat.search(text)
            if m:
                hits.append(f"{f}: matches {pat.pattern[:40]!r}: {m.group(0)[:30]!r}")
        for sec in secret_values:
            if len(sec) >= 8 and sec in text:
                hits.append(f"{f}: contains a secret value ({sec[:3]}...)")
    return hits


def dump_fixture(obj, f):
    """Write a scenario fixture compactly: the header keys on one line, then one exchange per line, so a
    diff still reads per exchange but the file is roughly half the size of indented JSON."""
    head = {k: v for k, v in obj.items() if k != "exchanges"}
    h = J.dumps(head, separators=(",", ":"))[:-1]
    f.write(h + (',' if head else '') + '"exchanges":[\n')
    f.write(",\n".join(J.dumps(e, separators=(",", ":")) for e in obj["exchanges"]))
    f.write("\n]}\n")


def run_all(c, only, out=None, fixtures=None, departures=(), pending=None):
    """Run every scenario in order (they read earlier state); `only` filters what is reported/written.

    `pending` (check only) maps a scenario id to the number of leading exchanges the server under test is expected
    to answer, or to [number, text]; later exchanges need routes from a slice that is not built yet. The run must stop
    exactly there, and with a text the stop error must contain it (so an F1 step failing at the same index is not hidden)."""
    summary = []
    pending = pending or {}
    for sid, slug, needs_base, fn in SCENARIOS:
        selected = not only or sid in only
        fname = f"{sid}-{slug}.json"
        c.ex, c.cursor, c.diffs = [], 0, []
        c.reset_scenario()
        c.expected, skip, stale, deferred, ndeferred, stop = [], None, [], None, 0, None
        c.overrides, c.web_skipped, c.defers = {}, 0, {}
        if c.mode == "check" and selected:
            fp = os.path.join(fixtures, fname)
            if not os.path.exists(fp):
                summary.append((sid, slug, "FAIL", ["no fixture " + fname]))
                continue
            fx = J.load(open(fp))
            c.expected = fx["exchanges"]
            skip = fx.get("error")
            for dep in departures:
                if dep["scenario"] != sid:
                    continue
                idx = dep_indexes(dep["exchange"], c.expected)
                bad = [i for i in idx if not 0 <= i < len(c.expected)]
                if not idx or bad:
                    stale.append(f"stale departure {dep['exchange']!r}: no such exchange in {fname} ({dep.get('reason', '')})")
                matches = dep.get("matches") or ([dep["match"]] if dep.get("match") and len(idx) == 1 else [None] * len(idx))
                for k, i in enumerate(idx):
                    if i in bad:
                        continue
                    got = ex_ident(c.expected[i])
                    if (matches[k] and matches[k] != got) or c.expected[i]["kind"] != dep["kind"]:
                        stale.append(f"stale departure #{i}: fixture exchange is {c.expected[i]['kind']} {got!r}, "
                                     f"departure says {dep['kind']} {matches[k]!r}")
                        continue
                    if i in c.overrides:
                        stale.append(f"duplicate departure for #{i} ({dep.get('reason', '')})")
                        continue
                    rs, sts = c.expected[i].get("status"), dep["expect"].get("status")
                    sts = sts if isinstance(sts, list) else ([sts] if sts is not None else [])
                    if rs is not None and any((x >= 400) != (rs >= 400) for x in sts) and not dep["expect"].get("ignore_body"):
                        stale.append(f"departure #{i} changes the status class (recorded {rs}, expects {sts}): its body "
                                     f"cannot match the recorded one, so it needs ignore_body with a reason")
                        continue
                    c.overrides[i] = dict(dep, match=matches[k] or got)
            for i, ident in (pending.get(sid) or {}).get("defer", []) if isinstance(pending.get(sid), dict) else []:
                if not 0 <= i < len(c.expected) or ex_ident(c.expected[i]) != ident:
                    stale.append(f"stale defer #{i}: {fname} has {ex_ident(c.expected[i])!r} there, the pending file says {ident!r}"
                                 if 0 <= i < len(c.expected) else f"stale defer #{i}: {fname} has no such exchange")
                else:
                    c.defers[i] = ident
            spec = pending.get(sid)
            if isinstance(spec, dict):  # {"stop": [N, text], "defer": [[index, "METHOD /path"], ...]}
                spec = spec.get("stop")
            if spec is not None:
                deferred, stop = spec if isinstance(spec, list) else (spec, None)
                ndeferred = max(0, len(c.expected) - deferred)
                if not 0 <= deferred < len(c.expected):
                    # nothing is deferred: the entry is stale (the scenario is whole) and must not hide an error
                    stale.append(f"stale pending entry {deferred}: {fname} has {len(c.expected)} exchanges, "
                                 f"so nothing is deferred; remove the entry")
                    deferred = None
                else:
                    c.expected = c.expected[:deferred]
        t0 = time.time()
        err = None
        try:
            if needs_base:
                ensure_base(c)
            fn(c)
        except Exception as e:  # noqa: BLE001 - scenario failures are data
            err = c.ns(f"{type(e).__name__}: {e}")[:1500]
        dt = time.time() - t0
        if not selected:
            continue
        if c.mode == "record":
            os.makedirs(out, exist_ok=True)
            with open(os.path.join(out, fname), "w") as f:
                dump_fixture({"scenario": sid, "title": slug, "error": err, "exchanges": c.ex}, f)
            summary.append((sid, slug, "ERROR" if err else "ok", [err] if err else [], len(c.ex), dt))
            continue
        lines, nfail = [], 0
        for i, label, ds in c.diffs:
            bad = [x for x in ds if x[0] == "fail"]
            hon = [x for x in ds if x[0] == "honoured"]
            nfail += bool(bad)
            if bad or hon or ds or c.verbose:
                tag = "FAIL" if bad else ("ok* " if hon else ("warn" if ds else "ok  "))
                lines.append(f"  {tag} #{i:02d} {label}")
                lines += [f"       {'expected difference honoured' if lv == 'honoured' else lv}: {t}" for lv, t in ds]
        # unpaired exchanges and errors: each counts as a failed exchange
        missing = len(c.expected) - len(c.ex)
        if err and deferred is not None and len(c.ex) == deferred and (stop is None or stop in err):
            lines.append(f"  (pending: {ndeferred} later exchange(s) need a later slice; the scenario stopped at #{deferred}: {err[:100]})")
        elif err:
            if skip and norm_msg(skip) == norm_msg(err):
                lines.append(f"  (fixture recorded the same error: {skip[:200]})")
            else:
                nfail += 1
                lines.append(f"  ERROR {err}" + ("" if skip else "  (the fixture recorded no error)"))
                if skip:
                    lines.append(f"  fixture recorded a different error: {skip[:300]}")
        elif skip and deferred is None:
            nfail += 1
            lines.append(f"  FAIL fixture recorded an error but the scenario completed: {skip[:300]}")
        elif deferred is not None and ndeferred:
            nfail += 1
            lines.append(f"  FAIL the scenario completed but {ndeferred} exchange(s) are listed as pending: update the pending file")
        if missing > 0:
            nfail += missing
            lines.append(f"  FAIL {missing} recorded exchange(s) not produced (fixture has {len(c.expected)}, run made {len(c.ex)})")
        if stale:
            nfail += len(stale)
            lines += ["  FAIL " + x for x in stale]
        summary.append((sid, slug, "FAIL" if nfail else "ok", lines, len(c.ex), dt, nfail, c.web_skipped, ndeferred))
    return summary


def cmd_run(a):
    ids = {x[0] for x in SCENARIOS}
    only = set(a.only.split(",")) if a.only else None
    if only and only - ids:
        print(f"unknown scenario id(s) {sorted(only - ids)}; known: {sorted(ids)}", file=sys.stderr)
        return 2
    deps = load_departures(a.departures, ids) if getattr(a, "departures", None) else []
    c = Ctx(a.base_url, a.admin_token, a.cmd)
    c.strict_first_read = getattr(a, "strict_first_read", False)
    c.include_web = getattr(a, "include_web", False)
    c.verbose = a.verbose
    t0 = time.time()
    leaks = []
    try:
        if a.cmd == "record":
            ver = c.call("GET", "/version", rec=False).json
            summary = run_all(c, only, out=a.out)
            os.makedirs(a.out, exist_ok=True)
            with open(os.path.join(a.out, "meta.json"), "w") as f:
                J.dump({"server_version": ver, "scenarios": sorted(x for x in os.listdir(a.out) if x.endswith(".json") and x != "meta.json")}, f, indent=2)
                f.write("\n")
            leaks = scan_fixtures(a.out, c.secrets)
        else:
            pend = J.load(open(a.pending)) if getattr(a, "pending", None) else {}
            if set(pend) - ids:
                print(f"pending names unknown scenario(s) {sorted(set(pend) - ids)}", file=sys.stderr)
                return 2
            summary = run_all(c, only, fixtures=a.fixtures, departures=deps, pending=pend)
    finally:
        if c.tmp:
            shutil.rmtree(c.tmp, ignore_errors=True)
    bad = 0
    for s in summary:
        sid, slug, st, lines = s[:4]
        extra = f"  ({s[4]} exchanges, {s[5]:.1f}s)" if len(s) > 4 else ""
        print(f"[{sid}] {slug}: {st}{extra}")
        for ln in lines:
            print(ln if a.cmd == "check" else f"  {ln}")
        bad += st in ("FAIL", "ERROR")
    for h in leaks:
        print(f"LEAK {h}")
    nfail = sum(s[6] for s in summary if len(s) > 6)
    web = sum(s[7] for s in summary if len(s) > 7)
    pend_n = sum(s[8] for s in summary if len(s) > 8)
    print(f"\n{len(summary) - bad}/{len(summary)} scenarios ok in {time.time() - t0:.0f}s"
          + (f"; {nfail} failed exchange(s)" if a.cmd == "check" else "")
          + (f"; {web} web exchange(s) skipped (check --include-web runs them)" if web else "")
          + (f"; {pend_n} exchange(s) pending a later slice" if pend_n else "")
          + (f"; {len(leaks)} credential-shaped value(s) in the fixtures" if leaks else ""))
    return 1 if bad or leaks else 0


def load_dir(d):
    out = {}
    for f in sorted(os.listdir(d)):
        if f.endswith(".json") and f != "meta.json":
            out[f] = J.load(open(os.path.join(d, f)))
    return out


def cmd_diff(a):
    A, B, bad = load_dir(a.a), load_dir(a.b), 0
    for f in sorted(set(A) | set(B)):
        if f not in A or f not in B:
            print(f"{f}: only in {'A' if f in A else 'B'}")
            bad += 1
            continue
        ea, eb = A[f]["exchanges"], B[f]["exchanges"]
        print(f"{f}: {len(ea)} vs {len(eb)} exchanges" + (f"  (errors: A={A[f]['error']!r} B={B[f]['error']!r})" if A[f]["error"] or B[f]["error"] else ""))
        bij = Bij()
        for i, (x, y) in enumerate(zip(ea, eb)):
            ds = cmp_exchange(x, y, bij)
            ma, mb = msg_text(x), msg_text(y)
            texty = isinstance(x.get("body"), dict) and "message" in x["body"] or "body_text" in x
            if ma != mb and x["kind"] == "http" and ma and mb and texty:
                ds.append(("info", f"text differs: {ma[:160]!r} vs {mb[:160]!r}"))
            if ds:
                bad += 1
                print(f"  #{i:02d} {ex_label(x)}")
                for lv, t in ds:
                    print(f"       {lv}: {t}")
    print(f"{bad} differing exchange(s)")
    return 1 if bad or {f for f in A} ^ {f for f in B} else 0


def cmd_show(a):
    for f, fx in load_dir(a.dir).items():
        if a.only and not f.startswith(tuple(a.only.split(","))):
            continue
        print(f"== {f}" + (f"  ERROR {fx['error']}" if fx["error"] else ""))
        for i, ex in enumerate(fx["exchanges"]):
            if ex["kind"] == "note":
                print(f"  #{i:02d} note {ex['key']} = {ex['value']!r}")
                continue
            print(f"  #{i:02d} {ex_label(ex)}" + (f"  [{ex.get('auth')}]" if ex["kind"] == "http" else ""))
            if ex["kind"] == "git" and not a.body:
                print(f"       ok={ex['ok']} | " + " / ".join(x.strip() for x in ex["output"].splitlines()[-2:] if x.strip())[:200])
            if a.body:
                if ex["kind"] == "git":
                    print("       " + ex["output"].replace("\n", "\n       ")[:a.limit])
                else:
                    if ex.get("headers"):
                        print(f"       headers {ex['headers']}")
                    b = ex.get("body", ex.get("body_text", ex.get("body_prefix_hex")))
                    print("       " + (J.dumps(b) if not isinstance(b, str) else b)[:a.limit])
            else:
                m = msg_text(ex)
                if m and ex["kind"] == "http" and ex["status"] >= 300:
                    print(f"       {m[:140]}")
    return 0


def cmd_selftest(a):
    """Offline checks of the fixture writer: it round-trips awkward values, and every stored fixture is exactly
    what `dump_fixture` would write (so a hand-edited or re-indented file is caught)."""
    import io
    sample = {"scenario": "Z", "title": "t", "error": "line1\nline2 \u00e4 \"q\"", "exchanges": [
        {"kind": "http", "method": "GET", "path": "/a?b=1&c=\u00e4", "status": 200, "body": {"k": [1, 2.5, None, True, "x\ty"]}},
        {"kind": "note", "key": "n", "value": {"nested": {"a": []}}}]}
    for obj in (sample, dict(sample, exchanges=[])):
        buf = io.StringIO()
        dump_fixture(obj, buf)
        text = buf.getvalue()
        assert J.loads(text) == obj, "round trip"
        assert text.endswith("]}\n"), "ends the object on its own line"
        n = len(obj["exchanges"])
        assert text.count("\n") == (n + 2 if n else 3), "header line, one line per exchange, closing line"
        assert all("\n" not in J.dumps(e) for e in obj["exchanges"])
    # git steps compare the command line too, by placeholder identity
    step = {"kind": "git", "name": "clone", "cmd": "git clone http://<creds>@<host>/acme/a.git <tmp>/w", "ok": True, "output": ""}
    assert not cmp_exchange(step, dict(step), Bij()), "an identical git step matches"
    other = dict(step, cmd="git clone --depth=1 http://<creds>@<host>/acme/a.git <tmp>/w")
    assert any("git command" in t for _, t in cmp_exchange(step, other, Bij())), "changed arguments must fail"
    bad = []
    for d in sorted(os.listdir(a.fixtures_root)):
        full = os.path.join(a.fixtures_root, d)
        if not os.path.isdir(full):
            continue
        for fn in sorted(os.listdir(full)):
            if not fn.endswith(".json") or fn == "meta.json":
                continue
            raw = open(os.path.join(full, fn)).read()
            buf = io.StringIO()
            dump_fixture(J.loads(raw), buf)
            if buf.getvalue() != raw:
                bad.append(f"{d}/{fn}")
    for b in bad:
        print(f"not in canonical compact form: {b}")
    print("selftest ok" if not bad else f"selftest FAILED: {len(bad)} file(s)")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(prog="run.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("record", "check"):
        p = sub.add_parser(name)
        p.add_argument("--base-url", required=True)
        p.add_argument("--admin-token", required=True)
        p.add_argument("--only", help="comma-separated scenario ids, e.g. A,F: all scenarios still run, only these are reported")
        p.add_argument("-v", "--verbose", action="store_true")
        if name == "record":
            p.add_argument("--out", required=True)
        else:
            p.add_argument("--fixtures", required=True)
            p.add_argument("--departures", help="JSON list of reviewed differences from the recorded behaviour")
            p.add_argument("--pending", help="JSON map scenario id -> leading exchange count the server answers; the rest wait for a later slice")
            p.add_argument("--include-web", action="store_true",
                           help="also run the exchanges tagged `web` (Gitea web UI routes); skipped by default")
            p.add_argument("--strict-first-read", action="store_true",
                           help="fail when the first read of an async repo field differs from the settled value")
    p = sub.add_parser("diff")
    p.add_argument("a")
    p.add_argument("b")
    p = sub.add_parser("selftest", help="offline checks of the fixture writer and the stored fixtures")
    p.add_argument("--fixtures-root", dest="fixtures_root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures"))
    p = sub.add_parser("show")
    p.add_argument("dir")
    p.add_argument("--only")
    p.add_argument("--body", action="store_true")
    p.add_argument("--limit", type=int, default=600)
    a = ap.parse_args()
    sys.exit({"record": cmd_run, "check": cmd_run, "diff": cmd_diff, "show": cmd_show, "selftest": cmd_selftest}[a.cmd](a))


# =========================================================================== scenarios
# Each scenario is a function of the Ctx. `c.call(...)` records an exchange; `rec=False` calls are
# setup and are not compared. Use `must_contain` for the words a `message` must carry, `exact` to
# force value equality of a body path, `loose` to compare a path by type only.


@scenario("A", "meta", base=False)
def sc_meta(c):
    c.call("GET", "/version")
    c.call("GET", "/version", as_="none")
    c.call("GET", "/api/healthz", as_="none", api=False)
    c.call("GET", "/user")
    c.call("GET", "/user", as_="bad")
    c.call("GET", "/user", as_="none")
    c.call("POST", "/user/repos", {"name": "probe", "private": True}, expect=201, rec=False)
    me = c.admin_user
    c.call("GET", f"/repos/{me}/probe", as_="none")
    c.call("GET", f"/repos/{me}/probe", as_="bad")
    c.call("GET", f"/repos/{me}/missing")


@scenario("B", "users-orgs-tokens", base=False)
def sc_users(c):
    pw = c.new_password()
    body = {"username": "alice", "email": "alice@example.invalid", "password": pw, "must_change_password": False}
    c.call("POST", "/admin/users", body, expect=201)
    c.pw["alice"] = pw
    c.call("POST", "/admin/users", body, must_contain=["already exists"])
    c.mk_user("bot", rec=True)
    c.mk_user("carol")
    c.mk_user("dave")
    pw2 = c.new_password()
    c.call("PATCH", "/admin/users/alice", {"login_name": "alice", "source_id": 0, "password": pw2,
                                           "visibility": "private", "must_change_password": False})
    c.pw["alice"] = pw2
    c.call("GET", "/users/alice")
    c.call("GET", "/users/alice", as_="none")
    c.call("GET", "/users/nobody-here", must_contain=["not exist"])
    org = {"username": "acme", "full_name": "Acme", "visibility": "private"}
    c.call("POST", "/orgs", org, expect=201)
    c.call("POST", "/orgs", org, must_contain=["already exists"])
    c.call("GET", "/orgs/acme")
    c.call("GET", "/orgs/nobody-org")
    c.call("GET", f"/users/{c.admin_user}/orgs/acme/permissions")
    c.call("GET", "/users/alice/orgs/acme/permissions")
    # teams: a non-goal for sc-forge, so these exchanges are tagged and tolerate a server without them
    team = c.call("POST", "/orgs/acme/teams", {"name": "devs", "permission": "read", "includes_all_repositories": False,
                                               "units": ["repo.code", "repo.pulls"]}, expect=201, tags=["team"])
    tid = team.json.get("id", 0) if team.is_json and isinstance(team.json, dict) else 0
    c.call("PUT", f"/teams/{tid}/members/carol", expect=204, tags=["team"])
    c.call("GET", "/users/carol/orgs/acme/permissions", tags=["team"])
    # tokens
    c.mk_token("alice", "ci", ["read:repository"], "alice-ro", rec=True)
    r = c.mk_token("alice", "tmp", ["read:repository", "write:repository"], "alice-tmp", rec=True)
    order = ["id", "name", "scopes"]  # list order of same-second tokens is a tie-break on some versions
    c.call("GET", "/users/alice/tokens", as_="alice-basic", volatile=order)
    c.call("GET", "/users/alice/tokens", as_="alice-ro")
    c.call("DELETE", f"/users/alice/tokens/{r.json['id']}", as_="alice-basic")
    c.call("GET", "/users/alice/tokens", as_="alice-basic", volatile=order)
    c.call("POST", "/users/alice/tokens", {"name": "ci", "scopes": ["all"]}, as_="alice-basic")
    c.mk_token("alice", "all", ["all"], "alice")
    c.mk_token("bot", "scoped", ["read:user", "read:organization", "write:repository"], "bot-scoped", rec=True)
    c.mk_token("bot", "all", ["all"], "bot")
    c.mk_token("carol", "all", ["all"], "carol")
    c.mk_token("dave", "all", ["all"], "dave")
    c.call("POST", "/orgs/acme/repos", {"name": "nope"}, as_="alice-ro")
    # scope enforcement: read-only token against writes, on a repo alice owns
    c.call("POST", "/user/repos", {"name": "scoped", "auto_init": True, "private": True}, as_="alice", expect=201, rec=False)
    f = c.call("GET", "/repos/alice/scoped/contents/README.md", rec=False, expect=200).json
    sha = c.head("scoped", org="alice")
    c.call("GET", "/repos/alice/scoped", as_="alice-ro")
    c.call("POST", "/user/repos", {"name": "nope"}, as_="alice-ro")
    c.call("POST", "/repos/alice/scoped/contents/new.txt", {"content": "aGk=", "message": "m"}, as_="alice-ro")
    c.call("PUT", "/repos/alice/scoped/contents/README.md", {"content": "aGk=", "message": "m", "sha": f["sha"]}, as_="alice-ro")
    c.call("PUT", "/repos/alice/scoped/collaborators/carol", {"permission": "write"}, as_="alice-ro")
    c.call("POST", f"/repos/alice/scoped/statuses/{sha}", {"state": "success", "context": "x"}, as_="alice-ro")
    # the scoped bot token
    c.call("GET", "/user", as_="bot-scoped")
    c.call("GET", "/orgs/acme", as_="bot-scoped")
    c.call("GET", "/admin/users", as_="bot-scoped")
    c.call("POST", "/user/repos", {"name": "botrepo", "private": True}, as_="bot-scoped")
    c.call("GET", "/repos/alice/scoped", as_="bot-scoped")


def local_commit(c, p, files, msg="local commit"):
    for rel, content in files.items():
        fp = os.path.join(p, rel)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w") as f:
            f.write(content)
    c.git(["add", "-A"], cwd=p, rec=False)
    c.git(["commit", "-q", "-m", msg], cwd=p, rec=False)
    return c.git(["rev-parse", "HEAD"], cwd=p, rec=False)[1]


@scenario("C", "repos")
def sc_repos(c):
    create = {"name": "alpha", "auto_init": True, "default_branch": "main", "private": True, "readme": "Default"}
    c.call("POST", "/orgs/acme/repos", create, expect=201)
    c.call("POST", "/orgs/acme/repos", create, must_contain=["already exists"])
    c.call("POST", "/orgs/acme/repos", {"name": "empty", "auto_init": False, "private": True, "default_branch": "main"},
           expect=201)
    c.call("GET", "/repos/acme/alpha")
    c.call("GET", "/repos/acme/empty")
    c.call("GET", "/repos/acme/missing")
    c.call("PATCH", "/repos/acme/alpha", {"private": True})
    c.call("PATCH", "/repos/acme/alpha", {"has_actions": True})
    c.call("PATCH", "/repos/acme/alpha", {"description": "Alpha repo"})
    c.call("GET", "/repos/search?limit=50&sort=alpha")
    c.call("GET", "/repos/search?q=alp&limit=50")
    # access before any grant
    c.call("GET", "/repos/acme/alpha", as_="dave")
    c.call("GET", "/repos/acme/alpha", as_="bad")
    c.call("GET", "/repos/acme/alpha", as_="none")
    # collaborators
    c.call("PUT", "/repos/acme/alpha/collaborators/bot", {"permission": "write"})
    c.call("PUT", "/repos/acme/alpha/collaborators/carol", {"permission": "read"})
    c.call("PUT", "/repos/acme/alpha/collaborators/alice", {"permission": "write"})
    c.call("PUT", "/repos/acme/alpha/collaborators/nobody-here", {"permission": "write"})
    c.call("GET", "/repos/acme/alpha/collaborators")
    c.call("GET", "/repos/acme/alpha/collaborators/bot/permission")
    c.call("GET", "/repos/acme/alpha", as_="bot")
    c.call("GET", "/repos/acme/alpha", as_="bot-scoped")
    c.call("GET", "/repos/acme/alpha", as_="carol")
    c.call("GET", "/repos/search?limit=50&sort=alpha", as_="carol")
    c.call("DELETE", "/repos/acme/alpha/collaborators/carol")
    c.call("GET", "/repos/acme/alpha", as_="carol")
    c.call("PUT", "/repos/acme/alpha/collaborators/carol", {"permission": "read"}, expect=204)
    # pushes over HTTP
    p = c.wc("alpha", "bot")
    local_commit(c, p, {"bot.txt": "bot\n"})
    c.git(["push", "origin", "HEAD:refs/heads/bot-branch"], cwd=p, name="push-write-collab")
    c.git(["push", c.git_url("alpha", "bot-scoped"), "HEAD:refs/heads/bot-scoped-branch"], cwd=p, name="push-write-scoped-token")
    c.git(["push", c.git_url("alpha", "alice-ro"), "HEAD:refs/heads/ro-scope"], cwd=p, name="push-readonly-scope")
    c.git(["push", c.git_url("alpha", "carol"), "HEAD:refs/heads/carol-branch"], cwd=p, name="push-read-collab")
    c.git(["push", c.git_url("alpha", "dave"), "HEAD:refs/heads/dave-branch"], cwd=p, name="push-no-grant")
    c.git(["clone", c.git_url("alpha", "dave"), c.tmp + "/dave-clone"], name="clone-no-grant")
    c.git(["clone", c.git_url("alpha", "carol"), c.tmp + "/carol-clone"], name="clone-read-collab")
    # delete
    c.call("POST", "/orgs/acme/repos", {"name": "doomed", "auto_init": True, "private": True}, expect=201)
    c.call("DELETE", "/repos/acme/doomed")
    c.call("GET", "/repos/acme/doomed")
    c.call("DELETE", "/repos/acme/doomed")
    c.call("POST", "/orgs/acme/repos", {"name": "doomed", "auto_init": True, "private": True}, expect=201)


@scenario("D", "empty-repo")
def sc_empty(c):
    c.mk_repo("blank", auto_init=False)
    c.call("GET", "/repos/acme/blank")
    for path in ("/commits", "/commits?sha=main&limit=1", "/branches", "/branches/main", "/git/refs/heads",
                 "/git/refs", "/contents", "/contents/README.md", "/git/trees/main", "/git/commits/HEAD",
                 "/archive/main.zip", "/tags", "/pulls?state=all"):
        c.call("GET", "/repos/acme/blank" + path)


@scenario("E", "history-reads")
def sc_history(c):
    c.mk_repo("hist", auto_init=False)
    c1 = c.push_branch("hist", "main", {"README.md": "# hist\n"}, base=None, msg="first")
    c2 = c.push_branch("hist", "main", {"docs/guide.md": "guide\n", "src/lib.rs": "fn main() {}\n"}, msg="second")
    c3 = c.push_branch("hist", "main", {"README.md": "# hist\nedited\n"}, msg="third")
    f1 = c.push_branch("hist", "feat/x", {"feat1.txt": "f1\n"}, base=c2, msg="feat one")
    f2 = c.push_branch("hist", "feat/x", {"feat2.txt": "f2\n"}, base="origin/feat/x", msg="feat two")
    R = "/repos/acme/hist"
    repo_state(c, R, "hist")
    c.call("GET", R + "/branches")
    c.call("GET", R + "/branches?limit=1&page=2")
    c.call("GET", R + "/branches/main")
    c.call("GET", R + "/branches/feat/x")
    c.call("GET", R + "/branches/nope")
    c.call("GET", R + "/git/refs/heads")
    c.call("GET", R + "/git/refs/heads/main")
    c.call("GET", R + "/git/refs/heads/feat/x")
    c.call("GET", R + "/git/refs/heads/nope")
    c.call("GET", R + "/git/refs")
    q = "&stat=false&files=false&verification=false"
    c.call("GET", R + f"/commits?sha=main&limit=50{q}")
    c.call("GET", R + f"/commits?sha=main&limit=2&page=1{q}")
    c.call("GET", R + f"/commits?sha=main&limit=2&page=2{q}")
    c.call("GET", R + f"/commits?sha=main&limit=2&page=3{q}")
    c.call("GET", R + f"/commits?sha=feat/x&limit=50{q}")
    c.call("GET", R + f"/commits?sha={f2}&limit=50{q}")
    c.call("GET", R + "/commits?sha=main&limit=1")
    c.call("GET", R + f"/commits?sha=nope&limit=50{q}")
    c.call("GET", R + f"/git/commits/{c3}")
    c.call("GET", R + f"/git/commits/{f2}")
    c.call("GET", R + f"/git/commits/{c3}.diff", must_contain=["diff --git"])
    c.call("GET", R + f"/git/commits/{c3}.patch", must_contain=["From "])
    c.call("GET", R + f"/git/commits/{'0' * 40}")
    c.call("GET", R + f"/git/trees/{c3}?recursive=true")
    c.call("GET", R + f"/git/trees/{c3}")
    c.call("GET", R + "/git/trees/main?recursive=true&per_page=2&page=1")
    c.call("GET", R + "/contents")
    c.call("GET", R + "/contents?ref=feat/x")
    c.call("GET", R + "/contents/docs")
    c.call("GET", R + "/contents/README.md?ref=main")
    c.call("GET", R + f"/contents/README.md?ref={c1}")
    c.call("GET", R + "/contents/src/lib.rs")
    c.call("GET", R + "/contents/nope.txt")
    c.call("GET", R + "/contents/README.md?ref=nope")
    sha = c.call("GET", R + "/contents/README.md?ref=main", rec=False).json["sha"]
    b64 = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731
    c.call("POST", R + "/contents/new.txt", {"content": b64("new\n"), "message": "add new.txt", "branch": "main"})
    c.call("POST", R + "/contents/new.txt", {"content": b64("new\n"), "message": "add again", "branch": "main"})
    c.call("PUT", R + "/contents/README.md", {"content": b64("# hist\nupdated\n"), "message": "update readme",
                                              "sha": sha, "branch": "main"})
    c.call("PUT", R + "/contents/README.md", {"content": b64("# hist\nstale\n"), "message": "stale update",
                                              "sha": sha, "branch": "main"})
    c.call("PUT", R + "/contents/README.md", {"content": b64("# hist\nno sha\n"), "message": "no sha", "branch": "main"})
    c.call("POST", R + "/contents/branch-file.txt", {"content": b64("b\n"), "message": "to new branch",
                                                    "branch": "main", "new_branch": "api-branch"})
    sha2 = c.call("GET", R + "/contents/new.txt?ref=main", rec=False).json["sha"]
    c.call("PUT", R + "/contents/new.txt", {"content": b64("new2\n"), "message": "update to new branch", "sha": sha2,
                                           "branch": "main", "new_branch": "api-branch-2"})
    c.call("POST", R + "/contents/x.txt", {"content": b64("x\n"), "message": "dup branch", "branch": "main",
                                          "new_branch": "api-branch"})
    c.call("GET", R + "/archive/main.zip", binary=True)
    c.call("GET", R + "/archive/main.tar.gz", binary=True)
    c.call("GET", R + f"/archive/{c1}.zip", binary=True)
    c.call("GET", R + "/archive/nope.zip", binary=True)


def b64(s):
    return base64.b64encode(s.encode()).decode()


def mkpr(c, repo, branch, files, title=None, rec=False, base="main", settle=False, as_="bot-scoped",
         more=(), from_="origin/main"):
    """Push `branch` (one commit per files dict) and open a PR for it. Returns (number, head_sha)."""
    sha = c.push_branch(repo, branch, files, base=from_, msg=f"add {branch}")
    for extra in more:
        sha = c.push_branch(repo, branch, extra, base=f"origin/{branch}", msg=f"more on {branch}")
    r = c.call("POST", f"/repos/acme/{repo}/pulls", {"title": title or f"PR {branch}", "body": f"body {branch}",
                                                     "head": branch, "base": base}, as_=as_, expect=201, rec=rec)
    if settle:  # Gitea answers "Please try again later" to a merge while the PR is still being checked
        settled(c, repo, r.json["number"])
    return r.json["number"], sha


def get_pr(c, repo, n, rec=False, **kw):
    return c.call("GET", f"/repos/acme/{repo}/pulls/{n}", rec=rec, expect=None if rec else 200, **kw).json


def wait_for(fn, timeout=10.0, step=0.25):
    """Poll fn() until truthy. Returns (value, seconds)."""
    t0 = time.time()
    while True:
        v = fn()
        if v or time.time() - t0 > timeout:
            return v, time.time() - t0
        time.sleep(step)


def settled(c, repo, n, timeout=40, pre=3.0):
    """Wait until Gitea has finished (re)checking a PR. The API shows `mergeable: true` before the check
    starts, so probe the merge endpoint with a bogus head_commit_id (never merges) until it stops saying
    "Please try again later" twice in a row."""
    time.sleep(pre)
    t0, good = time.time(), 0
    while time.time() - t0 < timeout:
        r = c.call("POST", f"/repos/acme/{repo}/pulls/{n}/merge", {"Do": "merge", "head_commit_id": "0" * 40},
                   as_="bot-scoped", rec=False, no_retry=True)
        good = 0 if "try again later" in r.text.lower() else good + 1
        if good >= 2:
            return True
        time.sleep(1)
    return False


def advance_main(c, repo, name):
    sha = c.push_branch(repo, "adv-" + name, {name + ".txt": name + "\n"}, msg="advance " + name)
    c.git(["push", "-q", "origin", f"{sha}:refs/heads/main"], cwd=c.wc(repo), rec=False)
    return sha


def parents(c, repo, sha):
    p = c.wc(repo)
    c.git(["fetch", "-q", "origin"], cwd=p, rec=False)
    return len(c.git(["rev-list", "--parents", "-n1", sha], cwd=p, rec=False)[1].split()) - 1


def advert_refs(data):
    """Ref names advertised in a smart-HTTP info/refs body (pkt-lines `<sha> <ref>[\\0caps]`)."""
    refs, i = [], 0
    while i + 4 <= len(data):
        try:
            n = int(data[i:i + 4], 16)
        except ValueError:
            break
        if n < 4:
            i += 4
            continue
        payload, i = data[i + 4:i + n], i + n
        line = payload.split(b"\0", 1)[0].decode("latin-1").strip()
        m = re.match(r"^[0-9a-f]{40} (.+)$", line)
        if m:
            refs.append(m.group(1))
    return refs


def advert_probe(c, repo, label):
    """Record which refs each service advertises (sc-forge hides everything but heads and tags)."""
    for svc, key in (("git-upload-pack", "upload_pack"), ("git-receive-pack", "receive_pack")):
        r = c.call("GET", f"/acme/{repo}.git/info/refs?service={svc}", as_="admin-tokbasic", api=False, volatile=["$text"])
        c.note(f"{label}_advertised_refs_{key}", [c.ns(x) for x in advert_refs(r.data)])


def repo_state(c, path, label):
    """GET a repo whose `empty`/`default_branch` may lag a push: record the settled value, keep the race as a note."""
    r = c.call("GET", path, settle_keys=["empty", "default_branch"])
    c.note(f"{label}_first_read", c.first_read, strict=False)
    return r


def tokbasic(c, who):
    return "none" if who == "none" else f"{who}-tokbasic"


@scenario("F", "pulls")
def sc_pulls(c):
    c.mk_repo("prs")
    R, A = "/repos/acme/prs", "bot-scoped"
    c.push_branch("prs", "f1", {"f1.txt": "one\n"})
    c.push_branch("prs", "f2", {"f2.txt": "two\n"})
    new = {"title": "Add f1", "body": "First", "head": "f1", "base": "main"}
    p1 = c.call("POST", R + "/pulls", new, as_=A, expect=201, volatile=["mergeable"])
    n1 = p1.json["number"]
    c.call("POST", R + "/pulls", new, as_=A)
    n2 = c.call("POST", R + "/pulls", {"title": "Add f2", "body": "Second", "head": "f2", "base": "main"},
                as_=A, expect=201, volatile=["mergeable"]).json["number"]
    c.call("POST", R + "/pulls", {"title": "x", "head": "nope", "base": "main"}, as_=A)
    c.call("POST", R + "/pulls", {"title": "x", "head": "main", "base": "main"}, as_=A)
    c.call("POST", R + "/pulls", {"title": "x", "head": "f1", "base": "nope"}, as_=A)
    c.call("POST", R + "/pulls", {"head": "f1", "base": "main"}, as_=A)
    lst = c.call("GET", R + "/pulls?state=all&head=acme%3Af2&limit=50", as_=A)
    c.note("head_filter_returned_heads", [x["head"]["ref"] for x in lst.json])
    c.call("GET", R + "/pulls?state=open&limit=50", as_=A)
    c.call("GET", R + "/pulls?state=closed&limit=50", as_=A)
    c.call("GET", R + f"/pulls/{n1}", as_=A, volatile=["mergeable"])
    c.call("GET", R + "/pulls/999", as_=A)
    # head moves when a commit is pushed to the head branch
    old = p1.json["head"]["sha"]
    new_sha = c.push_branch("prs", "f1", {"f1b.txt": "more\n"}, base="origin/f1")
    imm = get_pr(c, "prs", n1)["head"]["sha"]
    c.note("head_sha_updated_immediately", imm == new_sha, strict=False)
    ok, dt = wait_for(lambda: get_pr(c, "prs", n1)["head"]["sha"] == new_sha)
    c.note("head_sha_updated_within_10s", bool(ok))
    final = c.call("GET", R + f"/pulls/{n1}", as_=A, volatile=["mergeable"])
    c.note("head_sha_changed_after_push", final.json["head"]["sha"] != old)
    c.call("GET", R + f"/pulls?state=open&limit=50", as_=A)
    c.call("GET", R + f"/pulls/{n1}.diff", as_=A)
    c.call("GET", R + f"/pulls/{n1}.patch", as_=A, volatile=["$text"])
    c.call("GET", R + f"/pulls/{n1}/commits", as_=A)
    c.call("GET", R + f"/pulls/{n1}/files", as_=A)
    # close / reopen / edit
    c.call("PATCH", R + f"/pulls/{n2}", {"state": "closed"}, as_=A, volatile=["mergeable"])
    c.call("GET", R + "/pulls?state=closed&limit=50", as_=A)
    c.call("PATCH", R + f"/pulls/{n2}", {"state": "open"}, as_=A, volatile=["mergeable"])
    c.call("PATCH", R + f"/pulls/{n2}", {"title": "Renamed f2"}, as_=A, volatile=["mergeable"])
    # reviews
    c.call("GET", R + f"/pulls/{n1}/reviews", as_=A)
    c.call("POST", R + f"/pulls/{n1}/reviews", {"body": "looks fine", "event": "COMMENT"})
    c.call("POST", R + f"/pulls/{n1}/reviews", {"body": "please change", "event": "REQUEST_CHANGES"}, as_="alice")
    c.call("POST", R + f"/pulls/{n1}/reviews", {"body": "now ok", "event": "APPROVED"}, as_="alice")
    c.call("POST", R + f"/pulls/{n1}/reviews", {"body": "read only approves", "event": "APPROVED"}, as_="carol")
    c.call("POST", R + f"/pulls/{n1}/reviews", {"body": "self approve", "event": "APPROVED"}, as_=A)
    c.call("POST", R + f"/pulls/{n1}/reviews", {"body": "bogus", "event": "BOGUS"}, as_="alice")
    revs = c.call("GET", R + f"/pulls/{n1}/reviews", as_=A)
    c.call("GET", R + f"/pulls/{n1}/reviews?page=1&limit=25", as_=A)
    rid = revs.json[0]["id"]
    c.call("GET", R + f"/pulls/{n1}/reviews/{rid}", as_=A)
    c.call("GET", R + f"/pulls/{n1}/reviews/{rid}/comments", as_=A)
    for who in (A, "bot"):
        c.call("GET", R + f"/issues/{n1}/comments", as_=who)
        c.call("POST", R + f"/issues/{n1}/comments", {"body": "hello"}, as_=who)
        c.call("GET", R + f"/issues/{n1}/comments", as_=who)


@scenario("G", "merge")
def sc_merge(c):
    c.mk_repo("merges")
    R, A = "/repos/acme/merges", "bot-scoped"

    def merge(n, body, **kw):
        return c.call("POST", R + f"/pulls/{n}/merge", body, as_=A, **kw)

    def getpr(n, **kw):  # `mergeable` flips while Gitea re-checks open PRs after every base change
        return c.call("GET", R + f"/pulls/{n}", as_=A, volatile=["mergeable"], **kw)

    def settle_merged(n, label):
        first = get_pr(c, "merges", n)
        final, dt = wait_for(lambda: get_pr(c, "merges", n)["merged"] and get_pr(c, "merges", n))
        c.note(f"{label}_merged_immediately_after_merge_call", first["merged"], strict=False)
        c.note(f"{label}_merged_within_10s", bool(final))
        c.note(f"{label}_seconds_to_merged", round(dt), strict=False)
        return final or get_pr(c, "merges", n)

    # 1. clean merge
    n1, s1 = mkpr(c, "merges", "m1", {"m1.txt": "1\n"})
    c.call("GET", R + f"/pulls/{n1}/merge", as_=A)
    getpr(n1)
    merge(n1, {"Do": "merge"})
    fin = settle_merged(n1, "merge")
    c.call("GET", R + f"/pulls/{n1}", as_=A)
    c.note("merged_flag_true_after_merge", fin["merged"] is True)
    c.note("merge_commit_sha_present", bool(fin.get("merge_commit_sha")))
    c.note("merge_commit_parent_count", parents(c, "merges", fin["merge_commit_sha"]) if fin.get("merge_commit_sha") else -1)
    c.note("head_sha_unchanged_after_merge", fin["head"]["sha"] == s1)
    c.call("GET", R + f"/pulls/{n1}/merge", as_=A)
    merge(n1, {"Do": "merge"})  # retry after success
    # 1b. merge immediately after creation (check not finished): unrecorded, outcome kept as notes
    nb, sb = mkpr(c, "merges", "m1b", {"m1b.txt": "b\n"})
    r = merge(nb, {"Do": "merge"}, rec=False, no_retry=True)
    c.note("immediate_merge_status", r.status, strict=False)
    c.note("immediate_merge_message", (r.json or {}).get("message", "") if r.is_json else r.text.strip()[:80], strict=False)
    if r.status != 200:
        merge(nb, {"Do": "merge"}, rec=False)
    settle_merged(nb, "immediate")
    c.call("GET", R + f"/pulls/{nb}", as_=A)
    # 2. correct head_commit_id
    n2, s2 = mkpr(c, "merges", "m2", {"m2.txt": "2\n"})
    merge(n2, {"Do": "merge", "head_commit_id": s2})
    settle_merged(n2, "headid")
    # 3. wrong head_commit_id, then right one
    n3, s3 = mkpr(c, "merges", "m3", {"m3.txt": "3\n"})
    merge(n3, {"Do": "merge", "head_commit_id": "0" * 40})
    merge(n3, {"Do": "merge", "head_commit_id": s2})
    getpr(n3)
    merge(n3, {"Do": "merge", "head_commit_id": s3})
    settle_merged(n3, "wrongid_then_right")
    # invalid Do / missing Do (this PR stays open; it is closed below so it does not slow later checks)
    n6, s6 = mkpr(c, "merges", "m6", {"m6.txt": "6\n"})
    merge(n6, {"Do": "bogus"})
    merge(n6, {})
    c.call("PATCH", R + f"/pulls/{n6}", {"state": "closed"}, as_=A, rec=False, expect=201)
    # 4. head already an ancestor of base (empty merge)
    n4, s4 = mkpr(c, "merges", "m4", {"m4.txt": "4\n"})
    c.git(["push", "-q", "origin", f"{s4}:refs/heads/main"], cwd=c.wc("merges"), rec=False)
    time.sleep(6)
    getpr(n4)
    merge(n4, {"Do": "merge"}, no_retry=True)
    getpr(n4)
    c.call("POST", R + "/pulls", {"title": "again", "head": "m1", "base": "main"}, as_=A)  # head contained in base
    c.call("PATCH", R + f"/pulls/{n4}", {"state": "closed"}, as_=A, rec=False)
    # 5. conflict. Gitea answers a conflicting merge with the same "Please try again later" it uses while checking.
    base_sha = c.push_branch("merges", "cbase", {"conflict.txt": "base\n"})
    c.git(["push", "-q", "origin", f"{base_sha}:refs/heads/main"], cwd=c.wc("merges"), rec=False)
    na, _ = mkpr(c, "merges", "cf1", {"conflict.txt": "one\n"})
    nc, _ = mkpr(c, "merges", "cf2", {"conflict.txt": "two\n"})
    merge(na, {"Do": "merge"})
    time.sleep(8)
    # settled conflict state: poll until 8 equal reads, then `mergeable` is compared by value (false)
    cf = c.call("GET", R + f"/pulls/{nc}", as_=A, settle_keys=["mergeable"], strict_keys=["mergeable"])
    if c.mode == "record" and cf.json.get("mergeable") is not False:
        raise SetupError(f"the conflicting PR settled as mergeable={cf.json.get('mergeable')!r}")
    merge(nc, {"Do": "merge"}, no_retry=True)
    c.call("PATCH", R + f"/pulls/{nc}", {"state": "closed"}, as_=A, rec=False)
    # 6. closed PR
    n5, _ = mkpr(c, "merges", "m5", {"m5.txt": "5\n"})
    c.call("PATCH", R + f"/pulls/{n5}", {"state": "closed"}, as_=A)
    merge(n5, {"Do": "merge"})
    c.call("GET", R + f"/pulls/{n5}", as_=A)
    # 7. merge styles
    nq, _ = mkpr(c, "merges", "sq", {"sq1.txt": "a\n"}, more=[{"sq2.txt": "b\n"}])
    merge(nq, {"Do": "squash"})
    fin = settle_merged(nq, "squash")
    c.call("GET", R + f"/pulls/{nq}", as_=A)
    c.note("squash_parent_count", parents(c, "merges", fin["merge_commit_sha"]) if fin.get("merge_commit_sha") else -1)
    nr, _ = mkpr(c, "merges", "rb", {"rb1.txt": "a\n"}, more=[{"rb2.txt": "b\n"}])
    advance_main(c, "merges", "adv1")
    merge(nr, {"Do": "rebase"})
    fin = settle_merged(nr, "rebase")
    c.call("GET", R + f"/pulls/{nr}", as_=A)
    c.note("rebase_parent_count", parents(c, "merges", fin["merge_commit_sha"]) if fin.get("merge_commit_sha") else -1)
    nm, _ = mkpr(c, "merges", "rm", {"rm1.txt": "a\n"})
    advance_main(c, "merges", "adv2")
    merge(nm, {"Do": "rebase-merge"})
    fin = settle_merged(nm, "rebase_merge")
    c.note("rebase_merge_parent_count", parents(c, "merges", fin["merge_commit_sha"]) if fin.get("merge_commit_sha") else -1)
    nf, _ = mkpr(c, "merges", "ffo", {"ffo.txt": "a\n"})
    merge(nf, {"Do": "fast-forward-only"})
    fin = settle_merged(nf, "ff_only")
    c.call("GET", R + f"/pulls/{nf}", as_=A)
    c.note("ff_only_parent_count", parents(c, "merges", fin["merge_commit_sha"]) if fin.get("merge_commit_sha") else -1)
    nf2, _ = mkpr(c, "merges", "ffo2", {"ffo2.txt": "a\n"})
    advance_main(c, "merges", "adv3")
    time.sleep(6)
    merge(nf2, {"Do": "fast-forward-only"}, no_retry=True)
    getpr(nf2)
    c.call("PATCH", R + f"/pulls/{nf2}", {"state": "closed"}, as_=A, rec=False)
    # 8. required status checks
    ns_, ss = mkpr(c, "merges", "sc1", {"sc1.txt": "s\n"})
    c.call("POST", R + "/branch_protections", {"branch_name": "main", "enable_push": False,
                                               "enable_status_check": True, "status_check_contexts": ["ci/test"]},
           expect=201)
    merge(ns_, {"Do": "merge"}, must_contain=["required status checks"])
    for state in ("pending", "failure"):
        c.call("POST", R + f"/statuses/{ss}", {"state": state, "context": "ci/test"}, expect=201, rec=False)
        merge(ns_, {"Do": "merge"}, must_contain=["required status checks"])
    c.call("POST", R + f"/statuses/{ss}", {"state": "success", "context": "ci/test"}, expect=201, rec=False)
    merge(ns_, {"Do": "merge"})
    settle_merged(ns_, "status_gated")
    c.call("DELETE", R + "/branch_protections/main")


@scenario("H", "statuses")
def sc_statuses(c):
    c.mk_repo("status")
    R = "/repos/acme/status"
    shas = [c.head("status")] + [c.api_file("status", f"f{i}.txt", f"{i}\n", f"commit {i}") for i in range(1, 6)]
    s0, s1, s2, s3, s4, s5 = shas

    def post(sha, state, ctx, **kw):
        body = {"state": state, "context": ctx, "description": f"{ctx} is {state}", "target_url": "http://example.invalid/run/1"}
        return c.call("POST", R + f"/statuses/{sha}", body, **kw)

    def combined(sha):
        return c.call("GET", R + f"/commits/{sha}/status?limit=50")

    r = combined(s0)
    c.note("combined_state_no_statuses", r.json["state"])
    c.call("GET", R + f"/statuses/{s0}?limit=100")
    c.call("GET", R + f"/commits/{s0}/statuses?limit=100")
    # same context twice
    post(s1, "pending", "ci/test", as_="bot-scoped", expect=201)
    r = combined(s1)
    c.note("combined_state_pending", r.json["state"])
    time.sleep(1.1)  # same-second statuses list in random order on some versions
    post(s1, "success", "ci/test", as_="bot-scoped", expect=201)
    r = combined(s1)
    c.note("combined_statuses_after_pending_then_success", len(r.json["statuses"]))
    c.call("GET", R + f"/statuses/{s1}?limit=100")
    r = c.call("GET", R + f"/commits/{s1}/statuses?limit=100")
    c.note("list_history_len_after_two_posts", len(r.json))
    # mixes
    post(s2, "success", "ci/test", expect=201)
    post(s2, "failure", "ci/lint", expect=201)
    c.note("combined_success_plus_failure", combined(s2).json["state"])
    post(s2, "success", "ci/lint", expect=201)
    c.note("combined_all_success", combined(s2).json["state"])
    post(s2, "pending", "ci/other", expect=201)
    c.note("combined_success_plus_pending", combined(s2).json["state"])
    post(s2, "error", "ci/err", expect=201)
    c.note("combined_with_error", combined(s2).json["state"])
    combined(s2)
    # state strings
    for st in ("success", "pending", "failure", "error", "warning", "skipped", "bogus", ""):
        post(s3, st, f"st-{st or 'empty'}")
    combined(s3)
    c.call("POST", R + f"/statuses/{s3}", {"state": "success"})
    c.call("POST", R + f"/statuses/{s3}", {"context": "no-state"})
    c.call("POST", R + f"/statuses/{s3}", {"state": "success", "context": "x" * 300})
    # unknown / malformed sha, no permission
    post("0123456789abcdef0123456789abcdef01234567", "success", "ci/test")
    post("nope", "success", "ci/test")
    post(s4, "success", "ci/test", as_="carol")
    post(s4, "success", "ci/test", as_="dave")
    # a commit whose only status has an unknown state string
    post(s5, "bogus", "ci/bogus-only", expect=201)
    r = combined(s5)
    c.note("combined_state_only_bogus", r.json["state"])
    c.note("combined_total_only_bogus", r.json["total_count"])
    c.call("GET", R + f"/statuses/{s5}?limit=100")
    combined("0123456789abcdef0123456789abcdef01234567")
    c.call("GET", R + "/commits/main/status?limit=50")
    c.call("GET", R + "/statuses/main?limit=100")


@scenario("I", "branch-protection")
def sc_protection(c):
    c.mk_repo("prot")
    R = "/repos/acme/prot"
    c.call("GET", R + "/branch_protections")
    body = {"branch_name": "main", "enable_push": False, "enable_status_check": True, "status_check_contexts": ["ci/test"]}
    c.call("POST", R + "/branch_protections", body, expect=201)
    c.call("POST", R + "/branch_protections", body)
    c.call("GET", R + "/branch_protections")
    c.call("GET", R + "/branch_protections/main")
    c.call("GET", R + "/branch_protections/nope")
    c.call("POST", R + "/branch_protections", body, as_="bot")
    p = c.wc("prot", "bot")
    local_commit(c, p, {"direct.txt": "x\n"})
    c.git(["push", "origin", "HEAD:refs/heads/main"], cwd=p, name="push-protected-write-collab",
          must_contain=["protected"])
    c.git(["push", c.git_url("prot", "admin"), "HEAD:refs/heads/main"], cwd=p, name="push-protected-admin")
    c.git(["push", "origin", "HEAD:refs/heads/other"], cwd=p, name="push-other-branch")
    c.git(["push", "origin", ":refs/heads/main"], cwd=p, name="delete-protected-by-push")
    c.call("PATCH", R + "/branch_protections/main", {"enable_push": True})
    c.git(["push", "origin", "HEAD:refs/heads/main"], cwd=p, name="push-after-enable-push")
    c.call("PATCH", R + "/branch_protections/main", {"enable_status_check": False})
    c.call("PATCH", R + "/branch_protections/nope", {"enable_push": True})
    c.call("DELETE", R + "/branch_protections/main")
    c.call("GET", R + "/branch_protections/main")
    c.call("DELETE", R + "/branch_protections/main")


@scenario("J", "smart-http")
def sc_smart(c):
    c.mk_repo("smart")
    wcp = c.wc("smart")
    tok = c.principals["admin"]["secret"]
    tip_old = c.head("smart")
    c.push_branch("smart", "main", {"a.txt": "a\n"})
    c.push_branch("smart", "main", {"b.txt": "b\n"})
    tip = c.push_branch("smart", "main", {"a.txt": "a edited\n"})  # a.txt's first blob is history-only (partial clone)
    dead = c.push_branch("smart", "tmp-dead", {"dead.txt": "x\n"})
    c.git(["push", "-q", "origin", ":refs/heads/tmp-dead"], cwd=wcp, rec=False)
    url = lambda **kw: c.git_url("smart", **kw)  # noqa: E731
    variants = [
        ("admin-token", dict(who="admin")),
        ("oauth2-token", dict(who="admin", user="oauth2")),
        ("bot-token", dict(who="bot")),
        ("other-name-admin-token", dict(who="admin", user="someone")),
        ("bot-name-admin-token", dict(who="admin", user="bot")),
        ("token-as-username", dict(who="admin", user=tok, secret="")),
        ("bad-token", dict(who="bad")),
        ("no-credentials", dict(who="admin", user="", secret="")),
    ]
    for label, kw in variants:
        u = url(**kw)
        c.git(["clone", "-q", u, f"{c.tmp}/j-{label}"], name=f"clone-{label}")
        c.git(["push", u, f"{tip}:refs/heads/j-{label}"], cwd=wcp, name=f"push-{label}")
        c.git(["fetch", "-q", u, "main"], cwd=wcp, name=f"fetch-{label}")
    plain = url(user="", secret="")
    hdrs = [("hdr-basic-token-empty-password", "Authorization: Basic " + base64.b64encode(f"{tok}:".encode()).decode()),
            ("hdr-token", "Authorization: token " + tok), ("hdr-bearer", "Authorization: Bearer " + tok)]
    for label, h in hdrs:
        c.git(["ls-remote", plain], name=f"ls-remote-{label}", extra_header=(label, h))
    # raw endpoints
    for svc in ("git-upload-pack", "git-receive-pack"):
        for who in ("none", "bad", "admin", "oauth2"):
            c.call("GET", f"/acme/smart.git/info/refs?service={svc}", as_=tokbasic(c, who), api=False,
                   volatile=["$text"], must_contain=[f"service={svc}"] if who in ("admin", "oauth2") else None)
    c.call("GET", "/acme/smart.git/info/refs?service=git-upload-pack", as_="admin-tokbasic", api=False,
           headers={"Git-Protocol": "version=2"}, volatile=["$text"], must_contain=["version 2"])
    # fetch a commit by id
    fd = c.tmp + "/jfetch"
    c.git(["init", "-q", fd], rec=False)
    for proto in ("0", "2"):
        for label, sha in (("tip", tip), ("old", tip_old), ("dead", dead)):
            c.git(["-c", f"protocol.version={proto}", "fetch", "-q", url(who="admin"), sha], cwd=fd,
                  name=f"fetch-sha-{label}-v{proto}")
    for proto in ("0", "2"):
        c.git(["-c", f"protocol.version={proto}", "ls-remote", url(who="admin")], name=f"ls-remote-v{proto}")
    # partial and shallow clones
    d = c.tmp + "/jpartial"
    c.git(["clone", "--filter=blob:none", url(who="admin"), d], name="clone-filter-blob-none")
    if os.path.isdir(d):
        miss = c.git(["rev-list", "--objects", "--all", "--missing=print"], cwd=d, rec=False)[1].splitlines()
        c.note("partial_clone_missing_objects", sum(1 for x in miss if x.startswith("?")) > 0)
        c.note("partial_clone_promisor", c.git(["config", "--get", "remote.origin.promisor"], cwd=d, rec=False, ok=None)[1])
    d2 = c.tmp + "/jshallow"
    c.git(["clone", "-q", "--depth=1", url(who="admin"), d2], name="clone-depth-1")
    if os.path.isdir(d2):
        c.note("shallow_clone", c.git(["rev-parse", "--is-shallow-repository"], cwd=d2, rec=False)[1])
        c.git(["fetch", "-q", "--unshallow"], cwd=d2, name="unshallow")
    # force-with-lease
    a = c.push_branch("smart", "flw-a", {"flw.txt": "A\n"})
    b = c.push_branch("smart", "flw-b", {"flw.txt": "B\n"})
    u = url(who="admin")
    c.git(["push", "--force-with-lease=refs/heads/b:", u, f"{a}:refs/heads/b"], cwd=wcp, name="flw-absent-expected-and-absent")
    c.git(["push", "--force-with-lease=refs/heads/b:", u, f"{b}:refs/heads/b"], cwd=wcp, name="flw-absent-expected-but-exists")
    c.git(["push", f"--force-with-lease=refs/heads/b:{a}", u, f"{b}:refs/heads/b"], cwd=wcp, name="flw-correct-lease-nonff")
    c.git(["push", f"--force-with-lease=refs/heads/b:{a}", u, f"{a}:refs/heads/b"], cwd=wcp, name="flw-stale-lease")
    c.git(["push", u, f"{a}:refs/heads/b"], cwd=wcp, name="push-nonff-without-force")
    # tags and deletes
    c.git(["tag", "v1", tip], cwd=wcp, rec=False)
    c.git(["tag", "-a", "v2", "-m", "release", tip], cwd=wcp, rec=False)
    c.git(["push", u, "refs/tags/v1", "refs/tags/v2"], cwd=wcp, name="push-tags")
    c.call("GET", "/repos/acme/smart/tags")
    c.call("GET", "/repos/acme/smart/git/refs/tags")
    c.git(["push", u, ":refs/tags/v1"], cwd=wcp, name="delete-tag-by-push")
    c.call("GET", "/repos/acme/smart/tags")
    c.git(["push", u, ":refs/heads/b"], cwd=wcp, name="delete-branch-by-push")
    c.call("GET", "/repos/acme/smart/branches/b")
    c.git(["push", u, ":refs/heads/main"], cwd=wcp, name="delete-default-branch-by-push")
    c.call("GET", "/acme/smart.git/HEAD", as_="admin-tokbasic", api=False)


@scenario("K", "visibility-probing")
def sc_visibility(c):
    c.mk_repo("vis")
    for who in ("none", "bad", "dave", "carol"):
        for repo in ("vis", "ghost"):
            c.call("GET", f"/repos/acme/{repo}", as_=who)
            c.call("GET", f"/repos/acme/{repo}/contents", as_=who)
            c.call("GET", f"/repos/acme/{repo}/branches", as_=who)
            c.call("GET", f"/acme/{repo}.git/info/refs?service=git-upload-pack", as_=tokbasic(c, who), api=False,
                   volatile=["$text"])
            c.call("GET", f"/acme/{repo}.git/info/refs?service=git-receive-pack", as_=tokbasic(c, who), api=False,
                   volatile=["$text"])
    for who in ("none", "dave"):
        for repo in ("vis", "ghost"):
            c.call("GET", f"/acme/{repo}", as_=tokbasic(c, who), api=False, volatile=["$text"], tags=["web"])  # Gitea web UI
            c.git(["ls-remote", c.git_url(repo, who)] if who != "none" else ["ls-remote", c.git_url(repo, "admin", user="", secret="")],
                  name=f"ls-remote-{repo}-{who}")
    for who in ("none", "dave", "carol", "admin"):
        c.call("GET", "/repos/search?limit=50&sort=alpha", as_=who)
    c.call("GET", "/repos/search?q=vis&limit=50", as_="dave")
    c.call("GET", "/user/repos?limit=50", as_="dave")
    c.call("GET", "/orgs/acme", as_="dave")
    c.call("GET", "/orgs/acme/repos", as_="dave")
    c.call("GET", "/orgs/acme/repos?limit=50", as_="carol")
    c.call("GET", "/orgs/acme/repos?limit=50", as_="none")


@scenario("L", "force-private")
def sc_force_private(c):
    c.call("POST", "/orgs/acme/repos", {"name": "pub1", "private": False, "auto_init": True})
    c.call("GET", "/repos/acme/pub1")
    c.call("PATCH", "/repos/acme/pub1", {"private": False})
    c.call("GET", "/repos/acme/pub1")
    c.call("PATCH", "/repos/acme/pub1", {"private": True})
    c.call("PATCH", "/repos/acme/pub1", {"private": False})
    c.call("POST", "/orgs/acme/repos", {"name": "nodef", "auto_init": False})
    c.call("POST", "/user/repos", {"name": "pub2", "private": False}, as_="alice")
    c.call("GET", "/repos/alice/pub2", as_="none")
    c.call("GET", "/repos/alice/pub2", as_="dave")
    c.call("POST", "/user/repos", {"name": "nodef2"}, as_="alice")
    c.call("POST", "/orgs", {"username": "pubco", "visibility": "public"})
    c.call("GET", "/orgs/pubco", as_="dave")
    c.call("POST", "/orgs/pubco/repos", {"name": "pubrepo", "private": False})
    c.call("GET", "/repos/pubco/pubrepo", as_="dave")


@scenario("M", "names")
def sc_names(c):
    for name in ("Mixed", "mixed", "MIXED"):
        c.call("POST", "/orgs/acme/repos", {"name": name, "auto_init": False})
    c.call("GET", "/repos/acme/mixed")
    c.call("GET", "/repos/acme/Mixed")
    c.call("GET", "/repos/ACME/mixed")
    for name in (".", "..", ".hidden", "-dash", "trail.git", "wiki.wiki", "feed.rss", "feed.atom", "a b", "a..b",
                 "api", "admin", "user", "assets", "x" * 101, "ok_name-1.x", "ünï"):
        c.call("POST", "/orgs/acme/repos", {"name": name, "auto_init": False})
    for n, i in (("Acme", 1), ("api", 2), ("admin", 3), ("user", 4), ("assets", 5), ("explore", 6), (".dot", 7),
                 ("-dash", 8), ("has space", 9), ("org.git", 10), ("x" * 41, 11)):
        c.call("POST", "/orgs", {"username": n})
    for n in ("Alice", "api", "user", "-lead", ".lead", "trail.git", "bad name"):
        c.call("POST", "/admin/users", {"username": n, "email": f"{n.replace(' ', '')}@example.invalid", "password": c.new_password(),
                                        "must_change_password": False})
    c.call("POST", "/orgs/acme/repos", {"name": "rename-me", "auto_init": True}, expect=201)
    c.call("PATCH", "/repos/acme/rename-me", {"name": "renamed"})
    c.call("GET", "/repos/acme/rename-me")
    c.call("GET", "/repos/acme/renamed")
    c.call("GET", "/repos/acme/rename-me", as_="dave")
    c.call("GET", "/acme/rename-me.git/info/refs?service=git-upload-pack", as_="admin-tokbasic", api=False,
           volatile=["$text"])
    c.git(["ls-remote", c.git_url("rename-me", "admin")], name="ls-remote-old-name")
    c.git(["ls-remote", c.git_url("renamed", "admin")], name="ls-remote-new-name")
    c.call("PATCH", "/repos/acme/renamed", {"name": "mixed"})
    c.call("PATCH", "/repos/acme/renamed", {"name": "Renamed"})
    c.call("PATCH", "/repos/acme/Renamed", {"name": "renamed"})


@scenario("N", "default-branch")
def sc_default_branch(c):
    c.mk_repo("dflt")
    c.push_branch("dflt", "dev", {"dev.txt": "d\n"})
    R = "/repos/acme/dflt"
    c.call("PATCH", R, {"default_branch": "nope"})
    c.call("PATCH", R, {"default_branch": "dev"})
    c.call("GET", R)
    c.git(["ls-remote", "--symref", c.git_url("dflt"), "HEAD"], name="ls-remote-symref-after-change", note_stdout=True)
    c.call("GET", R + "/branches")
    c.call("GET", R + "/contents")
    d = c.tmp + "/ndflt"
    c.git(["clone", "-q", c.git_url("dflt"), d], name="clone-after-change")
    if os.path.isdir(d):
        c.note("clone_checked_out_branch", c.git(["symbolic-ref", "--short", "HEAD"], cwd=d, rec=False)[1])
    c.call("PATCH", R, {"default_branch": "main"}, retry_while=["already in queue"])  # async branch sync, 1.26
    c.call("DELETE", R + "/branches/dev")
    # empty repo, first push name decides?
    c.mk_repo("fresh1", auto_init=False)
    repo_state(c, "/repos/acme/fresh1", "fresh1_before_push")
    c.push_branch("fresh1", "trunk", {"t.txt": "t\n"}, base=None)
    repo_state(c, "/repos/acme/fresh1", "fresh1_after_trunk")
    c.git(["ls-remote", "--symref", c.git_url("fresh1"), "HEAD"], name="ls-remote-symref-trunk-first", note_stdout=True)
    c.call("GET", "/repos/acme/fresh1/branches")
    c.mk_repo("fresh2", auto_init=False)
    c.push_branch("fresh2", "main", {"t.txt": "t\n"}, base=None)
    repo_state(c, "/repos/acme/fresh2", "fresh2_after_main")
    c.mk_repo("fresh3", auto_init=False, default_branch="develop")
    repo_state(c, "/repos/acme/fresh3", "fresh3_before_push")
    c.push_branch("fresh3", "main", {"t.txt": "t\n"}, base=None)
    repo_state(c, "/repos/acme/fresh3", "fresh3_after_main")
    c.git(["ls-remote", "--symref", c.git_url("fresh3"), "HEAD"], name="ls-remote-symref-main-pushed-first", note_stdout=True)
    c.push_branch("fresh3", "develop", {"u.txt": "u\n"}, base="origin/main")
    repo_state(c, "/repos/acme/fresh3", "fresh3_after_develop")
    c.git(["ls-remote", "--symref", c.git_url("fresh3"), "HEAD"], name="ls-remote-symref-develop-pushed-second", note_stdout=True)


@scenario("O", "pr-head-lifecycle")
def sc_pr_lifecycle(c):
    c.mk_repo("life")
    R, A = "/repos/acme/life", "bot-scoped"
    wcp = c.wc("life")
    url = c.git_url("life")
    # 1. force-push the head branch
    n1, s1 = mkpr(c, "life", "l1", {"l1.txt": "1\n"})
    c.call("GET", R + f"/pulls/{n1}", as_=A)
    s1b = c.push_branch("life", "l1", {"l1-other.txt": "rewritten\n"}, base="origin/main", msg="rewritten")
    ok, _ = wait_for(lambda: get_pr(c, "life", n1)["head"]["sha"] == s1b)
    c.note("force_push_head_sha_follows", bool(ok))
    c.call("GET", R + f"/pulls/{n1}", as_=A)
    c.call("GET", R + "/pulls?state=open&limit=50", as_=A)
    c.git(["ls-remote", url, "refs/pull/*"], name="ls-remote-pull-refs", cwd=wcp, note_stdout=True)
    # 2. delete the head branch while the PR is open
    n2, s2 = mkpr(c, "life", "l2", {"l2.txt": "2\n"})
    c.call("DELETE", R + "/branches/l2")
    time.sleep(1)
    c.call("GET", R + f"/pulls/{n2}", as_=A)
    c.call("GET", R + "/pulls?state=open&limit=50", as_=A)
    c.call("POST", R + f"/pulls/{n2}/merge", {"Do": "merge"}, as_=A)
    c.call("GET", R + f"/pulls/{n2}", as_=A)
    c.git(["ls-remote", url, "refs/pull/*"], name="ls-remote-pull-refs-after-delete", cwd=wcp, note_stdout=True)
    advert_probe(c, "life", "life")
    c.call("GET", R + f"/pulls/{n2}/commits", as_=A)
    c.call("GET", R + f"/pulls/{n2}.diff", as_=A)
    # 3. merge, then recreate the head branch at a new commit
    n3, s3 = mkpr(c, "life", "l3", {"l3.txt": "3\n"})
    c.call("POST", R + f"/pulls/{n3}/merge", {"Do": "merge"}, as_=A)
    wait_for(lambda: get_pr(c, "life", n3)["merged"])
    s3b = c.push_branch("life", "l3", {"l3-new.txt": "again\n"}, base="origin/main", msg="reborn l3")
    time.sleep(2)
    j = c.call("GET", R + f"/pulls/{n3}", as_=A)
    c.note("merged_pr_head_sha_frozen", j.json["head"]["sha"] == s3)
    c.note("merged_pr_head_sha_follows_new_branch", j.json["head"]["sha"] == s3b)
    # 4. closed PR, then branch deleted
    n4, _ = mkpr(c, "life", "l4", {"l4.txt": "4\n"})
    c.call("PATCH", R + f"/pulls/{n4}", {"state": "closed"}, as_=A)
    c.call("DELETE", R + "/branches/l4")
    time.sleep(1)
    c.call("GET", R + f"/pulls/{n4}", as_=A)
    c.call("PATCH", R + f"/pulls/{n4}", {"state": "open"}, as_=A)
    # 1.26 answers "open" and then sometimes reverts the PR to "closed" (head branch missing): racy, state not compared
    c.call("GET", R + f"/pulls/{n4}", as_=A, volatile=["state", "closed_at"])
    # 5. head commit pushed straight into base
    n5, s5 = mkpr(c, "life", "l5", {"l5.txt": "5\n"})
    c.git(["push", "-q", "origin", f"{s5}:refs/heads/main"], cwd=wcp, rec=False)
    ok, dt = wait_for(lambda: get_pr(c, "life", n5)["merged"], timeout=15)
    c.note("direct_push_marks_pr_merged", bool(ok))
    c.note("direct_push_seconds_to_detect", round(dt), strict=False)
    c.call("GET", R + f"/pulls/{n5}", as_=A)
    c.call("GET", R + f"/pulls/{n5}/merge", as_=A)


@scenario("P", "pagination")
def sc_pagination(c):
    c.mk_repo("pages")
    R, A = "/repos/acme/pages", "bot-scoped"
    for i in range(1, 6):
        time.sleep(1.1)  # distinct commit/update times: some Gitea versions order by time and tie-break randomly
        mkpr(c, "pages", f"pg{i}", {f"pg{i}.txt": f"{i}\n"}, title=f"PR {i}", settle=0)
    head = c.head("pages")
    for i in range(1, 6):
        time.sleep(1.1)  # statuses created in the same second list in a random order on some versions
        c.call("POST", R + f"/statuses/{head}", {"state": "success", "context": f"s{i}"}, expect=201, rec=False)
    for pg in (1, 2, 3, 0, -1):
        c.call("GET", R + f"/pulls?state=all&limit=2&page={pg}", as_=A)
    for lim in (0, 100, 51, 50, -1):
        r = c.call("GET", R + f"/pulls?state=all&limit={lim}", as_=A)
        c.note(f"pulls_limit_{lim}_count", len(r.json) if isinstance(r.json, list) else -1)
    c.call("GET", R + "/pulls?state=all&limit=abc", as_=A)
    c.call("GET", R + "/pulls?state=all&sort=oldest&limit=5", as_=A)
    c.call("GET", R + "/pulls?state=all&sort=newest&limit=5", as_=A)
    c.call("GET", R + "/pulls?state=all&sort=recentupdate&limit=5", as_=A)
    for pg in (1, 2, 3, 4):
        c.call("GET", R + f"/branches?limit=2&page={pg}", as_=A)
    p = c.wc("pages")
    c.git(["push", "-q", "origin"] + [f"{head}:refs/heads/many{i:02d}" for i in range(55)], cwd=p, rec=False)
    for q in ("", "?limit=100", "?limit=51", "?limit=0", "?page=2", "?limit=50&page=2"):
        r = c.call("GET", R + "/branches" + q, as_=A, rec=False)  # 55 verbose branch objects: keep counts only
        c.note(f"branches{q or '_default'}_count", len(r.json))
        c.note(f"branches{q or '_default'}_headers", {h: r.headers[h].replace(c.base, "<base>") for h in ("x-total-count", "link") if h in r.headers})
    for pg in (1, 2, 3):
        c.call("GET", R + f"/commits/{head}/statuses?limit=2&page={pg}", as_=A)
    for pg in (1, 2):
        c.call("GET", R + f"/statuses/{head}?limit=3&page={pg}", as_=A)
    c.call("GET", R + f"/commits/{head}/status?limit=2&page=1", as_=A)
    c.call("GET", R + f"/commits/{head}/status?limit=2&page=2", as_=A)
    for i in range(1, 4):
        c.mk_repo(f"pgrepo{i}", auto_init=False)
    for pg in (1, 2, 3):
        c.call("GET", f"/repos/search?q=pgrepo&limit=2&page={pg}&sort=alpha")


@scenario("Q", "protection-bypass")
def sc_bypass(c):
    c.mk_repo("bypass")
    R = "/repos/acme/bypass"
    c.call("POST", R + "/branch_protections", {"branch_name": "main", "enable_push": False}, expect=201)
    c.call("POST", R + "/contents/viaapi.txt", {"content": b64("x\n"), "message": "api to main", "branch": "main"}, as_="bot")
    c.call("POST", R + "/contents/viaapi-admin.txt", {"content": b64("x\n"), "message": "api to main", "branch": "main"})
    sha = c.call("GET", R + "/contents/README.md", rec=False).json["sha"]
    c.call("PUT", R + "/contents/README.md", {"content": b64("changed\n"), "message": "put to main", "sha": sha,
                                              "branch": "main"}, as_="bot")
    c.call("POST", R + "/contents/viapr.txt", {"content": b64("x\n"), "message": "api new branch", "branch": "main",
                                               "new_branch": "q-api"}, as_="bot")
    n1, _ = mkpr(c, "bypass", "q1", {"q1.txt": "1\n"})
    c.call("POST", R + f"/pulls/{n1}/merge", {"Do": "merge"}, as_="bot-scoped")
    wait_for(lambda: get_pr(c, "bypass", n1)["merged"])
    # force-push on an unprotected branch
    p = c.wc("bypass", "bot")
    c.git(["fetch", "-q", "origin"], cwd=p, rec=False)
    c.git(["checkout", "-q", "-B", "fp1", "origin/main"], cwd=p, rec=False)
    local_commit(c, p, {"fp.txt": "1\n"})
    c.git(["push", "origin", "HEAD:refs/heads/fp1"], cwd=p, name="push-unprotected-branch")
    c.git(["reset", "-q", "--hard", "origin/main"], cwd=p, rec=False)
    local_commit(c, p, {"fp.txt": "2\n"})
    c.git(["push", "-f", "origin", "HEAD:refs/heads/fp1"], cwd=p, name="force-push-unprotected-branch")
    # non-ff to the protected branch, before and after enable_push
    c.git(["reset", "-q", "--hard", "origin/main~1"], cwd=p, rec=False)
    local_commit(c, p, {"div.txt": "d\n"})
    c.git(["push", "origin", "HEAD:refs/heads/main"], cwd=p, name="nonff-protected-push-disabled")
    c.call("PATCH", R + "/branch_protections/main", {"enable_push": True})
    c.git(["push", "origin", "HEAD:refs/heads/main"], cwd=p, name="nonff-protected-push-enabled")
    c.git(["push", "-f", "origin", "HEAD:refs/heads/main"], cwd=p, name="force-protected-push-enabled")
    c.git(["push", "origin", ":refs/heads/main"], cwd=p, name="delete-protected-push-enabled")
    c.call("PATCH", R + "/branch_protections/main", {"enable_push": False})
    c.git(["push", "origin", ":refs/heads/main"], cwd=p, name="delete-protected-push-disabled")
    c.call("DELETE", R + "/branches/main")
    c.call("DELETE", R + "/branches/main", as_="bot")
    c.call("GET", R + "/branches/main")
    c.call("DELETE", R + "/branch_protections/main")


@scenario("R", "token-scope-edges")
def sc_token_edges(c):
    c.call("POST", "/user/repos", {"name": "scoped2", "auto_init": True, "private": True}, as_="alice", expect=201, rec=False)
    c.mk_token("alice", "po", ["public-only", "read:repository"], "alice-po", rec=True)
    c.call("GET", "/repos/alice/scoped2", as_="alice-po")
    c.call("GET", "/user", as_="alice-po")
    c.call("GET", "/repos/search?limit=50", as_="alice-po")
    c.call("POST", "/users/alice/tokens", {"name": "via-ro", "scopes": ["all"]}, as_="alice-ro")
    c.call("POST", "/users/alice/tokens", {"name": "via-all-token", "scopes": ["all"]}, as_="alice")
    c.principals["alice-tokpw"] = {"kind": "basic", "user": "alice", "secret": c.principals["alice"]["secret"]}
    c.call("POST", "/users/alice/tokens", {"name": "via-token-as-password", "scopes": ["read:repository"]}, as_="alice-tokpw")
    c.call("GET", "/users/alice/tokens", as_="alice-tokpw", volatile=["id", "name", "scopes"])  # order is a tie-break
    c.principals["alice-pw-on-bot"] = {"kind": "basic", "user": "alice", "secret": c.pw["alice"]}
    c.call("POST", "/users/bot/tokens", {"name": "stolen", "scopes": ["all"]}, as_="alice-pw-on-bot")
    c.call("GET", "/users/bot/tokens", as_="alice-pw-on-bot")
    c.call("POST", "/users/alice/tokens", {"name": "badscope", "scopes": ["nonsense"]}, as_="alice-basic")
    c.call("POST", "/users/alice/tokens", {"name": "noscope"}, as_="alice-basic")
    c.call("POST", "/users/alice/tokens", {"name": "", "scopes": ["all"]}, as_="alice-basic")
    c.mk_token("alice", "wo", ["write:organization"], "alice-wo", rec=True)
    c.call("POST", "/orgs", {"username": "botorg"}, as_="bot")
    c.call("POST", "/orgs/botorg/repos", {"name": "intruder"}, as_="alice-wo")
    c.call("POST", "/orgs/botorg/repos", {"name": "intruder"}, as_="alice")
    c.call("POST", "/orgs/botorg/repos", {"name": "legit"}, as_="bot")
    c.call("GET", "/orgs/botorg", as_="alice-wo")
    c.call("GET", "/repos/alice/scoped2", as_="alice-wo")
    c.call("GET", "/repos/alice/scoped2/branches", as_="bot-scoped")


@scenario("S", "ref-pushes")
def sc_refs(c):
    c.mk_repo("refs")
    R = "/repos/acme/refs"
    n1, s1 = mkpr(c, "refs", "r1", {"r1.txt": "1\n"}, settle=1)
    p = c.wc("refs", "bot")
    c.git(["fetch", "-q", "origin"], cwd=p, rec=False)
    c.git(["checkout", "-q", "-B", "work", "origin/main"], cwd=p, rec=False)
    h = local_commit(c, p, {"w.txt": "w\n"})
    c.git(["tag", "-a", "annot", "-m", "annotated", h], cwd=p, rec=False)
    tests = [
        ("replace-ref", f"{h}:refs/replace/{s1}"),
        ("pull-1-head", f"{h}:refs/pull/1/head"),
        ("pull-1-head-forced", f"+{h}:refs/pull/1/head"),
        ("pull-999-head", f"{h}:refs/pull/999/head"),
        ("heads-pull-1-head", f"{h}:refs/heads/pull/1/head"),
        ("lightweight-tag", f"{h}:refs/tags/v-bot"),
        ("annotated-tag", "refs/tags/annot:refs/tags/annot"),
        ("notes-ref", f"{h}:refs/notes/commits"),
        ("for-ref", f"{h}:refs/for/main"),
        ("changes-ref", f"{h}:refs/changes/1/2"),
        ("keep-around-ref", f"{h}:refs/keep-around/{h}"),
        ("arbitrary-ref", f"{h}:refs/custom/thing"),
        ("tag-delete", ":refs/tags/v-bot"),
    ]
    for name, spec in tests:
        c.git(["push", "origin", spec], cwd=p, name="bot-push-" + name)
    c.git(["push", c.git_url("refs", "carol"), f"{h}:refs/tags/v-carol"], cwd=p, name="read-collab-push-tag")
    c.git(["ls-remote", c.git_url("refs", "admin")], name="ls-remote-all-refs", note_stdout=True)
    advert_probe(c, "refs", "refs")
    c.call("GET", R + "/git/refs", as_="bot-scoped")
    c.call("GET", R + "/tags", as_="bot-scoped")
    c.call("GET", R + f"/pulls/{n1}", as_="bot-scoped", volatile=["mergeable"])


@scenario("T", "merge-outcomes")
def sc_outcomes(c):
    c.mk_repo("outcomes")
    R, A = "/repos/acme/outcomes", "bot-scoped"
    wcp = c.wc("outcomes")

    def getpr(n):
        return c.call("GET", R + f"/pulls/{n}", as_=A, volatile=["mergeable"])

    def try_pr(title, head, raw_note=None):
        """Open a PR and record what Gitea says about it and about merging it."""
        r = c.call("POST", R + "/pulls", {"title": title, "head": head, "base": "main"}, as_=A, volatile=["mergeable"])
        if r.status == 201:
            n = r.json["number"]
            time.sleep(6)
            getpr(n)
            m = c.call("POST", R + f"/pulls/{n}/merge", {"Do": "merge"}, as_=A, no_retry=True,
                       volatile=["$text"])  # 1.26 sends a truncated JSON body here, sometimes empty
            if raw_note:
                c.note(raw_note, c.ns(m.text), strict=False)
            getpr(n)
        return r

    c.push_branch("outcomes", "orph", {"orph.txt": "o\n"}, base=None)
    try_pr("unrelated", "orph", raw_note="unrelated_merge_exact_body")
    c.push_branch("outcomes", "tid", {"t.txt": "t\n"})
    c.git(["rm", "-q", "t.txt"], cwd=wcp, rec=False)
    c.git(["commit", "-q", "-m", "remove t"], cwd=wcp, rec=False)
    c.git(["push", "-q", "-f", "origin", "HEAD:refs/heads/tid"], cwd=wcp, rec=False)
    try_pr("same tree", "tid")
    cont = c.push_branch("outcomes", "cont", {"cont.txt": "c\n"})
    c.git(["push", "-q", "origin", f"{cont}:refs/heads/main"], cwd=wcp, rec=False)
    try_pr("contained", "cont")
    n1, _ = mkpr(c, "outcomes", "ok1", {"ok1.txt": "1\n"}, more=[{"ok1b.txt": "2\n"}])
    getpr(n1)
    c.call("POST", R + f"/pulls/{n1}/merge", {"Do": "merge"}, as_=A)
    wait_for(lambda: get_pr(c, "outcomes", n1)["merged"])
    getpr(n1)
    c.call("POST", R + f"/pulls/{n1}/merge", {"Do": "merge"}, as_=A)
    c.push_branch("outcomes", "cbase", {"cf.txt": "base\n"})
    c.git(["push", "-q", "origin", "origin/cbase:refs/heads/main"], cwd=wcp, rec=False)
    na, _ = mkpr(c, "outcomes", "cfa", {"cf.txt": "a\n"})
    nb, _ = mkpr(c, "outcomes", "cfb", {"cf.txt": "b\n"})
    c.call("POST", R + f"/pulls/{na}/merge", {"Do": "merge"}, as_=A)
    time.sleep(8)
    cf = c.call("GET", R + f"/pulls/{nb}", as_=A, settle_keys=["mergeable"], strict_keys=["mergeable"])
    if c.mode == "record" and cf.json.get("mergeable") is not False:
        raise SetupError(f"the conflicting PR settled as mergeable={cf.json.get('mergeable')!r}")
    c.call("POST", R + f"/pulls/{nb}/merge", {"Do": "merge"}, as_=A, no_retry=True)
    c.call("PATCH", R + f"/pulls/{nb}", {"state": "closed"}, as_=A)
    c.call("GET", R + f"/pulls/{nb}", as_=A)


@scenario("U", "status-check-edges")
def sc_check_edges(c):
    c.mk_repo("checks")
    R, A = "/repos/acme/checks", "bot-scoped"
    n1, h1 = mkpr(c, "checks", "u1", {"u1.txt": "1\n"})
    main_sha = c.head("checks")
    c.call("POST", R + "/branch_protections", {"branch_name": "main", "enable_push": False,
                                               "enable_status_check": True, "status_check_contexts": ["ci/test"]},
           expect=201)

    def post(sha, state, ctx):
        c.call("POST", R + f"/statuses/{sha}", {"state": state, "context": ctx}, expect=201, rec=False)

    def merge(n):
        return c.call("POST", R + f"/pulls/{n}/merge", {"Do": "merge"}, as_=A)

    post(main_sha, "success", "ci/test")
    merge(n1)  # a status exists, but on another commit
    for state in ("warning", "error", "failure", "pending"):
        post(h1, state, "ci/test")
        merge(n1)
    post(h1, "success", "ci/other")
    merge(n1)  # wrong context
    post(h1, "skipped", "ci/test")
    merge(n1)  # `skipped` on the required context
    wait_for(lambda: get_pr(c, "checks", n1)["merged"])
    c.call("GET", R + f"/pulls/{n1}", as_=A, volatile=["mergeable"])
    n3, h3 = mkpr(c, "checks", "u3", {"u3.txt": "3\n"})
    post(h3, "success", "ci/test")
    merge(n3)
    # status posted, then the head moves
    n2, h2 = mkpr(c, "checks", "u2", {"u2.txt": "2\n"})
    post(h2, "success", "ci/test")
    h2b = c.push_branch("checks", "u2", {"u2b.txt": "b\n"}, base="origin/u2")
    wait_for(lambda: get_pr(c, "checks", n2)["head"]["sha"] == h2b)
    merge(n2)
    post(h2b, "success", "ci/test")
    merge(n2)
    c.call("DELETE", R + "/branch_protections/main")


@scenario("V", "smart-http-bytes")
def sc_wire(c):
    import gzip
    c.mk_repo("wire")
    head = c.head("wire")
    for svc in ("git-upload-pack", "git-receive-pack"):
        c.call("GET", f"/acme/wire.git/info/refs?service={svc}", as_="admin-tokbasic", api=False,
               track=("cache-control", "expires", "pragma"), volatile=["$text"],
               must_contain=[f"001e# service=git-upload-pack\n0000" if svc == "git-upload-pack"
                             else "001f# service=git-receive-pack\n0000"])
        c.call("GET", f"/acme/wire.git/info/refs?service={svc}", api=False, as_="none",
               track=("cache-control", "expires", "pragma"), volatile=["$text"])
    r = c.call("GET", "/acme/wire.git/info/refs?service=git-upload-pack", as_="admin-tokbasic", api=False,
               headers={"Git-Protocol": "version=2"}, track=("cache-control",), volatile=["$text"])
    c.note("v2_advert_first_bytes", r.data[:46].decode("latin-1").replace("\n", "\\n"))
    def advert_notes(svc, label):
        r = c.call("GET", f"/acme/wire.git/info/refs?service={svc}", as_="admin-tokbasic", api=False, volatile=["$text"])
        d = r.data
        c.note(f"{label}_preamble", d[:d.find(b"0000") + 4].decode("latin-1").replace("\n", "\\n"))
        first = d[d.find(b"0000") + 4:]
        caps = first.split(b"\x00", 1)[1].split(b"\n", 1)[0].decode("latin-1") if b"\x00" in first else ""
        c.note(f"{label}_capabilities", re.sub(r"agent=git/\S+", "agent=git/<v>", caps), strict=False)
        c.note(f"{label}_first_pkt_prefix", first[:4].decode("latin-1"), strict=False)

    advert_notes("git-upload-pack", "v0_upload")
    advert_notes("git-receive-pack", "receive")
    c.call("GET", "/acme/wire.git/HEAD", as_="admin-tokbasic", api=False)
    c.call("GET", "/acme/wire.git/objects/info/packs", as_="admin-tokbasic", api=False)
    want = f"want {head} side-band-64k ofs-delta\n".encode()
    req = b"%04x" % (len(want) + 4) + want + b"0000" + b"0009done\n"
    ct = {"Content-Type": "application/x-git-upload-pack-request", "Accept": "application/x-git-upload-pack-result"}
    r1 = c.call("POST", "/acme/wire.git/git-upload-pack", data=req, headers=ct, as_="admin-tokbasic", api=False,
                binary=True, track=("cache-control",))
    c.note("plain_upload_pack_response_head", r1.data[:8].decode("latin-1"))
    r2 = c.call("POST", "/acme/wire.git/git-upload-pack", data=gzip.compress(req),
                headers=dict(ct, **{"Content-Encoding": "gzip"}), as_="admin-tokbasic", api=False, binary=True,
                track=("cache-control",))
    c.note("gzip_upload_pack_response_head", r2.data[:8].decode("latin-1"))
    c.call("POST", "/acme/wire.git/git-upload-pack", data=req, headers=ct, as_="none", api=False)
    c.call("POST", "/acme/wire.git/git-receive-pack", data=b"0000", as_="none", api=False,
           headers={"Content-Type": "application/x-git-receive-pack-request"})
    c.call("POST", "/acme/wire.git/git-upload-pack", data=req, headers=ct, as_="dave-tokbasic", api=False)


@scenario("W", "protected-contents")
def sc_protected_contents(c):
    c.mk_repo("pcont")
    R = "/repos/acme/pcont"
    c.call("POST", R + "/branch_protections", {"branch_name": "main", "enable_push": True}, expect=201)
    for who in ("bot", "admin"):
        c.call("POST", R + f"/contents/w1-{who}.txt", {"content": b64("x\n"), "message": "create on main",
                                                       "branch": "main"}, as_=who)
    sha = c.call("GET", R + "/contents/README.md", rec=False).json["sha"]
    c.call("PUT", R + "/contents/README.md", {"content": b64("pushable\n"), "message": "update on main", "sha": sha,
                                              "branch": "main"}, as_="bot")
    # now require ci/test and post nothing
    c.call("PATCH", R + "/branch_protections/main", {"enable_status_check": True, "status_check_contexts": ["ci/test"]})
    for who in ("bot", "admin"):
        c.call("POST", R + f"/contents/w2-{who}.txt", {"content": b64("x\n"), "message": "create, check unmet",
                                                       "branch": "main"}, as_=who)
    sha = c.call("GET", R + "/contents/README.md", rec=False).json["sha"]
    c.call("PUT", R + "/contents/README.md", {"content": b64("again\n"), "message": "update, check unmet",
                                              "sha": sha, "branch": "main"}, as_="bot")
    # direct fast-forward push: enable_push:true + required context unmet
    p = c.wc("pcont", "bot")
    c.git(["fetch", "-q", "origin"], cwd=p, rec=False)
    c.git(["checkout", "-q", "-B", "work", "origin/main"], cwd=p, rec=False)
    local_commit(c, p, {"ff.txt": "ff\n"})
    c.git(["push", "origin", "HEAD:refs/heads/main"], cwd=p, name="ff-push-enable-push-status-unmet")
    # and once the required context has succeeded on the tip
    tip = c.head("pcont")
    c.call("POST", R + f"/statuses/{tip}", {"state": "success", "context": "ci/test"}, expect=201, rec=False)
    c.call("POST", R + "/contents/w3-bot.txt", {"content": b64("x\n"), "message": "create, check met", "branch": "main"},
           as_="bot")
    c.call("GET", R + "/branch_protections/main")


@scenario("X", "auth-forms")
def sc_auth_forms(c):
    c.mk_repo("authrepo")
    R = "/repos/acme/authrepo"
    sha = c.head("authrepo")
    tok = c.principals["bot"]["secret"]
    c.principals["bot-bearer"] = dict(c.principals["bot"], kind="bearer")
    c.principals["bot-basic-token-password"] = dict(c.principals["bot"], kind="basic")
    c.principals["bot-basic-token-user"] = dict(c.principals["bot"], kind="basic-nopass")
    c.principals["bot-basic-oauth2"] = dict(c.principals["bot"], kind="basic", user="oauth2")
    c.principals["bot-basic-other-name"] = dict(c.principals["bot"], kind="basic", user="someone")
    c.principals["bad-bearer"] = dict(c.principals["bad"], kind="bearer")
    c.principals["bad-basic-token-user"] = dict(c.principals["bad"], kind="basic-nopass")
    c.principals["bot-basic-password"] = {"kind": "basic", "user": "bot", "secret": c.pw["bot"]}
    forms = ["bot", "bot-bearer", "bot-basic-token-password", "bot-basic-token-user", "bot-basic-oauth2",
             "bot-basic-other-name", "bot-basic-password", "bad-bearer", "bad-basic-token-user"]
    for i, who in enumerate(forms):
        c.call("GET", "/user", as_=who)
        c.call("GET", R, as_=who)
        c.call("POST", R + f"/statuses/{sha}", {"state": "success", "context": f"auth-{i}"}, as_=who)
    # site admin with a password
    pw = c.new_password()
    c.call("POST", "/admin/users", {"username": "siteowner", "email": "siteowner@example.invalid", "password": pw,
                                    "must_change_password": False}, expect=201, rec=False)
    c.call("PATCH", "/admin/users/siteowner", {"login_name": "siteowner", "source_id": 0, "admin": True}, expect=200, rec=False)
    c.principals["siteowner-pw"] = {"kind": "basic", "user": "siteowner", "secret": pw}
    c.call("GET", "/user", as_="siteowner-pw")
    r = c.call("POST", "/users/bot/tokens", {"name": "by-site-admin-password", "scopes": ["read:repository"]},
               as_="siteowner-pw")
    c.call("GET", "/users/bot/tokens", as_="siteowner-pw", volatile=["id", "name", "scopes"])  # same-second tie order
    c.call("POST", "/users/bot/tokens", {"name": "by-admin-token", "scopes": ["read:repository"]}, as_="admin")
    # a read-only token used as the Basic password mints what?
    c.principals["alice-ro-as-password"] = {"kind": "basic", "user": "alice", "secret": c.principals["alice-ro"]["secret"]}
    r = c.call("POST", "/users/alice/tokens", {"name": "minted-by-readonly-token", "scopes": ["all"]},
               as_="alice-ro-as-password")
    c.note("readonly_token_as_password_status", r.status)
    if r.status == 201:
        c.secrets.add(r.json["sha1"])
        c.principals["minted"] = {"kind": "token", "user": "alice", "secret": r.json["sha1"]}
        c.call("POST", "/user/repos", {"name": "minted-probe", "private": True}, as_="minted")
    c.call("GET", "/users/alice/tokens", as_="alice-ro-as-password", volatile=["id", "name", "scopes"])


# @@SCENARIOS@@

if __name__ == "__main__":
    main()
