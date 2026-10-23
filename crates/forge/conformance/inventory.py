#!/usr/bin/env python3
"""Print the distinct HTTP route shapes recorded in a fixture directory.

usage: python3 -I inventory.py fixtures/1.22.6 [--count]

Path positions are templated structurally ({owner}, {repo}, {n}, {sha}, {name}), so
the list does not depend on the names a scenario happened to use. Used to keep the
spec's "Appendix A" honest: every route printed here has one decision there.
"""
import collections
import glob
import json
import re
import sys


def template(path):
    path = path.split("?")[0]
    path = re.sub(r"<id:[^>]*>", "{n}", path)
    path = re.sub(r"<sha[^>]*>|\b[0-9a-f]{40}\b", "{sha}", path)
    parts = path.split("/")
    out = []
    i = 0
    while i < len(parts):
        p = parts[i]
        out.append(p)
        if p == "repos" and parts[i - 1:i] == ["v1"] and parts[i + 1:i + 2] != ["search"]:
            for slot in ("{owner}", "{repo}"):
                i += 1
                if i < len(parts):
                    out.append(slot)
        elif p in ("orgs", "users", "teams") and parts[i - 1:i] in (["v1"], ["api"]):
            i += 1
            if i < len(parts):
                out.append("{org}" if p == "orgs" else "{name}")
        elif p == "users" and parts[i - 1:i] == ["admin"]:
            i += 1
            if i < len(parts):
                out.append("{name}")
        elif p == "collaborators":
            i += 1
            if i < len(parts):
                out.append("{name}")
        i += 1
    path = "/".join(out)
    path = re.sub(r"/\d+(?=/|\.|$)", "/{n}", path)
    path = re.sub(r"(/pulls/\{n\})\.(diff|patch)$", r"\1.\2", path)
    if not path.startswith("/api/"):  # web UI and git routes: /{owner}/{repo}[.git]/...
        segs = path.split("/")
        if len(segs) > 2:
            segs[1], segs[2] = "{owner}", re.sub(r"^[^.]+", "{repo}", segs[2])
        path = "/".join(segs)
    return path


def main():
    d = sys.argv[1]
    routes = collections.defaultdict(set)
    for p in sorted(glob.glob(d.rstrip("/") + "/[A-Z]-*.json")):
        f = json.load(open(p))
        for e in f["exchanges"]:
            if e.get("kind") == "http":
                routes[(e["method"], template(e["path"]))].add(f["scenario"])
    if "--count" in sys.argv:
        print(len(routes))
        return
    print(f"{len(routes)} distinct HTTP route shapes")
    for (m, t), s in sorted(routes.items(), key=lambda x: (x[0][1], x[0][0])):
        print(f"{m:6} {t}   [{','.join(sorted(s))}]")


if __name__ == "__main__":
    main()
