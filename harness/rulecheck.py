"""Each new rule gets a line it must flag and a benign twin it must not.

The twins are the point: a rule that fires on the vulnerable line and also on
the safe one buys recall with precision the clean-repo branch charges for.
"""
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "agent"))
from phylax_agent import _VULN_RULES

CASES = [
    # cwe,        must flag,                                            must not flag
    ("CWE-918", 'r = requests.get(request.args["url"])',
                'r = requests.get(f"{BASE_URL}/health", timeout=5)'),
    ("CWE-918", 'const r = await fetch(req.query.target)',
                'const r = await fetch(`${API_ROOT}/v1/status`)'),
    ("CWE-611", 'parser = etree.XMLParser(resolve_entities=True)',
                'parser = etree.XMLParser(resolve_entities=False)'),
    ("CWE-601", 'return redirect(request.args.get("next"))',
                'return redirect(url_for("dashboard"))'),
    ("CWE-22",  'tar.extractall(dest)',
                'tar.extractall(dest, filter="data")'),
    ("CWE-943", 'users.find({"name": req.body.name})',
                'users.find({"name": sanitise(name)})'),
    ("CWE-90",  'conn.search_s(base, scope, "(uid=" + username + ")")',
                'conn.search_s(base, scope, "(uid=%s)", [escape(username)])'),
    ("CWE-915", 'Object.assign(user, req.body)',
                'Object.assign(user, {name: req.body.name})'),
    ("CWE-614", 'resp.set_cookie("sid", sid, httponly=False)',
                'resp.set_cookie("sid", sid, httponly=True, secure=True)'),
    ("CWE-1336", 'return render_template_string(user_supplied)',
                 'return render_template("page.html", name=name)'),
    # The reclassification must not cost the XSS rule its own cases.
    ("CWE-79",  'el.innerHTML = untrustedHtml',
                'el.textContent = untrustedHtml'),
    # Untrusted data in a non-URL argument is a payload, not an SSRF target.
    ("CWE-918", 'requests.get(request.host_url + path)',
                'requests.post(API_URL, json=body, params=params)'),
    ("CWE-90",  'conn.search_s(base, scope, "(uid=%s)" % username)',
                'conn.search_s(base, scope, filt, ["cn"])'),
    ("CWE-943", 'db.users.find({"owner": request.args["u"]})',
                'db.users.find({"query": q, "body": text})'),
]


def cwes_for(line):
    return {cwe for pat, cwe, *_ in _VULN_RULES if pat.search(line)}


bad = 0
for cwe, positive, benign in CASES:
    hit = cwe in cwes_for(positive)
    pos_extra = cwes_for(positive) - {cwe}
    twin = cwes_for(benign)
    ok = hit and not twin
    bad += not ok
    print(f"{'ok ' if ok else 'FAIL'} {cwe:9} flag={hit!s:5} twin_fires={sorted(twin) or '-'}"
          f" also={sorted(pos_extra) or '-'}")

print("\nFAILURES:", bad)
sys.exit(1 if bad else 0)
