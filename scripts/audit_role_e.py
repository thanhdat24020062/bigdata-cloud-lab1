#!/usr/bin/env python3
import os, re, json, csv, hashlib, subprocess, sys, shutil
from datetime import date, datetime

ROOT = os.getcwd()
SELF = os.path.abspath(__file__)
stats = {"PASS": 0, "WARN": 0, "FAIL": 0}

def rec(level, msg):
    stats[level] += 1
    print(f"[{level}] {msg}")

def check(cond, ok, bad, level="FAIL"):
    rec("PASS" if cond else level, ok if cond else bad)
    return bool(cond)

def head(t): print(f"\n=== {t} ===")

files = []
for d, dirs, fs in os.walk(ROOT):
    dirs[:] = [x for x in dirs if x != ".git"]
    for f in fs:
        p = os.path.join(d, f)
        if os.path.abspath(p) != SELF:
            files.append(p)
rel = lambda p: os.path.relpath(p, ROOT)

def text(p):
    try:
        if os.path.getsize(p) > 5_000_000: return ""
        return open(p, errors="replace").read()
    except Exception:
        return ""

def jl(p):
    rows = []
    for line in text(p).splitlines():
        line = line.strip()
        if line.startswith("{"):
            try: rows.append(json.loads(line))
            except Exception: pass
    if not rows:
        try:
            d = json.loads(text(p))
            rows = d if isinstance(d, list) else [d]
        except Exception:
            pass
    return rows

def first_uid(p):
    m = re.findall(r"^( *)(?:- )?uid: (\S+)", text(p), re.M)
    return min(m, key=lambda x: len(x[0]))[1] if m else None

def one(name):
    for f in files:
        if os.path.basename(f) == name: return f
    return None

def git(*a):
    try:
        r = subprocess.run(["git", *a], capture_output=True, text=True, cwd=ROOT)
        return r.returncode, r.stdout.strip()
    except Exception:
        return 1, ""

ev = [f for f in files if rel(f).startswith("evidence" + os.sep)]
FIX = hashlib.sha256(b"research-landing-zone-v1\n").hexdigest()

# ---------- A ----------
head("A. Cấu trúc bundle (mục 10 của đề)")
root_need = ["README.md", "policies-redacted.json", "governance.json", "security-results.csv",
             "benchmark-summary.csv", "recovery-summary.json", "contribution.csv"]
for n in root_need:
    if os.path.isfile(os.path.join(ROOT, n)): rec("PASS", f"Có {n} ở root")
    elif one(n): rec("WARN", f"{n} có nhưng sai vị trí: {rel(one(n))}")
    else: rec("WARN" if n in ("policies-redacted.json","security-results.csv","benchmark-summary.csv","contribution.csv") else "FAIL",
              f"Thiếu {n} (của người khác thì cần đôn đốc)" if n in ("policies-redacted.json","security-results.csv","benchmark-summary.csv","contribution.csv") else f"Thiếu {n}")
for d in ("manifests", "evidence", "individual"):
    n = len([f for f in files if rel(f).startswith(d + os.sep) and os.path.basename(f) != ".gitkeep"])
    check(n > 0, f"{d}/ có {n} file", f"{d}/ không có file nào (chỉ rỗng/.gitkeep)")
empty = []
for d, dirs, fs in os.walk(ROOT):
    dirs[:] = [x for x in dirs if x != ".git"]
    if d != ROOT and not [f for f in os.listdir(d) if f != ".gitkeep"]:
        empty.append(rel(d))
check(not empty, "Không có thư mục rỗng", f"Thư mục rỗng (điền nội dung hoặc xóa): {empty}", "WARN")

# ---------- B ----------
head("B. Task 5 – evidence recovery")
need = ["pod-before.yaml","pvc-before.yaml","canary.jsonl","delete-time.txt","pod-after.yaml",
        "pvc-after.yaml","before-recovery.jsonl","after-recovery.jsonl","events.txt","pod-logs.txt"]
P = {}
for n in need:
    P[n] = one(n)
    check(P[n] and os.path.getsize(P[n]) > 0, f"{n} OK", f"Thiếu/rỗng: {n}")
pu_b = first_uid(P["pod-before.yaml"]) if P["pod-before.yaml"] else None
pu_a = first_uid(P["pod-after.yaml"]) if P["pod-after.yaml"] else None
pv_b = first_uid(P["pvc-before.yaml"]) if P["pvc-before.yaml"] else None
pv_a = first_uid(P["pvc-after.yaml"]) if P["pvc-after.yaml"] else None
if pu_b and pu_a: check(pu_b != pu_a, f"Pod UID đổi ({pu_b[:8]} → {pu_a[:8]})", "Pod UID KHÔNG đổi – chưa chứng minh thay Pod")
else: rec("FAIL", "Không đọc được Pod UID trước/sau")
if pv_b and pv_a: check(pv_b == pv_a, f"PVC UID giữ nguyên ({pv_b[:8]})", "PVC UID khác nhau – PVC bị tạo lại?")
else: rec("FAIL", "Không đọc được PVC UID trước/sau")
for n in ("pvc-before.yaml", "pvc-after.yaml"):
    if P[n]: check("phase: Bound" in text(P[n]), f"{n}: Bound", f"{n}: không Bound")
if P["pod-before.yaml"] and P["pod-after.yaml"]:
    nb = re.search(r"nodeName: (\S+)", text(P["pod-before.yaml"])); na = re.search(r"nodeName: (\S+)", text(P["pod-after.yaml"]))
    if nb and na: rec("PASS", f"Node trước/sau: {nb.group(1)} → {na.group(1)}" + ("" if nb.group(1)==na.group(1) else " (KHÁC node – local-path PV có thể không đi theo, cần giải thích)"))
    check(re.search(r"imageID:.*sha256:[0-9a-f]{64}", text(P["pod-after.yaml"])), "pod-after có imageID digest thật", "pod-after thiếu imageID sha256 thật")
for k in ("before-recovery.jsonl", "after-recovery.jsonl"):
    if P[k]:
        rows = jl(P[k])
        good = [r for r in rows if r.get("op") == "get" and r.get("ok") and r.get("hash_ok") is True]
        ver = [r for r in rows if r.get("kind") == "verified"]
        check(len(good) == 32 and ver, f"{k}: 32/32 hash đúng + 'verified'", f"{k}: {len(good)}/32 hash đúng, verified={bool(ver)}")
hb = {r.get("key"): r.get("sha256") for r in jl(P["before-recovery.jsonl"]) if r.get("sha256")} if P["before-recovery.jsonl"] else {}
ha = {r.get("key"): r.get("sha256") for r in jl(P["after-recovery.jsonl"]) if r.get("sha256")} if P["after-recovery.jsonl"] else {}
if hb and ha: check(hb == ha, "Hash từng object trước = sau recovery", "Hash trước/sau KHÁC nhau – dữ liệu bị đổi!")
if P["delete-time.txt"]:
    check(re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", text(P["delete-time.txt"])), "delete-time.txt đúng định dạng ISO", "delete-time.txt sai định dạng", "WARN")
if P["events.txt"]:
    t = text(P["events.txt"]); check(re.search(r"Killing|Started|Created|Scheduled", t), "events.txt có sự kiện thay Pod", "events.txt không thấy Killing/Started/Scheduled", "WARN")

# ---------- C ----------
head("C. Canary + recovery-summary.json")
calc = None
if P["canary.jsonl"]:
    rows = sorted([r for r in jl(P["canary.jsonl"]) if "start_s" in r], key=lambda r: r["start_s"])
    fails = [r for r in rows if not r.get("ok")]
    check(len(rows) > 0, f"Canary: {len(rows)} mẫu, {len(fails)} lần fail", "Canary không có mẫu hợp lệ")
    ff = next((i for i, r in enumerate(rows) if not r.get("ok")), None)
    if rows and ff is None:
        calc = "none"; rec("WARN", "Canary không thấy lỗi → ghi 'interruption not observed at this sampling resolution', KHÔNG ghi 'zero downtime'")
    elif rows:
        run, stable = [], None
        for j in range(ff + 1, len(rows)):
            if rows[j].get("ok"):
                run.append(j)
                if len(run) == 5: stable = rows[run[0]]["end_s"]; break
            else: run = []
        if stable is None: rec("FAIL", "Không có 5 lần đọc đúng liên tiếp sau lỗi đầu – chưa đủ thời gian watch hoặc chưa recover")
        else:
            calc = (rows[ff]["start_s"], stable, stable - rows[ff]["start_s"], len(fails))
            check(calc[2] <= 120, f"T_observed tự tính = {calc[2]:.2f}s (t_failure={calc[0]:.2f}, t_stable={calc[1]:.2f}, {calc[3]} read fail)", f"T_observed = {calc[2]:.2f}s > 120s – cần chẩn đoán")
sm = one("recovery-summary.json")
if sm:
    try:
        S = json.load(open(sm))
        nulls = [k for k, v in S.items() if v is None]
        check(not nulls, "recovery-summary: không còn null", f"Còn null: {nulls}")
        check(S.get("sampling_limit") not in (None, "describe", ""), "sampling_limit đã mô tả", "sampling_limit còn placeholder")
        check(S.get("pod_uid_changed") is True, "pod_uid_changed=true", f"pod_uid_changed={S.get('pod_uid_changed')}")
        check(S.get("pvc_uid_unchanged") is True, "pvc_uid_unchanged=true", f"pvc_uid_unchanged={S.get('pvc_uid_unchanged')}")
        check(S.get("verified_before") in (32, True) and S.get("verified_after") in (32, True), "verified_before/after = 32", f"verified: {S.get('verified_before')}/{S.get('verified_after')}")
        check({"S06","S08","S10"} <= set(S.get("policy_retests", [])), "policy_retests có S06,S08,S10", "policy_retests thiếu S06/S08/S10")
        unp = " ".join(map(str, S.get("unproven", []))).lower()
        check(all(w in unp for w in ("ha", "backup", "node")), "unproven nêu HA/backup/node-loss", "unproven thiếu HA/backup/node-loss")
        if isinstance(calc, tuple) and S.get("observed_interruption_s") is not None:
            check(abs(float(S["observed_interruption_s"]) - calc[2]) < 0.5, "observed_interruption_s khớp số tính lại", f"Lệch: file ghi {S['observed_interruption_s']} vs tính lại {calc[2]:.2f}")
        if isinstance(calc, tuple) and S.get("first_failure_start_s") is not None:
            check(abs(float(S["first_failure_start_s"]) - calc[0]) < 0.5, "first_failure_start_s khớp", f"first_failure_start_s lệch: {S['first_failure_start_s']} vs {calc[0]:.2f}", "WARN")
        if calc == "none":
            check("not observed" in json.dumps(S).lower(), "Summary dùng cách nói 'not observed'", "Canary không có lỗi nhưng summary không ghi 'not observed'", "WARN")
    except Exception as e:
        rec("FAIL", f"recovery-summary.json lỗi parse: {e}")

# ---------- D ----------
head("D. Retest sau recovery + independent check (verify B)")
exp = {"S06": ("allow", "analyst"), "S08": ("deny", "analyst"), "S10": ("deny", "analyst")}
for tid, (kind, who) in exp.items():
    p = one(f"{tid}-retest.json")
    if not p: rec("FAIL", f"Thiếu {tid}-retest.json"); continue
    rows = jl(p); r = rows[0] if rows else {}
    if kind == "allow":
        check(r.get("ok") and r.get("http") == 200, f"{tid}: allow, HTTP 200", f"{tid}: không phải allow thành công → {r.get('http')}/{r.get('error')}")
    else:
        check(r.get("http") == 403 and r.get("error") == "AccessDenied", f"{tid}: deny đúng (403 AccessDenied)", f"{tid}: không phải 403 AccessDenied → {r.get('http')}/{r.get('error')} (timeout/404 = inconclusive)")
    check(r.get("principal") == who, f"{tid}: principal={who}", f"{tid}: principal={r.get('principal')} (kỳ vọng {who})", "WARN")
for n in ("E-hash-check-raw.json", "E-hash-check-release.json"):
    p = one(n)
    if p: check(FIX in text(p), f"{n}: có SHA-256 fixture đúng", f"{n}: không chứa SHA-256 fixture {FIX[:12]}…")
    else: rec("FAIL", f"Thiếu {n}")
p = one("pvc-binding-check.yaml")
if p:
    t = text(p)
    check("Bound" in t, "pvc-binding-check: Bound", "pvc-binding-check: không Bound")
    check(re.search(r"volumeName: \S+", t), "pvc-binding-check: có volumeName", "pvc-binding-check: thiếu volumeName", "WARN")
    check("storageClassName" in t, "pvc-binding-check: có StorageClass", "pvc-binding-check: thiếu storageClassName", "WARN")
tp = one("topology.txt")
if tp: check("object-data" in text(tp), "topology.txt nhắc PVC object-data", "topology.txt không thấy object-data", "WARN")

# ---------- E ----------
head("E. governance.json")
g = os.path.join(ROOT, "governance.json")
recs = []
if os.path.isfile(g):
    try:
        d = json.load(open(g)); recs = d if isinstance(d, list) else [d]
    except Exception as e:
        rec("FAIL", f"governance.json không parse được: {e}")
else:
    rec("FAIL", "Thiếu governance.json ở root")
keys = ["bucket","owner","steward","classification","purpose","retention","retention_enforced","cleanup_owner","access_policy","verified_tests","approved_by","policy_revision"]
check({r.get("bucket") for r in recs} >= {"research-raw","research-release"}, "Có record cho cả 2 bucket", "Thiếu record của 1 trong 2 bucket")
sec = one("security-results.csv"); sec_txt = {}
if sec:
    for row in csv.reader(open(sec, errors="replace")):
        m = next((c.strip() for c in row if re.fullmatch(r"[SKN]\d\d", c.strip())), None)
        if m: sec_txt[m] = " ".join(row).lower()
for r in recs:
    b = r.get("bucket")
    miss = [k for k in keys if k not in r]
    check(not miss, f"[{b}] đủ 12 trường", f"[{b}] thiếu trường: {miss}")
    check(r.get("retention_enforced") is False, f"[{b}] retention_enforced=false", f"[{b}] retention_enforced không phải false")
    check(re.fullmatch(r"[0-9a-f]{7,40}", str(r.get("policy_revision",""))), f"[{b}] policy_revision dạng hash", f"[{b}] policy_revision không phải hash: {r.get('policy_revision')}")
    rc, _ = git("cat-file", "-e", str(r.get("policy_revision","")) + "^{commit}")
    check(rc == 0, f"[{b}] commit {r.get('policy_revision')} tồn tại trong git", f"[{b}] commit {r.get('policy_revision')} KHÔNG có trong git repo này")
    for k in ("owner","steward","approved_by"):
        check(re.fullmatch(r"student-[A-E]|\d{6,}", str(r.get(k,""))), f"[{b}] {k}={r.get(k)}", f"[{b}] {k} sai định dạng student ID: {r.get(k)}", "WARN")
    dm = re.search(r"(\d{4}-\d{2}-\d{2})", str(r.get("retention","")))
    if dm:
        try:
            dd = datetime.strptime(dm.group(1), "%Y-%m-%d").date()
            check(dd > date.today(), f"[{b}] ngày cleanup {dd} ở tương lai (nhớ xác nhận = hết chấm + 7 ngày)", f"[{b}] ngày cleanup {dd} đã qua")
        except ValueError: rec("FAIL", f"[{b}] ngày cleanup không hợp lệ: {dm.group(1)}")
    else: rec("WARN", f"[{b}] chưa có ngày cleanup cụ thể")
    if sec_txt:
        bad = [t for t in r.get("verified_tests", []) if t not in sec_txt or "pass" not in sec_txt[t]]
        check(not bad, f"[{b}] verified_tests đều pass trong CSV", f"[{b}] test không pass/không có trong CSV: {bad}")
    else:
        rec("WARN", f"[{b}] chưa có security-results.csv để đối chiếu verified_tests (chờ C)")
if sec_txt:
    expct = [f"S{i:02d}" for i in range(1,13)] + [f"K{i:02d}" for i in range(1,7)] + [f"N{i:02d}" for i in range(1,5)]
    check(all(i in sec_txt for i in expct), "security-results.csv đủ 22 test", f"Thiếu: {[i for i in expct if i not in sec_txt]}")
    bad = [i for i, t in sec_txt.items() if "inconclusive" in t or re.search(r"\bfail\b", t)]
    check(not bad, "Không còn test fail/inconclusive", f"fail/inconclusive: {bad} (giữ bản fail + retest)", "WARN")

# ---------- F ----------
head("F. README / evidence index / contribution / individual")
rd = os.path.join(ROOT, "README.md")
if os.path.isfile(rd):
    w = len(re.findall(r"\S+", text(rd)))
    check(300 <= w <= 500, f"README {w} từ (300–500)", f"README {w} từ – ngoài 300–500")
    low = text(rd).lower()
    check(all(x in low for x in ("limit", "design")) or all(x in low for x in ("hạn chế", "thiết kế")), "README có design + limitations", "README thiếu phần design/limitations", "WARN")
idx = [f for f in files if re.search(r"index", os.path.basename(f), re.I)]
if idx:
    it = "".join(text(i) for i in idx) + (text(rd) if os.path.isfile(rd) else "")
    miss = [rel(f) for f in ev if os.path.basename(f) not in it and f not in idx and os.path.basename(f) != ".gitkeep"]
    check(not miss, f"Index ({rel(idx[0])}) liệt kê hết evidence", f"Index thiếu {len(miss)} file: {miss[:6]}", "WARN")
    check("TODO" not in "".join(text(i) for i in idx), "Index không còn TODO", "Index còn TODO chưa mô tả")
else: rec("FAIL", "Chưa có evidence index (evidence/INDEX.md)")
cf = one("contribution.csv")
if cf:
    h = (text(cf).splitlines() or [""])[0].lower()
    check(all(w in h for w in ("operator","reviewer","artifact","commit")), "contribution.csv đủ cột", f"contribution.csv thiếu cột: {h}")
else: rec("WARN", "Chưa có contribution.csv")
ind = [f for f in files if rel(f).startswith("individual" + os.sep) and os.path.basename(f) != ".gitkeep"]
check(len(ind) >= 5, f"individual/ có {len(ind)}/5 file", f"individual/ mới có {len(ind)}/5 file (đề: 5 kết quả độc lập)", "WARN")
mine = [f for f in ind if re.search(r"role.?_?e|_E[._]", os.path.basename(f), re.I)]
if mine:
    f = mine[0]; t = ""
    if f.endswith(".pdf"):
        if shutil.which("pdftotext"):
            t = subprocess.run(["pdftotext", f, "-"], capture_output=True, text=True).stdout.lower()
        else: rec("WARN", "Không có pdftotext (sudo apt install poppler-utils) – bỏ qua kiểm nội dung PDF")
    else: t = text(f).lower()
    if t:
        for w, lbl in (("t_failure","t_failure"),("t_stable","t_stable"),("pvc","PVC UID"),("120","ngưỡng 120s")):
            check(w in t, f"Individual E nhắc {lbl}", f"Individual E chưa nhắc {lbl}", "WARN")
        check(re.search(r"backup|high availability|\bha\b|node", t), "Individual E nêu giới hạn bằng chứng (backup/HA/node)", "Individual E chưa nêu giới hạn (backup/HA/node-loss)", "WARN")
else: rec("FAIL", "Không thấy file individual của role E")

# ---------- G ----------
head("G. Git + credential")
rc, out = git("status", "--short")
if rc == 0:
    check(not out, "Git sạch, đã commit hết", f"Chưa commit:\n    " + out.replace("\n", "\n    "), "WARN")
    rc2, ahead = git("rev-list", "--count", "@{u}..HEAD")
    if rc2 == 0: check(ahead == "0", "Đã push hết", f"Còn {ahead} commit chưa push", "WARN")
    else: rec("WARN", "Không xác định được upstream (đã git push -u chưa?)")
    rc3, tracked = git("ls-files")
    bad = [f for f in tracked.splitlines() if re.search(r"(^|/)(private/|s3\.json$|observer\.json$|kubeconfig|[^/]*\.env$)", f, re.I)]
    check(not bad, "Git không track file nhạy cảm", f"Git ĐANG TRACK file nhạy cảm: {bad} → rotate credential!")
else: rec("WARN", "Không phải git repo")
bad = [rel(f) for f in files if re.search(r"(^|/)(private/|s3\.json$|observer\.json$|kubeconfig|[^/]*\.env$)", rel(f), re.I)]
check(not bad, "Không có file nhạy cảm theo tên", f"File nhạy cảm trong bundle: {bad}")
pats = {"access key": r"lab-[0-9a-f]{20}\b", "AWS secret": r"AWS_SECRET_ACCESS_KEY\s*=\s*\S{10,}",
        "secretKey": r'"secretKey"\s*:\s*"[^"]{8,}', "JWT": r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.",
        "private key": r"client-key-data|BEGIN (RSA |EC )?PRIVATE KEY",
        "Secret manifest": r"kind: Secret\b[\s\S]{0,400}\n\s*(data|stringData):"}
leak = False
for f in files:
    t = text(f)
    for n, p in pats.items():
        if re.search(p, t): leak = True; rec("FAIL", f"Nghi lộ [{n}] trong {rel(f)}")
if not leak: rec("PASS", "Không thấy pattern credential trong file text (PDF cần tự soát bằng mắt)")
ph = re.compile(r"TODO|FIXME|SET_ME|student-X|git-commit-id|sha256:\.\.\.|\bXXX\b")
for f in files:
    m = ph.search(text(f))
    if m: rec("WARN", f"Placeholder '{m.group(0)}' còn trong {rel(f)}")

print(f"\n===== TỔNG KẾT: {stats['PASS']} PASS | {stats['WARN']} WARN | {stats['FAIL']} FAIL =====")
sys.exit(1 if stats["FAIL"] else 0)
