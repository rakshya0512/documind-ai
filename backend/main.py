import os, re, json, time, uuid, math, sqlite3, threading, hmac, hashlib, base64, secrets, contextvars
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Request
from fastapi.responses import FileResponse, JSONResponse
import fitz, httpx

VERSION = "1.0.0"
DATA = Path(os.getenv("DATA_DIR", "data")); UP = DATA / "uploads"; TX = DATA / "text"
UP.mkdir(parents=True, exist_ok=True); TX.mkdir(parents=True, exist_ok=True)
MAX = int(os.getenv("MAX_UPLOAD_MB", "10")) * 1048576
CW = int(os.getenv("CHUNK_WORDS", "180"))
# --- authentication (simple built-in login) ---
# Override the defaults in production with env vars.
USERS = {
    "admin": {"password": os.getenv("ADMIN_PASSWORD", "12345"), "role": "admin"},
    "viewer": {"password": os.getenv("VIEWER_PASSWORD", "123"), "role": "viewer"},
}
ALLOW_MODE_SWITCH = os.getenv("ALLOW_MODE_SWITCH", "true").lower() in ("1", "true", "yes")
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "12"))
COOKIE = "dm_session"
_secret_file = DATA / "secret.key"
if os.getenv("SECRET_KEY"): SECRET = os.environ["SECRET_KEY"].encode()
else:
    if not _secret_file.exists(): _secret_file.write_text(secrets.token_hex(32))
    SECRET = _secret_file.read_text().strip().encode()
# per-request identity (set by the auth middleware)
CTX_USER = contextvars.ContextVar("user", default="anonymous")
CTX_ROLE = contextvars.ContextVar("role", default="none")
PERMS = {"admin": {"*"}, "analyst": {"read", "upload", "process", "delete", "ask"}, "viewer": {"read", "ask"}}
STAGES = [("upload", "Document Upload"), ("validation", "File Validation"), ("extraction", "Text Extraction"),
          ("cleaning", "Text Cleaning"), ("chunking", "Text Chunking"), ("embedding", "Embedding Generation"),
          ("indexing", "Indexing and Storage"), ("completed", "Processing Completed")]
DEFAULTS = {"display_name": "User", "email": "user@example.com", "compact": False, "default_scope": "all",
            "sort": "new", "retrieval_limit": 4, "answer_length": "medium", "show_sources": True}

db = sqlite3.connect(DATA / "app.db", check_same_thread=False); db.row_factory = sqlite3.Row
lock = threading.RLock()
db.executescript("""
CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY,name TEXT,path TEXT,type TEXT,size INT,uploaded TEXT,updated TEXT,status TEXT,pages INT,chunks INT DEFAULT 0,error TEXT,owner TEXT);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,doc_id TEXT,stage TEXT,status TEXT,stages TEXT,started TEXT,completed TEXT,duration REAL,error TEXT,retries INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS chunks(id INTEGER PRIMARY KEY AUTOINCREMENT,doc_id TEXT,seq INT,page INT,text TEXT);
CREATE INDEX IF NOT EXISTS ic ON chunks(doc_id);
CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,actor TEXT,action TEXT,doc_id TEXT,doc_name TEXT,job_id TEXT,result TEXT,detail TEXT);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);
""")
# jobs left "processing" by a crash must not stay stuck
db.execute("UPDATE jobs SET status='failed',error='Interrupted by restart' WHERE status='processing'")
db.execute("UPDATE documents SET status='failed',error='Interrupted by restart' WHERE status='processing'"); db.commit()

now = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
def rows(sql, *a):
    with lock: return [dict(r) for r in db.execute(sql, a).fetchall()]
def one(sql, *a):
    r = rows(sql, *a); return r[0] if r else None
def ex(sql, *a):
    with lock: c = db.execute(sql, a); db.commit(); return c
def log(action, result="success", doc=None, job=None, detail=""):
    ex("INSERT INTO activity(ts,actor,action,doc_id,doc_name,job_id,result,detail) VALUES(?,?,?,?,?,?,?,?)",
       now(), CTX_USER.get(), action, doc and doc["id"], doc and doc["name"], job, result, detail[:300])
def need(perm):
    role = CTX_ROLE.get(); p = PERMS.get(role, set())
    if "*" in p or perm in p: return
    log("permission_denied", "denied", detail=f"mode {role} lacks '{perm}'")
    raise HTTPException(403, f"Your current mode ({role}) cannot perform this action")
def getdoc(i):
    d = one("SELECT * FROM documents WHERE id=?", i)
    if not d: raise HTTPException(404, "Document not found")
    return d

app = FastAPI(title="DocuMind AI", version=VERSION)

if os.getenv("CORS_ORIGINS"):
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in os.environ["CORS_ORIGINS"].split(",")], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def _b64(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def make_token(user, mode):
    payload = _b64(json.dumps({"u": user, "m": mode, "exp": int(time.time()) + SESSION_HOURS * 3600}).encode())
    return payload + "." + _b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())
def read_token(tok):
    try:
        payload, sig = tok.split(".", 1)
        if not hmac.compare_digest(sig, _b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())): return None
        d = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if d["exp"] < time.time() or d["u"] not in USERS or d["m"] not in ("admin", "viewer"): return None
        if not ALLOW_MODE_SWITCH: d["m"] = USERS[d["u"]]["role"]
        return d
    except Exception: return None
def set_cookie(resp, request, tok):
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    resp.set_cookie(COOKIE, tok, max_age=SESSION_HOURS * 3600, httponly=True, samesite="lax", secure=secure, path="/")

OPEN_API = {"/api/auth/login", "/api/health"}
@app.middleware("http")
async def auth_mw(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api") and path not in OPEN_API:
        sess = read_token(request.cookies.get(COOKIE, ""))
        if not sess: return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        CTX_USER.set(sess["u"]); CTX_ROLE.set(sess["m"]); request.state.session = sess
    return await call_next(request)

@app.get("/api/health")
def health(): return {"status": "ok", "version": VERSION}

@app.post("/api/auth/login")
def login(body: dict, request: Request):
    u = str(body.get("username", "")).strip().lower(); p = str(body.get("password", ""))
    acct = USERS.get(u)
    if not acct or not hmac.compare_digest(acct["password"].encode(), p.encode()):
        CTX_USER.set(u[:40] or "unknown"); log("login_failed", "failed", detail="invalid credentials")
        raise HTTPException(401, "Invalid username or password")
    CTX_USER.set(u); log("login", "success")
    resp = JSONResponse({"username": u, "role": acct["role"], "mode": acct["role"], "can_switch": ALLOW_MODE_SWITCH})
    set_cookie(resp, request, make_token(u, acct["role"])); return resp

@app.get("/api/auth/me")
def me(request: Request):
    s = request.state.session
    return {"username": s["u"], "role": USERS[s["u"]]["role"], "mode": s["m"], "can_switch": ALLOW_MODE_SWITCH}

@app.post("/api/auth/mode")
def switch_mode(body: dict, request: Request):
    s = request.state.session; m = body.get("mode")
    if m not in ("admin", "viewer"): raise HTTPException(400, "Mode must be 'admin' or 'viewer'")
    if not ALLOW_MODE_SWITCH and m != USERS[s["u"]]["role"]: raise HTTPException(403, "Mode switching is disabled")
    log("mode_changed", "success", detail=f"{s['m']} -> {m}")
    resp = JSONResponse({"username": s["u"], "role": USERS[s["u"]]["role"], "mode": m, "can_switch": ALLOW_MODE_SWITCH})
    set_cookie(resp, request, make_token(s["u"], m)); return resp

@app.post("/api/auth/logout")
def logout():
    log("logout", "success"); resp = JSONResponse({"ok": True}); resp.delete_cookie(COOKIE, path="/"); return resp

# ---------- processing ----------
def new_job(doc_id):
    j = str(uuid.uuid4())[:8]
    ex("INSERT INTO jobs(id,doc_id,stage,status,stages,started) VALUES(?,?,?,?,?,?)", j, doc_id, "upload", "pending",
       json.dumps({k: {"status": "pending"} for k, _ in STAGES}), now()); return j

def run(job_id):
    j = one("SELECT * FROM jobs WHERE id=?", job_id); d = getdoc(j["doc_id"])
    st = {k: {"status": "pending"} for k, _ in STAGES}; t0 = time.time(); cur = ["upload"]
    ex("UPDATE documents SET status='processing',error=NULL WHERE id=?", d["id"])
    def save(status): ex("UPDATE jobs SET stage=?,status=?,stages=? WHERE id=?", cur[0], status, json.dumps(st), job_id)
    def step(k, fn):
        cur[0] = k; st[k] = {"status": "in_progress", "start": now()}; save("processing"); s = time.time()
        r = fn(); st[k].update(status="completed", end=now(), duration=round(time.time() - s, 3)); save("processing"); return r
    log("processing_started", "started", d, job_id)
    try:
        step("upload", lambda: None)
        def validate():
            p = Path(d["path"]); head = p.read_bytes()[:5]
            if p.stat().st_size == 0: raise ValueError("File is empty")
            if d["type"] == "pdf" and head != b"%PDF-": raise ValueError("File content is not a valid PDF")
            if d["type"] == "txt" and b"\x00" in p.read_bytes()[:2048]: raise ValueError("File is not plain text")
        step("validation", validate)
        def extract():
            p = Path(d["path"])
            if d["type"] == "pdf":
                with fitz.open(p) as doc: return [pg.get_text() for pg in doc]
            raw = p.read_bytes()
            try: t = raw.decode("utf-8")
            except UnicodeDecodeError: t = raw.decode("latin-1")
            return [t]
        pages = step("extraction", extract)
        if not "".join(pages).strip(): raise ValueError("No readable text found (scanned or empty document)")
        clean = lambda t: re.sub(r"[ \t]+", " ", re.sub(r"\n{3,}", "\n\n", re.sub(r"(?m)^\s*[=\-_*~]{3,}\s*$", "", t.replace("\x00", "")))).strip()
        pages = step("cleaning", lambda: [clean(p) for p in pages])
        def chunk():
            out = []
            for n, t in enumerate(pages, 1):
                w = t.split(); i = 0
                while i < len(w):
                    out.append((n, " ".join(w[i:i + CW]))); i += CW - 30 if len(w) > CW else CW
            return out
        ch = step("chunking", chunk)
        st["embedding"] = {"status": "not_configured", "note": "No embedding provider; TF-IDF retrieval is used"}
        def index():
            with lock:
                db.execute("DELETE FROM chunks WHERE doc_id=?", (d["id"],))
                db.executemany("INSERT INTO chunks(doc_id,seq,page,text) VALUES(?,?,?,?)", [(d["id"], i, p, t) for i, (p, t) in enumerate(ch)]); db.commit()
            (TX / f"{d['id']}.json").write_text(json.dumps(pages))
        step("indexing", index)
        cur[0] = "completed"; st["completed"] = {"status": "completed", "end": now()}
        dur = round(time.time() - t0, 2)
        ex("UPDATE jobs SET stage='completed',status='completed',stages=?,completed=?,duration=? WHERE id=?", json.dumps(st), now(), dur, job_id)
        ex("UPDATE documents SET status='ready',pages=?,chunks=?,updated=? WHERE id=?", len(pages), len(ch), now(), d["id"])
        log("processing_completed", "success", d, job_id, f"{len(ch)} chunks, {len(pages)} pages")
    except Exception as e:
        msg = str(e)[:200]; st[cur[0]] = {**st.get(cur[0], {}), "status": "failed", "error": msg}
        ex("UPDATE jobs SET status='failed',stage=?,stages=?,completed=?,duration=?,error=? WHERE id=?", cur[0], json.dumps(st), now(), round(time.time() - t0, 2), msg, job_id)
        ex("UPDATE documents SET status='failed',error=?,updated=? WHERE id=?", msg, now(), d["id"])
        log("processing_failed", "failed", d, job_id, f"stage {cur[0]}: {msg}")

# ---------- documents ----------
@app.post("/api/documents", status_code=201)
async def upload(bg: BackgroundTasks, file: UploadFile = File(...)):
    need("upload")
    name = Path(file.filename or "").name; ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    def reject(m): log("file_validation", "failed", detail=f"{name}: {m}"); raise HTTPException(400, m)
    if ext not in ("pdf", "txt"): reject("Only PDF and TXT files are supported")
    data = await file.read()
    if len(data) > MAX: reject(f"File exceeds {MAX // 1048576} MB limit")
    if not data: reject("File is empty")
    if ext == "pdf" and not data.startswith(b"%PDF-"): reject("File content is not a valid PDF")
    i = str(uuid.uuid4()); path = UP / f"{i}.{ext}"; path.write_bytes(data)
    ex("INSERT INTO documents(id,name,path,type,size,uploaded,updated,status,owner) VALUES(?,?,?,?,?,?,?,?,?)",
       i, name, str(path), ext, len(data), now(), now(), "pending", CTX_USER.get())
    d = getdoc(i); j = new_job(i); log("document_uploaded", "success", d, j, f"{len(data)} bytes"); bg.add_task(run, j)
    return {**d, "job_id": j}

@app.get("/api/documents")
def docs(q: str = "", type: str = "", status: str = "", sort: str = "new", since: str = "", page: int = 1, size: int = 10):
    need("read"); w, a = ["1=1"], []
    if q: w.append("name LIKE ?"); a.append(f"%{q}%")
    if type: w.append("type=?"); a.append(type)
    if status: w.append("status=?"); a.append(status)
    if since: w.append("uploaded>=?"); a.append(since)
    order = {"new": "uploaded DESC", "old": "uploaded", "name": "name COLLATE NOCASE", "status": "status"}.get(sort, "uploaded DESC")
    W = " AND ".join(w); size = min(max(size, 1), 100)
    total = one(f"SELECT COUNT(*) c FROM documents WHERE {W}", *a)["c"]
    return {"total": total, "items": rows(f"SELECT id,name,type,size,uploaded,updated,status,pages,chunks,error,owner FROM documents WHERE {W} ORDER BY {order} LIMIT ? OFFSET ?", *a, size, (max(page, 1) - 1) * size)}

@app.get("/api/documents/{i}")
def doc(i: str): need("read"); d = getdoc(i); d.pop("path"); return d

@app.get("/api/documents/{i}/text")
def text(i: str):
    need("read"); d = getdoc(i); f = TX / f"{i}.json"
    if d["status"] != "ready" or not f.exists(): raise HTTPException(409, "Text not available (document is not processed)")
    return {"pages": json.loads(f.read_text())}

@app.post("/api/documents/{i}/process")
def process(i: str, bg: BackgroundTasks):
    need("process"); d = getdoc(i)
    if d["status"] == "processing": raise HTTPException(409, "Already processing")
    j = new_job(i); log("processing_retry_requested", "queued", d, j); bg.add_task(run, j); return {"job_id": j}

@app.get("/api/documents/{i}/download")
def download(i: str): need("read"); d = getdoc(i); return FileResponse(d["path"], filename=d["name"])

@app.delete("/api/documents/{i}")
def delete(i: str):
    need("delete"); d = getdoc(i)
    ex("DELETE FROM chunks WHERE doc_id=?", i); ex("DELETE FROM documents WHERE id=?", i)
    for p in (Path(d["path"]), TX / f"{i}.json"): p.unlink(missing_ok=True)
    log("document_deleted", "success", d); return {"ok": True}

# ---------- jobs ----------
@app.get("/api/jobs")
def jobs():
    need("read")
    out = rows("SELECT j.*,d.name doc_name FROM jobs j LEFT JOIN documents d ON d.id=j.doc_id ORDER BY j.started DESC LIMIT 200")
    for j in out: j["stages"] = json.loads(j["stages"])
    return out
@app.get("/api/jobs/{i}")
def job(i: str):
    need("read"); j = one("SELECT j.*,d.name doc_name FROM jobs j LEFT JOIN documents d ON d.id=j.doc_id WHERE j.id=?", i)
    if not j: raise HTTPException(404, "Job not found")
    j["stages"] = json.loads(j["stages"]); return j
@app.post("/api/jobs/{i}/retry")
def retry(i: str, bg: BackgroundTasks):
    need("process"); j = one("SELECT * FROM jobs WHERE id=?", i)
    if not j: raise HTTPException(404, "Job not found")
    if j["status"] != "failed": raise HTTPException(409, "Only failed jobs can be retried")
    d = getdoc(j["doc_id"])
    ex("UPDATE jobs SET status='pending',stage='upload',error=NULL,completed=NULL,duration=NULL,started=?,retries=retries+1,stages=? WHERE id=?",
       now(), json.dumps({k: {"status": "pending"} for k, _ in STAGES}), i)
    log("processing_retry_requested", "queued", d, i); bg.add_task(run, i); return {"job_id": i}

# ---------- question answering ----------
STOP = set("the a an of to and in is are was were what which who whom how for on with that this these those it its as by be or from at about main list tell me give please explain describe there does do did say says said mention mentioned discuss document documents file text summarize summarise summary can could would should any all".split())
def stem(t):
    for suf in ("ing", "ed", "es", "s"):
        if t.endswith(suf) and len(t) - len(suf) >= 3: return t[:-len(suf)]
    return t
tok = lambda s: [stem(t) for t in re.findall(r"[a-z0-9]{2,}", s.lower())]
SUMMARY = re.compile(r"\b(summar\w*|overview|gist|tl;?dr|in short|brief)\b", re.I)
GENERIC = re.compile(r"\b(main|key|important|objective\w*|finding\w*|conclusion\w*|highlight\w*|about|risk\w*|limitation\w*|topic\w*)\b", re.I)
def leading(cands, k, scoped):
    """For broad questions ('summarize', 'main points') keyword search is useless: use the start of the document(s)."""
    if scoped: return [(0.0, c) for c in cands[:max(k, 6)]]
    seen, out = set(), []
    for c in cands:
        if c["doc_id"] not in seen: seen.add(c["doc_id"]); out.append((0.0, c))
    return out[:k]
def retrieve(q, cands, k):
    qt = {t for t in tok(q) if t not in STOP}
    if not qt or not cands: return []
    tf = [Counter(tok(c["text"])) for c in cands]; df = Counter(t for c in tf for t in c); n = len(cands); sc = []
    for c, f in zip(cands, tf):
        s = sum((1 + math.log(f[t])) * math.log(1 + n / df[t]) for t in qt if f[t])
        if s > 0: sc.append((s / (1 + 0.1 * math.log(1 + sum(f.values()))), c))
    return sorted(sc, key=lambda x: -x[0])[:k]
def llm(q, ctx, length):
    r = httpx.post("https://api.anthropic.com/v1/messages", timeout=60, headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"},
        json={"model": os.getenv("LLM_MODEL", "claude-sonnet-4-6"), "max_tokens": {"short": 300, "medium": 700, "long": 1500}.get(length, 700),
              "system": "Answer ONLY from the provided context. If it is insufficient, say the documents do not contain enough information. Do not invent facts.",
              "messages": [{"role": "user", "content": f"Context:\n{ctx}\n\nQuestion: {q}"}]})
    r.raise_for_status(); return r.json()["content"][0]["text"]
def extractive(q, top, summary=False):
    if summary:  # lead sentences of each passage, in document order
        out = []
        for _, c in top: out += re.split(r"(?<=[.!?])\s+", c["text"])[:2]
        return " ".join(out[:8])
    qt = {t for t in tok(q) if t not in STOP}; sents = []
    for _, c in top:
        for s in re.split(r"(?<=[.!?])\s+", c["text"]): sents.append((len(qt & set(tok(s))), s))
    best = [s for n, s in sorted(sents, key=lambda x: -x[0])[:3] if n > 0]
    return " ".join(best) or top[0][1]["text"][:300]

@app.post("/api/ask")
def ask(body: dict):
    need("ask"); q = str(body.get("question", "")).strip(); did = body.get("document_id")
    if not 3 <= len(q) <= 1000: raise HTTPException(400, "Question must be 3-1000 characters")
    s = settings_get()
    if did:
        d = getdoc(did)
        if d["status"] != "ready": raise HTTPException(409, f"Document is {d['status']}; only processed documents can be queried")
    cands = rows("SELECT c.text,c.page,c.doc_id,c.seq,d.name FROM chunks c JOIN documents d ON d.id=c.doc_id WHERE d.status='ready'" + (" AND c.doc_id=?" if did else "") + " ORDER BY c.doc_id,c.seq", *([did] if did else []))
    k = int(s["retrieval_limit"]); summary = bool(SUMMARY.search(q))
    top = leading(cands, k, bool(did)) if summary else retrieve(q, cands, k)
    if not top and GENERIC.search(q): top = leading(cands, k, bool(did)); summary = True
    log("question_submitted", "success", getdoc(did) if did else None, detail=f"{len(q)} chars, {len(top)} sources")
    if not top:
        return {"answer": "The available document content does not provide enough information to answer this.", "mode": "none", "sources": []}
    mode = "extractive-fallback"
    try:
        if os.getenv("ANTHROPIC_API_KEY"):
            ans = llm(q, "\n\n".join(f"[{c['name']} p.{c['page']}] {c['text']}" for _, c in top), s["answer_length"]); mode = "llm"
        else: ans = extractive(q, top, summary)
    except Exception: ans = extractive(q, top, summary); mode = "extractive-fallback (LLM unavailable)"
    return {"answer": ans, "mode": mode, "sources": [{"document": c["name"], "document_id": c["doc_id"], "page": c["page"], "excerpt": c["text"][:400], "score": round(sc, 2)} for sc, c in top]}

# ---------- analytics / activity / security / settings ----------
@app.get("/api/analytics/overview")
def analytics(since: str = "", type: str = "", status: str = ""):
    need("read"); w, a = ["1=1"], []
    for col, v in (("uploaded>=?", since), ("type=?", type), ("status=?", status)):
        if v: w.append(col); a.append(v)
    W = " AND ".join(w); ds = rows(f"SELECT status,type,uploaded,chunks FROM documents WHERE {W}", *a)
    jb = rows("SELECT status,duration FROM jobs"); qs = rows("SELECT ts FROM activity WHERE action='question_submitted'")
    durs = [j["duration"] for j in jb if j["status"] == "completed" and j["duration"] is not None]
    day = lambda L, k: dict(sorted(Counter(x[k][:10] for x in L).items()))
    return {"total": len(ds), "by_status": dict(Counter(d["status"] for d in ds)), "by_type": dict(Counter(d["type"] for d in ds)),
            "chunks": sum(d["chunks"] or 0 for d in ds), "uploads_by_day": day(ds, "uploaded"), "questions_by_day": day(qs, "ts"),
            "questions": len(qs), "jobs": dict(Counter(j["status"] for j in jb)), "durations": durs[-20:],
            "avg_duration": round(sum(durs) / len(durs), 2) if durs else None}

@app.get("/api/activity")
def activity(q: str = "", action: str = "", result: str = "", since: str = "", page: int = 1, size: int = 20, security: bool = False):
    need("read" if not security else "audit")
    w, a = ["1=1"], []
    if q: w.append("(doc_name LIKE ? OR detail LIKE ?)"); a += [f"%{q}%"] * 2
    if action: w.append("action=?"); a.append(action)
    if result: w.append("result=?"); a.append(result)
    if since: w.append("ts>=?"); a.append(since)
    if security: w.append("action IN ('permission_denied','document_deleted','settings_changed','login_failed','login','logout','mode_changed')")
    W = " AND ".join(w)
    return {"total": one(f"SELECT COUNT(*) c FROM activity WHERE {W}", *a)["c"], "actions": [r["action"] for r in rows("SELECT DISTINCT action FROM activity")],
            "items": rows(f"SELECT * FROM activity WHERE {W} ORDER BY id DESC LIMIT ? OFFSET ?", *a, size, (max(page, 1) - 1) * size)}
@app.get("/api/security/events")
def sec_events(): return activity(security=True, size=50)
@app.get("/api/security/status")
def sec_status(request: Request):
    need("audit"); env = lambda k: bool(os.getenv(k))
    S = lambda ok, note: {"status": ok, "note": note}
    return {"role": CTX_ROLE.get(), "items": {
        "Authentication": S("Active", "Signed session cookie (HttpOnly); admin and viewer accounts" + ("; change default passwords via ADMIN_PASSWORD / VIEWER_PASSWORD" if USERS["admin"]["password"] == "12345" else "")),
        "Role enforcement": S("Active", "Backend checks permissions on every protected endpoint"),
        "File validation": S("Active", "Extension, size, content-signature and readability checks on the server"),
        "Encryption in transit": S("Active" if request.url.scheme == "https" else "Requires Attention", f"Current connection uses {request.url.scheme}; deploy behind HTTPS"),
        "Encryption at rest": S("Configured" if env("KMS_KEY_ID") else "Not Configured", "Local files are stored unencrypted; S3/KMS adapter not implemented" if not env("KMS_KEY_ID") else "KMS_KEY_ID set, adapter not implemented"),
        "Audit logging": S("Active", "Application events stored in the database (append-only via API)"),
        "AWS IAM": S("Not Configured" if not env("AWS_ACCESS_KEY_ID") else "Configured", "Credentials detected but not verified" if env("AWS_ACCESS_KEY_ID") else "No AWS credentials"),
        "AWS KMS": S("Not Configured" if not env("KMS_KEY_ID") else "Configured", "Key id detected, not verified"),
        "AWS CloudTrail": S("Not Configured", "No integration"), "AWS CloudWatch": S("Not Configured", "No integration"),
        "Answering mode": S("Configured" if env("ANTHROPIC_API_KEY") else "Not Configured", "LLM answers" if env("ANTHROPIC_API_KEY") else "Extractive TF-IDF fallback in use")}}

def settings_get():
    s = dict(DEFAULTS)
    for r in rows("SELECT * FROM settings"): s[r["k"]] = json.loads(r["v"])
    return s
@app.get("/api/settings")
def get_settings(): return {**settings_get(), "role": CTX_ROLE.get(), "version": VERSION, "max_upload_mb": MAX // 1048576}
@app.put("/api/settings")
def put_settings(body: dict):
    ok = {"display_name": lambda v: isinstance(v, str) and 1 <= len(v) <= 60, "email": lambda v: isinstance(v, str) and re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+$", v),
          "compact": lambda v: isinstance(v, bool), "default_scope": lambda v: v in ("all", "single"), "sort": lambda v: v in ("new", "old", "name", "status"),
          "retrieval_limit": lambda v: isinstance(v, int) and 1 <= v <= 10, "answer_length": lambda v: v in ("short", "medium", "long"), "show_sources": lambda v: isinstance(v, bool)}
    for k, v in body.items():
        if k not in ok or not ok[k](v): raise HTTPException(400, f"Invalid value for '{k}'")
    for k, v in body.items(): ex("INSERT OR REPLACE INTO settings VALUES(?,?)", k, json.dumps(v))
    log("settings_changed", "success", detail=", ".join(body)); return settings_get()
@app.post("/api/settings/reset")
def reset(): ex("DELETE FROM settings"); log("settings_changed", "success", detail="reset"); return settings_get()

dist = Path(os.getenv("FRONTEND_DIST", str(Path(__file__).resolve().parent.parent / "frontend" / "dist")))
if dist.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/"): raise HTTPException(404, "Not found")
        f = (dist / full_path).resolve()
        if full_path and f.is_file() and dist.resolve() in f.parents: return FileResponse(f)
        return FileResponse(dist / "index.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))
