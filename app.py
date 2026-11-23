import os, re, ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
import requests
from flask import Flask, render_template, request, jsonify, make_response, redirect, url_for, session, flash
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import mm
from xml.sax.saxutils import escape
import sqlite3, functools
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.getenv("TRUSTSHIELD_SECRET_KEY") or os.urandom(32)
app.permanent_session_lifetime = timedelta(hours=8)
DB_PATH = os.path.join(os.path.dirname(__file__), "trustshield.db")

def db():
    conn=sqlite3.connect(DB_PATH); conn.row_factory=sqlite3.Row; return conn

def init_db():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)")

def login_required(fn):
    @functools.wraps(fn)
    def wrapped(*a,**kw):
        if not session.get("user_id"): return redirect(url_for("login"))
        return fn(*a,**kw)
    return wrapped

def admin_required(fn):
    @functools.wraps(fn)
    def wrapped(*a,**kw):
        if not session.get("user_id"): return redirect(url_for("login"))
        if session.get("role") != "admin": return ("Administrator access required",403)
        return fn(*a,**kw)
    return wrapped

init_db()
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["JSON_SORT_KEYS"] = False

SUSPICIOUS_TLDS = {"zip","mov","country","kim","cricket","science","work","party","gq","tk","ml","cf","click","top","xyz"}
SUSPICIOUS_TERMS = {"login","verify","verification","secure","account","update","password","wallet","banking","payment","signin","support","gift","free","bonus","claim","prize","urgent","recover"}
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy","shorturl.at","ow.ly","buff.ly"}
BRANDS = {"paypal","google","microsoft","apple","amazon","facebook","instagram","netflix","whatsapp","sbi","hdfc","icici"}

def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw: raise ValueError("Enter a website URL.")
    if len(raw) > 2048: raise ValueError("URL is too long (maximum 2,048 characters).")
    if any(ord(c) < 32 for c in raw): raise ValueError("URL contains invalid control characters.")
    candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "https://" + raw
    p = urlparse(candidate)
    if p.scheme not in ("http","https") or not p.hostname: raise ValueError("Enter a valid HTTP or HTTPS website URL.")
    if p.username or p.password: raise ValueError("URLs containing embedded credentials are not accepted.")
    try: p.hostname.encode("idna")
    except UnicodeError: raise ValueError("The domain contains invalid international characters.")
    return candidate, p

def signal(items, title, detail, severity, points):
    items.append({"title":title,"detail":detail,"severity":severity,"points":points})

def domain_age_lookup(host):
    """Best-effort RDAP registration lookup; unavailable data is never treated as safe."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return {"status":"not_applicable","message":"Domain age is not applicable to a raw IP address."}
    except ValueError: pass
    labels=host.lower().rstrip(".").split(".")
    two_level_suffixes={"co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.in","firm.in","net.in","org.in","gen.in","com.sg","com.my","co.jp"}
    suffix=".".join(labels[-2:]) if len(labels)>=2 else ""
    take=3 if suffix in two_level_suffixes and len(labels)>=3 else 2
    domain=".".join(labels[-take:]) if len(labels)>=take else host
    try:
        r=requests.get("https://rdap.org/domain/"+domain, timeout=6, headers={"Accept":"application/rdap+json"})
        if r.status_code==404: return {"status":"unavailable","message":"No registration record was returned by RDAP."}
        r.raise_for_status(); data=r.json()
        created=None
        for event in data.get("events",[]):
            if event.get("eventAction","").lower() in ("registration","registered"):
                created=event.get("eventDate"); break
        if not created: return {"status":"unavailable","message":"RDAP did not provide a domain creation date."}
        dt=datetime.fromisoformat(created.replace("Z","+00:00"))
        age=max(0,(datetime.now(timezone.utc)-dt.astimezone(timezone.utc)).days)
        return {"status":"available","domain":domain,"created":created,"age_days":age,"message":f"Domain registration record found. Approximate age: {age} days."}
    except (requests.RequestException,ValueError,KeyError,TypeError):
        return {"status":"unavailable","message":"RDAP lookup was unavailable. Domain age could not be verified."}

def heuristic_scan(url, p):
    items, host = [], (p.hostname or "").lower().rstrip(".")
    labels, tld, decoded = host.split("."), host.split(".")[-1] if "." in host else "", unquote(url).lower()
    if p.scheme == "http":
        signal(items,"Unencrypted HTTP","The connection does not use HTTPS. Data may not be protected in transit.","high",18)
    try:
        ipaddress.ip_address(host.strip("[]"))
        signal(items,"Raw IP address","The destination is an IP address rather than a conventional domain name.","medium",15)
    except ValueError: pass
    if "@" in p.netloc: signal(items,"Misleading @ symbol","The authority section contains an @ symbol that can make destinations confusing.","high",22)
    if host.startswith("xn--") or ".xn--" in host: signal(items,"Punycode domain","Internationalized domain encoding can be legitimate but may hide look-alike characters.","medium",12)
    if len(url) > 180: signal(items,"Unusually long URL",f"The URL contains {len(url)} characters, making the destination harder to inspect.","low",6)
    if len(labels) >= 5: signal(items,"Many subdomains",f"The host contains {len(labels)-2} subdomain labels. Check the actual registered domain.","low",7)
    if tld in SUSPICIOUS_TLDS: signal(items,"TLD watchlist match",f".{tld} appears on this prototype's heuristic watchlist. A TLD alone is not proof of abuse.","medium",10)
    if host in SHORTENERS: signal(items,"URL shortener","The final destination is hidden behind a short link.","medium",12)
    terms = sorted(x for x in SUSPICIOUS_TERMS if x in decoded)
    if terms: signal(items,"Sensitive-action wording","Found URL terms: "+", ".join(terms[:7])+". Such wording can occur on legitimate sites too.","medium" if len(terms)>1 else "low",min(16,4+len(terms)*2))
    if re.search(r"%[0-9a-fA-F]{2}",url): signal(items,"Encoded characters","Percent-encoded characters can obscure parts of a URL, though they are also common on normal sites.","low",4)
    try:
        if p.port and p.port not in (80,443): signal(items,"Non-standard port",f"The URL uses port {p.port}, which is less common for public websites.","medium",8)
    except ValueError: signal(items,"Invalid port","The URL contains an invalid port number.","high",15)
    if host.count("-") >= 3: signal(items,"Hyphen-heavy domain","Several hyphens appear in the hostname, a pattern sometimes used in deceptive domains.","low",5)
    root_guess = ".".join(labels[-2:]) if len(labels)>1 else host
    brand_hits = [b for b in BRANDS if b in host and b not in root_guess]
    if brand_hits: signal(items,"Possible brand impersonation","Brand-like text appears outside the guessed registered domain: "+", ".join(brand_hits[:3])+". This is only a clue.","high",18)
    age_info=domain_age_lookup(host)
    if age_info["status"]=="available":
        age=age_info["age_days"]
        if age < 30: signal(items,"Very recently registered domain",f"RDAP reports this domain is approximately {age} days old. New domains deserve extra scrutiny but are not automatically malicious.","medium",15)
        elif age < 180: signal(items,"Relatively new domain",f"RDAP reports this domain is approximately {age} days old. Treat age as one signal, not proof of abuse.","low",7)
    score = min(100,sum(x["points"] for x in items))
    if score >= 60: level,label,advice="high","High risk","Do not visit the link or enter credentials, payment details, or personal information. Verify the organisation using its official app or a separately typed address."
    elif score >= 30: level,label,advice="medium","Caution advised","Do not sign in or download files until you independently verify the domain and the source of the link."
    else: level,label,advice="low","Few heuristic warnings","The quick checks found few warning signs. This is not proof of safety; reputation and page content have not been fully verified."
    return score,level,label,advice,items,age_info

def urlhaus_lookup(url):
    key = os.getenv("URLHAUS_AUTH_KEY","").strip()
    if not key: return {"status":"not_configured","message":"URLhaus is not connected. Add a server-side API key to enable reputation lookup."}
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url":url}, headers={"Auth-Key":key}, timeout=8)
        if r.status_code == 401: return {"status":"auth_error","message":"URLhaus rejected the API key. Check URLHAUS_AUTH_KEY."}
        if r.status_code == 429: return {"status":"rate_limited","message":"URLhaus rate limit reached. Try again later."}
        if r.status_code != 200: return {"status":"unavailable","message":f"URLhaus service returned HTTP {r.status_code}."}
        data = r.json()
        if data.get("query_status") == "ok":
            return {"status":"listed","message":"Exact URL match found in URLhaus.","threat":data.get("threat","Malware"),"date_added":data.get("date_added"),"url_status":data.get("url_status"),"reporter":data.get("reporter")}
        if data.get("query_status") == "no_results":
            return {"status":"not_listed","message":"No exact URL match found. This does not mean the website is safe."}
        return {"status":"unavailable","message":"URLhaus returned an unexpected response."}
    except requests.Timeout: return {"status":"timeout","message":"URLhaus lookup timed out. Heuristic analysis is still available."}
    except requests.RequestException: return {"status":"unavailable","message":"URLhaus could not be reached. Heuristic analysis is still available."}
    except ValueError: return {"status":"unavailable","message":"URLhaus returned an unreadable response."}

@app.get("/login")
def login():
    if session.get("user_id"): return redirect(url_for("home"))
    return render_template("auth.html", mode="login")

@app.post("/login")
def login_post():
    username=request.form.get("username","").strip().lower(); password=request.form.get("password","")
    with db() as c: user=c.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
    if not user or not user["active"] or not check_password_hash(user["password_hash"],password):
        flash("Invalid credentials or inactive account.","error"); return redirect(url_for("login"))
    session.clear(); session.permanent=True; session.update(user_id=user["id"],username=user["username"],role=user["role"])
    return redirect(url_for("home"))

@app.get("/signup")
def signup(): return render_template("auth.html", mode="signup")

@app.post("/signup")
def signup_post():
    username=request.form.get("username","").strip().lower(); password=request.form.get("password",""); confirm=request.form.get("confirm","")
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}",username):
        flash("Username must be 3–32 characters: letters, numbers, dot, underscore or hyphen.","error"); return redirect(url_for("signup"))
    if len(password)<10 or not re.search(r"[A-Za-z]",password) or not re.search(r"[0-9]",password):
        flash("Use at least 10 characters with letters and numbers.","error"); return redirect(url_for("signup"))
    if password!=confirm: flash("Passwords do not match.","error"); return redirect(url_for("signup"))
    with db() as c:
        count=c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        role="admin" if count==0 else "user"
        try: c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",(username,generate_password_hash(password),role,datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError:
            flash("That username is already taken.","error"); return redirect(url_for("signup"))
        uid=c.execute("SELECT id FROM users WHERE username=?",(username,)).fetchone()[0]
    session.clear(); session.permanent=True; session.update(user_id=uid,username=username,role=role)
    if role=="admin": flash("First account created as administrator. Keep these credentials safe.","success")
    return redirect(url_for("home"))

@app.post("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

@app.get("/account")
@login_required
def account(): return render_template("account.html")

@app.post("/account/password")
@login_required
def change_password():
    old=request.form.get("old_password",""); new=request.form.get("new_password",""); confirm=request.form.get("confirm","")
    with db() as c: user=c.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    if not check_password_hash(user["password_hash"],old): flash("Current password is incorrect.","error")
    elif len(new)<10 or not re.search(r"[A-Za-z]",new) or not re.search(r"[0-9]",new): flash("New password must be 10+ characters and include letters and numbers.","error")
    elif new!=confirm: flash("New passwords do not match.","error")
    else:
        with db() as c: c.execute("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(new),session["user_id"]))
        flash("Password updated.","success")
    return redirect(url_for("account"))

@app.get("/admin")
@admin_required
def admin():
    with db() as c: users=c.execute("SELECT id,username,role,active,created_at FROM users ORDER BY id").fetchall()
    return render_template("admin.html",users=users)

@app.post("/admin/create")
@admin_required
def admin_create():
    username=request.form.get("username","").strip().lower(); password=request.form.get("password",""); role=request.form.get("role","user")
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}",username) or len(password)<10 or not re.search(r"[A-Za-z]",password) or not re.search(r"[0-9]",password):
        flash("Use a valid username and a 10+ character password containing letters and numbers.","error")
    else:
        try:
            with db() as c: c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",(username,generate_password_hash(password),role if role in ("user","admin") else "user",datetime.now(timezone.utc).isoformat()))
            flash("User account created.","success")
        except sqlite3.IntegrityError: flash("Username already exists.","error")
    return redirect(url_for("admin"))

@app.post("/admin/user/<int:uid>/reset")
@admin_required
def admin_reset(uid):
    password=request.form.get("password","")
    if len(password)<10 or not re.search(r"[A-Za-z]",password) or not re.search(r"[0-9]",password): flash("Temporary password must be 10+ characters and include letters and numbers.","error")
    else:
        with db() as c: c.execute("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(password),uid))
        flash("Password reset. Share the temporary password securely.","success")
    return redirect(url_for("admin"))

@app.post("/admin/user/<int:uid>/toggle")
@admin_required
def admin_toggle(uid):
    if uid==session["user_id"]: flash("You cannot deactivate your own account.","error")
    else:
        with db() as c: c.execute("UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?",(uid,))
        flash("Account status updated.","success")
    return redirect(url_for("admin"))

@app.get("/")
@login_required
def home(): return render_template("index.html")

@app.post("/api/scan")
@login_required
def scan():
    body = request.get_json(silent=True) or {}
    try: url,p = normalize_url(body.get("url",""))
    except ValueError as e: return jsonify({"error":str(e)}),400
    score,level,label,advice,signals,age_info = heuristic_scan(url,p)
    intel = urlhaus_lookup(url)
    if intel["status"] == "listed":
        score,level,label = max(score,90),"high","Known malicious URL"
        advice = "URLhaus has a matching threat-intelligence record. Do not visit this URL or provide information."
        signals.insert(0,{"title":"URLhaus exact match","detail":intel["message"]+" Threat: "+str(intel.get("threat","Malware"))+".","severity":"critical","points":100})
    return jsonify({"url":url,"domain":p.hostname,"scanned_at":datetime.now(timezone.utc).isoformat(),"score":score,"risk_level":level,"risk_label":label,"advice":advice,"signals":signals,"threat_intelligence":intel,"domain_age":age_info,"disclaimer":"Preliminary assessment only. No database match or low score does not prove a website is safe."})

@app.get("/api/health")
@login_required
def health(): return jsonify({"status":"ok","service":"TRUSTSHIELD","urlhaus_configured":bool(os.getenv("URLHAUS_AUTH_KEY","").strip())})

@app.post("/api/report/pdf")
@login_required
def export_pdf():
    data = request.get_json(silent=True) or {}
    needed = ["url","score","risk_level","risk_label","signals","advice","threat_intelligence","scanned_at"]
    if not all(k in data for k in needed):
        return jsonify({"error":"Incomplete scan report. Run a scan before exporting."}), 400
    try:
        buf=BytesIO()
        doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=19*mm,leftMargin=19*mm,topMargin=18*mm,bottomMargin=18*mm,title="TRUSTSHIELD Security Scan Report")
        st=getSampleStyleSheet()
        st.add(ParagraphStyle(name="BrandTS",parent=st["Title"],fontSize=21,textColor=colors.HexColor("#315e45"),alignment=1,spaceAfter=4))
        st.add(ParagraphStyle(name="SmallTS",parent=st["BodyText"],fontSize=8.5,leading=12,textColor=colors.HexColor("#354139")))
        st.add(ParagraphStyle(name="HeadTS",parent=st["Heading2"],fontSize=12,textColor=colors.HexColor("#315e45"),spaceBefore=12,spaceAfter=6))
        story=[Paragraph("TRUSTSHIELD",st["BrandTS"]),Paragraph("WEBSITE THREAT INTELLIGENCE · SECURITY SCAN REPORT",st["SmallTS"]),Spacer(1,12)]
        story += [Paragraph("Risk score: <b>%s/100</b> &nbsp;&nbsp; Classification: <b>%s</b>"%(int(data["score"]),escape(str(data["risk_label"]))),st["SmallTS"]),
                  Paragraph("Scanned URL",st["HeadTS"]),Paragraph(escape(str(data["url"])),st["SmallTS"]),
                  Paragraph("Scan details",st["HeadTS"])]
        rows=[[Paragraph("<b>Domain</b>",st["SmallTS"]),Paragraph(escape(str(data.get("domain","Not supplied"))),st["SmallTS"])],
              [Paragraph("<b>Scanned at</b>",st["SmallTS"]),Paragraph(escape(str(data["scanned_at"])),st["SmallTS"])],
              [Paragraph("<b>Domain age</b>",st["SmallTS"]),Paragraph(escape(str(data.get("domain_age",{}).get("message","Not available"))),st["SmallTS"])]]
        t=Table(rows,colWidths=[38*mm,132*mm]);t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.4,colors.HexColor("#dfe5dd")),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#f4f6f2")),("PADDING",(0,0),(-1,-1),7)]));story.append(t)
        story.append(Paragraph("Detection indicators",st["HeadTS"]))
        sig=data.get("signals",[])
        if sig:
            rows=[[Paragraph("<b>Indicator</b>",st["SmallTS"]),Paragraph("<b>Explanation</b>",st["SmallTS"]),Paragraph("<b>Points</b>",st["SmallTS"])]]
            for x in sig:
                rows.append([Paragraph(escape(str(x.get("title",""))),st["SmallTS"]),Paragraph(escape(str(x.get("detail",""))),st["SmallTS"]),Paragraph(escape(str(x.get("points",""))),st["SmallTS"])])
            t=Table(rows,colWidths=[42*mm,112*mm,16*mm],repeatRows=1);t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.35,colors.HexColor("#dfe5dd")),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e8efe9")),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),6)]));story.append(t)
        else: story.append(Paragraph("No configured heuristic indicators were triggered.",st["SmallTS"]))
        intel=data.get("threat_intelligence",{})
        story += [Paragraph("Threat intelligence · URLhaus",st["HeadTS"]),Paragraph(escape(str(intel.get("status","unknown")).replace("_"," ").upper())+" — "+escape(str(intel.get("message","No status supplied."))),st["SmallTS"]),
                  Paragraph("Safety recommendation",st["HeadTS"]),Paragraph(escape(str(data["advice"])),st["SmallTS"]),Spacer(1,14),
                  Paragraph("<b>Important limitation</b>",st["SmallTS"]),Paragraph("This is a preliminary educational assessment. Heuristic indicators can produce false positives and false negatives. A low score or no URLhaus match does not prove a website is safe. This is not a full security audit.",st["SmallTS"])]
        doc.build(story)
        resp=make_response(buf.getvalue());resp.headers["Content-Type"]="application/pdf";resp.headers["Content-Disposition"]='attachment; filename="trustshield-scan-report.pdf"'
        return resp
    except Exception:
        app.logger.exception("PDF generation failed")
        return jsonify({"error":"Could not generate PDF report."}),500


if __name__ == "__main__":
    app.run(host="127.0.0.1",port=int(os.getenv("PORT","5000")),debug=False)
