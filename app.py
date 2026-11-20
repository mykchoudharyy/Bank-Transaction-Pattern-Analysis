import os
import re
import hmac
import math
import secrets
import sqlite3
import hashlib
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px

# ==============================================================================
# CONFIG
# ==============================================================================
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bank_transactions.db")

st.set_page_config(
    page_title="Banking Transaction Pattern Analysis",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Bank keys: environment variables override the defaults (never hard-code in real life)
_DEFAULT_KEYS = {
    "HDFC Bank": "HDFC-2026",
    "State Bank of India": "SBI-2026",
    "ICICI Bank": "ICICI-2026",
    "Punjab National Bank": "PNB-2026",
    "Axis Bank": "AXIS-2026",
}
BANK_AUTH_KEYS = {
    b: os.environ.get("BANK_KEY_" + re.sub(r"\W", "_", b).upper(), k) for b, k in _DEFAULT_KEYS.items()
}
BANKS_LIST = list(BANK_AUTH_KEYS.keys())

PBKDF2_ITERS = 200_000
MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 5
SESSION_TIMEOUT_MIN = 15

PER_TXN_LIMIT = 1_000_000      # Rs 10 lakh per payment
DAILY_DEBIT_LIMIT = 500_000    # Rs 5 lakh per account per day

# ==============================================================================
# DATABASE HELPERS
# ==============================================================================
def run(sql, params=(), fetch=False):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall() if fetch else None
        conn.commit()
        return rows
    finally:
        conn.close()


def q(sql, params=()):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        return pd.read_sql_query(sql, conn, params=params)
    finally:
        conn.close()


def now_s():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_schema():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            bank_name TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )""")
    existing = {r[1] for r in cur.execute("PRAGMA table_info(users)").fetchall()}
    for col, ddl in [
        ("failed_attempts", "INTEGER DEFAULT 0"),
        ("locked_until", "TEXT"),
        ("last_login", "TEXT"),
    ]:
        if col not in existing:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, username TEXT, bank_name TEXT, action TEXT, detail TEXT
        )""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alert_reviews (
            txn_id TEXT PRIMARY KEY,
            bank_name TEXT, status TEXT, note TEXT, reviewer TEXT, ts TEXT
        )""")
    conn.commit()
    conn.close()


ensure_schema()


def audit(username, bank, action, detail=""):
    try:
        run("INSERT INTO audit_log(ts, username, bank_name, action, detail) VALUES (?,?,?,?,?)",
            (now_s(), username, bank, action, detail))
    except Exception:
        pass


# ==============================================================================
# SECURITY: PASSWORDS, LOGIN, LOCKOUT, SESSION
# ==============================================================================
def hash_pw(pw: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), PBKDF2_ITERS).hex()
    return f"pbkdf2${PBKDF2_ITERS}${salt}${dk}"


def verify_pw(pw: str, stored: str) -> bool:
    if stored.startswith("pbkdf2$"):
        _, it, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it)).hex()
        return hmac.compare_digest(calc, dk)
    # legacy plain SHA-256 hashes (from the old version) still work, then get upgraded
    return hmac.compare_digest(hashlib.sha256(pw.encode()).hexdigest(), stored)


def password_issues(pw: str):
    issues = []
    if len(pw) < 8:
        issues.append("at least 8 characters")
    if not re.search(r"[A-Z]", pw):
        issues.append("one uppercase letter")
    if not re.search(r"[a-z]", pw):
        issues.append("one lowercase letter")
    if not re.search(r"\d", pw):
        issues.append("one number")
    if not re.search(r"[^\w\s]", pw):
        issues.append("one special character")
    return issues


def create_user(full_name, bank_name, bank_key, username, password):
    if not hmac.compare_digest(bank_key.strip().upper(), BANK_AUTH_KEYS.get(bank_name, "")):
        audit(username.strip().lower(), bank_name, "REGISTER_FAIL", "bad bank key")
        return False, f"Bank Authorization Key is wrong for {bank_name}."
    if len(full_name.strip()) < 2:
        return False, "Enter your full name."
    if not re.fullmatch(r"[A-Za-z0-9_.]{4,20}", username.strip()):
        return False, "Username must be 4-20 characters: letters, numbers, dot or underscore."
    issues = password_issues(password)
    if issues:
        return False, "Password needs " + ", ".join(issues) + "."
    uname = username.strip().lower()
    if run("SELECT 1 FROM users WHERE username=?", (uname,), True):
        return False, "That username is taken. Try another."
    run("INSERT INTO users(username, full_name, bank_name, password_hash) VALUES (?,?,?,?)",
        (uname, full_name.strip(), bank_name, hash_pw(password)))
    audit(uname, bank_name, "REGISTER", "new analyst account")
    return True, f"Account created for {bank_name}. Open the Sign In tab to continue."


def authenticate_user(bank_name, username, password):
    uname = username.strip().lower()
    if not uname or not password:
        return None, "Enter username and password."
    rows = run("SELECT username, full_name, bank_name, password_hash, failed_attempts, locked_until, last_login "
               "FROM users WHERE username=?", (uname,), True)
    if not rows:
        hash_pw(password)  # keep timing similar for unknown users
        audit(uname, bank_name, "LOGIN_FAIL", "unknown user")
        return None, "Invalid credentials or bank selection."
    uname, full, ubank, ph, fails, locked, last_login = rows[0]
    if locked:
        try:
            until = datetime.fromisoformat(locked)
            if until > datetime.now():
                mins = max(1, math.ceil((until - datetime.now()).total_seconds() / 60))
                return None, f"Account locked after repeated failures. Try again in {mins} min."
        except ValueError:
            pass
    if ubank == bank_name and verify_pw(password, ph):
        if not ph.startswith("pbkdf2$"):
            ph = hash_pw(password)
        run("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=?, password_hash=? WHERE username=?",
            (now_s(), ph, uname))
        audit(uname, bank_name, "LOGIN", "success")
        return {"username": uname, "full_name": full, "bank_name": ubank, "prev_login": last_login}, ""
    fails = (fails or 0) + 1
    if fails >= MAX_FAILED_LOGINS:
        run("UPDATE users SET failed_attempts=0, locked_until=? WHERE username=?",
            ((datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat(), uname))
        audit(uname, bank_name, "ACCOUNT_LOCKED", f"{MAX_FAILED_LOGINS} failed logins")
        return None, f"Too many failed attempts. Account locked for {LOCK_MINUTES} minutes."
    run("UPDATE users SET failed_attempts=? WHERE username=?", (fails, uname))
    audit(uname, bank_name, "LOGIN_FAIL", f"attempt {fails}")
    return None, f"Invalid credentials or bank selection. {MAX_FAILED_LOGINS - fails} attempts left."


def logout(reason=None):
    u = st.session_state.get("auth_user")
    if u:
        audit(u["username"], u["bank_name"], "LOGOUT", reason or "user")
    st.session_state.auth_user = None
    if reason:
        st.session_state.flash = reason


# ==============================================================================
# DATA
# ==============================================================================
@st.cache_data(ttl=600, show_spinner=False)
def load_bank_transactions(bank_name: str) -> pd.DataFrame:
    sql = """
    SELECT
        t.txn_id, t.bank_name, t.account_id, t.merchant_id, t.timestamp, t.txn_type,
        t.channel, t.amount, t.status, t.city, t.balance_after,
        c.customer_id, c.masked_name AS customer_name, c.age_band, c.city_tier,
        a.account_type, m.category AS merchant_category
    FROM transactions t
    JOIN accounts a ON t.account_id = a.account_id
    JOIN customers c ON a.customer_id = c.customer_id
    JOIN merchants m ON t.merchant_id = m.merchant_id
    WHERE t.bank_name = ?
    """
    df = q(sql, (bank_name,))
    df["txn_id"] = df["txn_id"].astype(str)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["date"] = df["timestamp"].dt.date
    df["month"] = df["timestamp"].dt.to_period("M").astype(str)
    df["hour"] = df["timestamp"].dt.hour
    df["weekday"] = df["timestamp"].dt.day_name()
    df["is_failed"] = df["status"] != "Success"
    return df


def detect_anomalies(df, z_thresh=3.0, velocity=5, odd_hours=True):
    d = df.copy()
    g = d.groupby("channel")["amount"]
    sd = g.transform("std").replace(0, np.nan)
    d["z_score"] = ((d["amount"] - g.transform("mean")) / sd).fillna(0)
    d["f_amount"] = d["z_score"] >= z_thresh
    q75 = d["amount"].quantile(0.75)
    d["f_odd"] = (d["hour"].between(0, 4) & (d["amount"] > q75)) if odd_hours else False
    bucket = d["timestamp"].dt.floor("h")
    d["f_vel"] = d.groupby(["account_id", bucket])["txn_id"].transform("count") >= velocity
    d["risk_score"] = (d["f_amount"] * 50 + d["f_odd"] * 25 + d["f_vel"] * 25 +
                       np.clip(d["z_score"] - z_thresh, 0, 5) * 5).clip(0, 100).round(0)
    d["flagged"] = d[["f_amount", "f_odd", "f_vel"]].any(axis=1)
    reason = (pd.Series("", index=d.index)
              + np.where(d["f_amount"], "Unusually high amount; ", "")
              + np.where(d["f_odd"], "Large payment at night; ", "")
              + np.where(d["f_vel"], "Rapid repeat payments; ", ""))
    d["flag_reason"] = reason.str.rstrip("; ")
    d["risk_level"] = pd.cut(d["risk_score"], [-1, 49, 74, 100], labels=["Low", "Medium", "High"])
    return d


def run_hypothesis_test(df, dim, g1, g2):
    a = df.loc[df[dim] == g1, "amount"].dropna()
    b = df.loc[df[dim] == g2, "amount"].dropna()
    if len(a) < 2 or len(b) < 2:
        return {"valid": False}
    try:
        from scipy import stats
        t, p = stats.ttest_ind(a, b, equal_var=False)
    except Exception:
        se = math.sqrt(a.var(ddof=1) / len(a) + b.var(ddof=1) / len(b))
        t = (a.mean() - b.mean()) / se if se else 0.0
        p = math.erfc(abs(t) / math.sqrt(2))
    return {"valid": True, "mean_a": a.mean(), "mean_b": b.mean(), "n_a": len(a), "n_b": len(b),
            "t": float(t), "p_value": float(p), "significant": bool(p < 0.05)}


# ==============================================================================
# STYLE  (ledger-paper look: slate surface, deep teal ink, saffron accent)
# ==============================================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@500;600;700;800&family=DM+Sans:wght@400;500;600;700&display=swap');
:root{
  --ink:#0d2b30; --ink2:#14444b; --paper:#f3f5f7; --card:#ffffff; --line:#dde3e8;
  --muted:#5f7078; --saffron:#e9a216; --ok:#17835a; --bad:#c43b2f; --blue:#2457c5;
}
html, body, [class*="css"]{ font-family:'DM Sans',sans-serif; }
h1,h2,h3,.display{ font-family:'Sora',sans-serif !important; letter-spacing:-0.01em; }
.stApp{ background:var(--paper); color:#13242a; }
section[data-testid="stSidebar"], [data-testid="collapsedControl"], header[data-testid="stHeader"],
#MainMenu, footer, .stDeployButton{ display:none !important; }
.block-container{ padding-top:1.2rem !important; padding-bottom:2rem !important; max-width:1360px; }

.hero{ background:var(--ink); color:#fff; border-radius:18px; padding:42px 44px; position:relative; overflow:hidden; min-height:430px; }
.hero:after{ content:"₹"; position:absolute; right:-10px; bottom:-90px; font:800 340px 'Sora',sans-serif; color:rgba(233,162,22,.13); line-height:1; }
.hero h1{ color:#fff; font-size:38px; line-height:1.15; margin:0 0 14px 0; max-width:520px; }
.hero p{ color:#b8cdd1; font-size:15.5px; line-height:1.65; max-width:520px; margin:0 0 22px 0; }
.hero ul{ list-style:none; padding:0; margin:0; position:relative; z-index:2; }
.hero li{ color:#e6f0f1; font-size:14px; padding:7px 0 7px 22px; border-top:1px solid rgba(255,255,255,.12); position:relative; max-width:520px; }
.hero li:before{ content:""; position:absolute; left:2px; top:14px; width:8px; height:8px; border-radius:2px; background:var(--saffron); }

.topbar{ background:var(--ink); color:#fff; border-radius:16px; padding:16px 26px; display:flex; justify-content:space-between; align-items:center; }
.topbar .t1{ font-size:13px; color:#9fc0c6; }
.topbar .t2{ font-family:'Sora',sans-serif; font-size:21px; font-weight:700; margin-top:2px; }
.topbar .who{ text-align:right; font-size:13.5px; font-weight:600; }
.topbar .who span{ display:block; font-weight:400; font-size:12px; color:#9fc0c6; }

.kpi{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:16px 18px; border-top:3px solid var(--ink2); }
.kpi.gold{ border-top-color:var(--saffron); } .kpi.good{ border-top-color:var(--ok); } .kpi.bad{ border-top-color:var(--bad); }
.kpi .l{ font-size:13px; color:var(--muted); font-weight:500; }
.kpi .v{ font-family:'Sora',sans-serif; font-size:25px; font-weight:700; color:var(--ink); margin:4px 0 2px; }
.kpi .s{ font-size:12.5px; color:var(--muted); }
.up{ color:var(--ok); font-weight:700; } .down{ color:var(--bad); font-weight:700; }

.note{ background:#fff8e8; border-left:4px solid var(--saffron); padding:12px 16px; border-radius:8px; color:#5a4310; font-size:14px; margin:6px 0 14px; }
.note.info{ background:#eaf1fb; border-left-color:var(--blue); color:#1c3a73; }
.note.bad{ background:#fdeeec; border-left-color:var(--bad); color:#7d2118; }

.receipt{ background:#fff; border:1px dashed #9db0b6; border-radius:14px; padding:20px 24px; }
.receipt h3{ margin:0 0 10px; font-size:18px; }
.receipt .row{ display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid var(--line); font-size:14px; }
.receipt .row:last-child{ border-bottom:none; }
.pill{ display:inline-block; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:700; }
.pill.ok{ background:#dff3ea; color:var(--ok); } .pill.bad{ background:#fbe3e0; color:var(--bad); } .pill.warn{ background:#fdf0d2; color:#8a5d00; }

.footer{ margin-top:34px; padding:14px 20px; background:#fff; border:1px solid var(--line); border-radius:12px; display:flex; justify-content:space-between; font-size:12.5px; color:var(--muted); }

div[data-baseweb="tab-list"]{ gap:6px; background:#e6ebef; padding:5px; border-radius:12px; flex-wrap:wrap; }
button[data-baseweb="tab"]{ font-weight:600 !important; font-size:14px !important; padding:9px 16px !important; border-radius:9px !important; color:var(--muted) !important; }
button[data-baseweb="tab"][aria-selected="true"]{ background:#fff !important; color:var(--ink) !important; box-shadow:0 1px 3px rgba(13,43,48,.12); }
div[data-baseweb="tab-highlight"], div[data-baseweb="tab-border"]{ display:none !important; }

div[data-testid="stFormSubmitButton"] > button, div.stButton > button[kind="primary"], div[data-testid="stDownloadButton"] > button{
  background:var(--ink) !important; color:#fff !important; border:none !important; border-radius:9px !important; font-weight:600 !important; }
div[data-testid="stFormSubmitButton"] > button:hover, div.stButton > button[kind="primary"]:hover{ background:var(--ink2) !important; }
div[data-testid="stForm"]{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:20px; }
</style>
""", unsafe_allow_html=True)

px.defaults.color_discrete_sequence = ["#14444b", "#e9a216", "#2457c5", "#17835a", "#c43b2f", "#7a5af8", "#0e9aa7"]


def style_fig(fig, h=380):
    fig.update_layout(template="plotly_white", paper_bgcolor="#ffffff", plot_bgcolor="#ffffff", height=h,
                      font=dict(family="DM Sans, sans-serif", color="#13242a", size=12),
                      margin=dict(l=20, r=20, t=50, b=20), title_font=dict(family="Sora, sans-serif", size=15))
    return fig


def kpi(label, value, sub="", tone="", delta=None):
    d = ""
    if delta is not None and not (isinstance(delta, float) and math.isnan(delta)):
        cls, arrow = ("up", "▲") if delta >= 0 else ("down", "▼")
        d = f' <span class="{cls}">{arrow} {abs(delta):.1f}%</span>'
    return (f'<div class="kpi {tone}"><div class="l">{label}</div><div class="v">{value}</div>'
            f'<div class="s">{sub}{d}</div></div>')


def note(text, kind=""):
    st.markdown(f'<div class="note {kind}">{text}</div>', unsafe_allow_html=True)


def inr(x):
    return f"₹{x:,.0f}"


# ==============================================================================
# SESSION
# ==============================================================================
st.session_state.setdefault("auth_user", None)
st.session_state.setdefault("last_active", datetime.now())

if st.session_state.auth_user:
    if datetime.now() - st.session_state.last_active > timedelta(minutes=SESSION_TIMEOUT_MIN):
        logout(f"Signed out after {SESSION_TIMEOUT_MIN} minutes of inactivity.")
    else:
        st.session_state.last_active = datetime.now()

# ==============================================================================
# 1. LOGIN / REGISTER
# ==============================================================================
if not st.session_state.auth_user:
    _, mid, _ = st.columns([1, 1.3, 1])
    with mid:
        st.markdown("""
        <div style="text-align:center; margin:40px 0 18px 0;">
            <div class="display" style="font-size:30px; font-weight:800; color:#0d2b30;">Banking Transaction Pattern Analysis</div>
            <div style="color:#5f7078; font-size:14.5px; margin-top:6px;">Sign in to your bank's workspace</div>
        </div>
        """, unsafe_allow_html=True)
        if st.session_state.get("flash"):
            st.warning(st.session_state.pop("flash"))
        t_in, t_reg = st.tabs(["Sign in", "Create staff account"])
        with t_in:
            with st.form("signin_form"):
                s_bank = st.selectbox("Bank", BANKS_LIST)
                s_user = st.text_input("Username")
                s_pass = st.text_input("Password", type="password")
                if st.form_submit_button("Sign in", type="primary", use_container_width=True):
                    rec, err = authenticate_user(s_bank, s_user, s_pass)
                    if rec:
                        st.session_state.auth_user = rec
                        st.session_state.last_active = datetime.now()
                        st.rerun()
                    else:
                        st.error(err)
        with t_reg:
            with st.form("register_form", clear_on_submit=True):
                r_name = st.text_input("Full name")
                r_bank = st.selectbox("Assigned bank", BANKS_LIST)
                r_key = st.text_input("Bank authorization key", type="password",
                                      help="Issued by your bank's compliance team.")
                r_user = st.text_input("Choose a username")
                r_pass = st.text_input("Create a password", type="password",
                                       help="8+ characters with upper, lower, number and special character.")
                if st.form_submit_button("Create account", type="primary", use_container_width=True):
                    ok, msg = create_user(r_name, r_bank, r_key, r_user, r_pass)
                    (st.success if ok else st.error)(msg)
    st.stop()

# ==============================================================================
# 2. WORKSPACE
# ==============================================================================
user = st.session_state.auth_user
bank = user["bank_name"]
df = load_bank_transactions(bank)

h_left, h_right = st.columns([5.5, 1])
with h_left:
    prev = f"Last sign-in: {user['prev_login']}" if user.get("prev_login") else "First sign-in"
    st.markdown(f"""
    <div class="topbar">
        <div><div class="t1">{bank} analytics workspace</div>
        <div class="t2">Banking Transaction Pattern Analysis</div></div>
        <div class="who">{user['full_name']}<span>@{user['username']} · {prev}</span></div>
    </div>""", unsafe_allow_html=True)
with h_right:
    st.write("")
    if st.button("Sign out", use_container_width=True):
        logout()
        st.rerun()

if df.empty:
    st.warning("No transactions found for this bank.")
    st.stop()

# ---- global filters ----------------------------------------------------------
with st.expander("Filters · apply to every analytics tab", expanded=False):
    f1, f2, f3 = st.columns([1.3, 1.5, 1.2])
    dmin, dmax = df["date"].min(), df["date"].max()
    rng = f1.date_input("Date range", value=(dmin, dmax), min_value=dmin, max_value=dmax)
    sel_ch = f2.multiselect("Channels", sorted(df["channel"].unique()), default=sorted(df["channel"].unique()))
    sel_st = f3.multiselect("Status", sorted(df["status"].unique()), default=sorted(df["status"].unique()))

start, end = (rng[0], rng[1]) if isinstance(rng, (tuple, list)) and len(rng) == 2 else (dmin, dmax)
fdf = df[(df["date"] >= start) & (df["date"] <= end) & df["channel"].isin(sel_ch) & df["status"].isin(sel_st)]
if fdf.empty:
    st.warning("No transactions match these filters. Widen the date range or add channels.")
    st.stop()

tabs = st.tabs(["Overview", "Channels", "Failures", "Spending", "Fraud alerts",
                "Customers", "Payment desk", "Reports", "Audit log"])
tab1, tab2, tab3, tab4, tab5, tab_c, tab6, tab7, tab8 = tabs

# ------------------------------------------------------------------------------
# OVERVIEW
# ------------------------------------------------------------------------------
with tab1:
    total_txns = len(fdf)
    total_val = fdf["amount"].sum()
    succ_rate = (fdf["status"] == "Success").mean() * 100
    mon = fdf.groupby("month", as_index=False).agg(Transactions=("txn_id", "count"), Value_INR=("amount", "sum"),
                                                    Failed=("is_failed", "sum"))
    d_cnt = d_val = float("nan")
    if len(mon) >= 2:
        a, b = mon.iloc[-1], mon.iloc[-2]
        d_cnt = (a.Transactions / b.Transactions - 1) * 100 if b.Transactions else float("nan")
        d_val = (a.Value_INR / b.Value_INR - 1) * 100 if b.Value_INR else float("nan")

    k = st.columns(5)
    k[0].markdown(kpi("Total transactions", f"{total_txns:,}", "vs previous month", delta=d_cnt), unsafe_allow_html=True)
    k[1].markdown(kpi("Amount moved", f"₹{total_val/1e7:.2f} Cr", "vs previous month", "gold", delta=d_val), unsafe_allow_html=True)
    k[2].markdown(kpi("Average payment", inr(fdf["amount"].mean()), f"Median {inr(fdf['amount'].median())}"), unsafe_allow_html=True)
    k[3].markdown(kpi("Success rate", f"{succ_rate:.1f}%", f"Failed or reversed {100-succ_rate:.1f}%", "good" if succ_rate >= 95 else "bad"), unsafe_allow_html=True)
    k[4].markdown(kpi("Active accounts", f"{fdf['account_id'].nunique():,}", f"{fdf['customer_id'].nunique():,} customers"), unsafe_allow_html=True)

    st.write("")
    c1, c2 = st.columns(2)
    c1.plotly_chart(style_fig(px.line(mon, x="month", y="Transactions", markers=True, title="Monthly transaction count")), width="stretch")
    c2.plotly_chart(style_fig(px.area(mon, x="month", y="Value_INR", title="Monthly rupee volume (INR)", color_discrete_sequence=["#e9a216"])), width="stretch")

    daily = fdf.groupby("date", as_index=False).agg(Transactions=("txn_id", "count"))
    daily["7-day average"] = daily["Transactions"].rolling(7, min_periods=1).mean()
    c3, c4 = st.columns([1.6, 1])
    c3.plotly_chart(style_fig(px.line(daily, x="date", y=["Transactions", "7-day average"], title="Daily activity with 7-day trend")), width="stretch")
    c4.plotly_chart(style_fig(px.pie(fdf, names="status", hole=0.55, title="Transaction status mix")), width="stretch")

    if len(mon) >= 4:
        y = mon["Transactions"].to_numpy(dtype=float)
        slope, icpt = np.polyfit(np.arange(len(y)), y, 1)
        proj = max(0, slope * len(y) + icpt)
        note(f"<b>Trend projection:</b> if the current linear trend holds, next month will see about "
             f"<b>{proj:,.0f}</b> transactions ({'up' if slope >= 0 else 'down'} {abs(slope):,.0f} per month on average).", "info")

# ------------------------------------------------------------------------------
# CHANNELS
# ------------------------------------------------------------------------------
with tab2:
    ch = fdf.groupby("channel", as_index=False).agg(Transactions=("txn_id", "count"), Total_INR=("amount", "sum"),
                                                     Avg_Ticket=("amount", "mean"), Fail_Rate=("is_failed", "mean"))
    ch["Fail_Rate"] = (ch["Fail_Rate"] * 100).round(2)
    ch["Share_%"] = (ch["Transactions"] / ch["Transactions"].sum() * 100).round(1)
    ch = ch.sort_values("Transactions", ascending=False)
    top_vol = ch.iloc[0]["channel"]
    top_val = ch.sort_values("Total_INR", ascending=False).iloc[0]["channel"]
    note(f"<b>{top_vol}</b> handles the most transactions ({ch.iloc[0]['Share_%']}%), while <b>{top_val}</b> carries the largest rupee value.", "info")

    c1, c2 = st.columns(2)
    c1.plotly_chart(style_fig(px.bar(ch, x="channel", y="Transactions", color="channel", title="Transactions by channel")), width="stretch")
    c2.plotly_chart(style_fig(px.pie(ch, names="channel", values="Total_INR", hole=0.5, title="Share of rupee volume")), width="stretch")
    cm = fdf.groupby(["month", "channel"], as_index=False).size().rename(columns={"size": "Transactions"})
    st.plotly_chart(style_fig(px.bar(cm, x="month", y="Transactions", color="channel", barmode="stack", title="Channel mix over time")), width="stretch")
    st.dataframe(ch.rename(columns={"Fail_Rate": "Failure rate %"}), width="stretch", hide_index=True)

# ------------------------------------------------------------------------------
# FAILURES
# ------------------------------------------------------------------------------
with tab3:
    f_ch = fdf.groupby("channel", as_index=False).agg(Total=("txn_id", "count"), Failed=("is_failed", "sum"))
    f_ch["Failure_Rate_%"] = f_ch["Failed"] / f_ch["Total"] * 100
    f_hr = fdf.groupby("hour", as_index=False).agg(Total=("txn_id", "count"), Failed=("is_failed", "sum"))
    f_hr["Failure_Rate_%"] = f_hr["Failed"] / f_hr["Total"] * 100

    if f_hr["Failed"].sum() == 0:
        note("No failed or reversed transactions in the selected range.", "info")
    else:
        worst_hr = f_hr[f_hr["Total"] >= max(5, f_hr["Total"].median() * 0.2)].sort_values("Failure_Rate_%", ascending=False).iloc[0]
        worst_ch = f_ch.sort_values("Failure_Rate_%", ascending=False).iloc[0]
        note(f"Failures peak at <b>{int(worst_hr['hour']):02d}:00</b> ({worst_hr['Failure_Rate_%']:.1f}% of payments). "
             f"<b>{worst_ch['channel']}</b> is the least reliable channel at {worst_ch['Failure_Rate_%']:.1f}%.", "bad")

    c1, c2 = st.columns(2)
    c1.plotly_chart(style_fig(px.bar(f_ch, x="channel", y="Failure_Rate_%", color="Failure_Rate_%", color_continuous_scale="Reds", title="Failure rate (%) by channel")), width="stretch")
    c2.plotly_chart(style_fig(px.line(f_hr, x="hour", y="Failure_Rate_%", markers=True, title="Failure rate (%) by hour of day", color_discrete_sequence=["#c43b2f"])), width="stretch")

    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    hm = (fdf.groupby(["weekday", "hour"]).size().unstack(fill_value=0)
          .reindex(index=days, columns=range(24), fill_value=0))
    st.plotly_chart(style_fig(px.imshow(hm, aspect="auto", color_continuous_scale="Blues", title="Peak load heatmap (weekday × hour)")), width="stretch")
    fc = fdf[fdf["is_failed"]].groupby(["city"], as_index=False).size().rename(columns={"size": "Failed"}).sort_values("Failed", ascending=False).head(10)
    if not fc.empty:
        st.plotly_chart(style_fig(px.bar(fc, x="city", y="Failed", title="Cities with most failed transactions"), 330), width="stretch")

# ------------------------------------------------------------------------------
# SPENDING
# ------------------------------------------------------------------------------
with tab4:
    city_filter = st.selectbox("City", ["All cities"] + sorted(fdf["city"].unique().tolist()))
    ds = fdf if city_filter == "All cities" else fdf[fdf["city"] == city_filter]
    cat = ds.groupby("merchant_category", as_index=False).agg(Total_Spend=("amount", "sum")).sort_values("Total_Spend", ascending=False)
    tier = ds.groupby(["city_tier", "account_type"], as_index=False).agg(Avg_Payment=("amount", "mean"))
    age = ds.groupby("age_band", as_index=False).agg(Avg_Payment=("amount", "mean"))

    st.plotly_chart(style_fig(px.bar(cat, x="merchant_category", y="Total_Spend", color="merchant_category", title="Customer spend (INR) by merchant category")), width="stretch")
    c1, c2 = st.columns(2)
    c1.plotly_chart(style_fig(px.bar(tier, x="city_tier", y="Avg_Payment", color="account_type", barmode="group", title="Average payment by city tier and account type")), width="stretch")
    c2.plotly_chart(style_fig(px.bar(age, x="age_band", y="Avg_Payment", title="Average payment by age group", color_discrete_sequence=["#e9a216"])), width="stretch")

    c3, c4 = st.columns(2)
    wd = ds.groupby("weekday", as_index=False).agg(Spend=("amount", "sum")).set_index("weekday").reindex(days).reset_index()
    c3.plotly_chart(style_fig(px.bar(wd, x="weekday", y="Spend", title="Spend by day of week")), width="stretch")
    cap = ds["amount"].quantile(0.99)
    c4.plotly_chart(style_fig(px.histogram(ds[ds["amount"] <= cap], x="amount", nbins=40, title="Payment size distribution (top 1% trimmed)")), width="stretch")

    st.subheader("Top customers by spend")
    top_c = (ds.groupby(["customer_id", "customer_name"], as_index=False)
             .agg(Transactions=("txn_id", "count"), Total_Spend=("amount", "sum"), Avg_Payment=("amount", "mean"))
             .sort_values("Total_Spend", ascending=False).head(10))
    st.dataframe(top_c.round(0), width="stretch", hide_index=True)

# ------------------------------------------------------------------------------
# FRAUD ALERTS  (detect -> review -> record decision)
# ------------------------------------------------------------------------------
with tab5:
    s1, s2, s3 = st.columns(3)
    z_thresh = s1.slider("Amount sensitivity (z-score)", 2.0, 5.0, 3.0, 0.5, help="Lower = more alerts")
    velocity = s2.slider("Repeat payments per hour", 3, 10, 5)
    odd_on = s3.toggle("Flag large night payments (00:00-04:59)", value=True)

    anom = detect_anomalies(fdf, z_thresh, velocity, odd_on)
    reviews = q("SELECT txn_id, status AS review_status, note, reviewer, ts AS reviewed_at FROM alert_reviews WHERE bank_name=?", (bank,))
    flagged = anom[anom["flagged"]].merge(reviews, on="txn_id", how="left")
    flagged["review_status"] = flagged["review_status"].fillna("Not reviewed")
    flagged = flagged.sort_values(["risk_score", "amount"], ascending=False)

    k = st.columns(4)
    k[0].markdown(kpi("Flagged transactions", f"{len(flagged):,}", f"of {len(anom):,} analysed", "bad"), unsafe_allow_html=True)
    k[1].markdown(kpi("High risk", f"{(flagged['risk_level'] == 'High').sum():,}", "risk score 75+", "bad"), unsafe_allow_html=True)
    k[2].markdown(kpi("Value at risk", f"₹{flagged['amount'].sum()/1e5:,.1f} L", "sum of flagged payments", "gold"), unsafe_allow_html=True)
    k[3].markdown(kpi("Still to review", f"{(flagged['review_status'] == 'Not reviewed').sum():,}", "open cases"), unsafe_allow_html=True)
    st.write("")

    if flagged.empty:
        note("No transactions crossed the alert thresholds. Lower the sensitivity to widen the net.", "info")
    else:
        c1, c2 = st.columns([1.5, 1])
        sample = anom.sample(min(len(anom), 4000), random_state=1)
        sample = pd.concat([sample, flagged.head(500)]).drop_duplicates("txn_id")
        fig = px.scatter(sample, x="timestamp", y="amount", color="risk_level",
                         color_discrete_map={"Low": "#b7c4ca", "Medium": "#e9a216", "High": "#c43b2f"},
                         hover_data=["txn_id", "channel", "flag_reason"], title="Payments by risk level", opacity=0.75)
        c1.plotly_chart(style_fig(fig), width="stretch")
        rs = flagged.groupby("flag_reason", as_index=False).size().rename(columns={"size": "Cases"})
        c2.plotly_chart(style_fig(px.bar(rs, x="Cases", y="flag_reason", orientation="h", title="Why transactions were flagged")), width="stretch")

        cols = ["txn_id", "timestamp", "account_id", "channel", "merchant_category", "city", "amount", "risk_score", "risk_level", "flag_reason", "review_status"]
        st.dataframe(flagged[cols].head(200), width="stretch", hide_index=True)

        st.subheader("Review a case")
        with st.form("review_form", clear_on_submit=True):
            r1, r2, r3 = st.columns([1.4, 1, 2])
            case = r1.selectbox("Transaction", flagged["txn_id"].head(200).tolist())
            decision = r2.selectbox("Decision", ["Confirmed fraud", "False positive", "Escalated", "Under review"])
            comment = r3.text_input("Note")
            if st.form_submit_button("Save decision", type="primary"):
                run("INSERT INTO alert_reviews(txn_id, bank_name, status, note, reviewer, ts) VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(txn_id) DO UPDATE SET status=excluded.status, note=excluded.note, reviewer=excluded.reviewer, ts=excluded.ts",
                    (case, bank, decision, comment, user["username"], now_s()))
                audit(user["username"], bank, "ALERT_REVIEW", f"{case} -> {decision}")
                st.success(f"Saved: {case} marked as {decision}.")
                st.rerun()

# ------------------------------------------------------------------------------
# CUSTOMERS  (add customer -> open account with opening deposit -> customer 360)
# ------------------------------------------------------------------------------
def insert_row(table, vals):
    info = run(f"PRAGMA table_info({table})", fetch=True)
    row = {}
    for _cid, name, ctype, notnull, dflt, pk in info:
        ct = (ctype or "").upper()
        if name in vals:
            v = vals[name]
            row[name] = v.item() if hasattr(v, "item") else v
        elif notnull and dflt is None and not (pk and "INT" in ct):
            low = name.lower()
            if any(w in low for w in ("date", "time", "created", "opened")):
                row[name] = now_s()
            elif any(t in ct for t in ("INT", "REAL", "NUM", "FLOA", "DOUB")):
                row[name] = 0
            else:
                row[name] = ""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        cur = conn.execute(f"INSERT INTO {table} ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                           list(row.values()))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def next_id(table, col, fallback_prefix):
    best = None
    for (i,) in run(f"SELECT {col} FROM {table}", fetch=True):
        m = re.fullmatch(r"(\D*)(\d+)", str(i))
        if m and (best is None or int(m.group(2)) > best[1]):
            best = (m.group(1), int(m.group(2)), len(m.group(2)))
    if best:
        return f"{best[0]}{str(best[1] + 1).zfill(best[2])}"
    return fallback_prefix + secrets.token_hex(3).upper()


def mask_name(full):
    return " ".join(w[0] + "*" * (len(w) - 1) for w in full.split())


with tab_c:
    if st.session_state.get("cust_msg"):
        st.success(st.session_state.pop("cust_msg"))

    allc = q("SELECT c.customer_id, c.masked_name, c.age_band, c.city, c.city_tier, COUNT(a.account_id) AS accounts "
             "FROM customers c LEFT JOIN accounts a ON a.customer_id = c.customer_id "
             "GROUP BY c.customer_id ORDER BY c.customer_id")
    k = st.columns(3)
    k[0].markdown(kpi("Customers in database", f"{len(allc):,}", "all banks"), unsafe_allow_html=True)
    k[1].markdown(kpi("Customers at " + bank, f"{df['customer_id'].nunique():,}", "with at least one transaction", "gold"), unsafe_allow_html=True)
    k[2].markdown(kpi("Accounts at " + bank, f"{df['account_id'].nunique():,}", ""), unsafe_allow_html=True)
    st.write("")

    cc1, cc2 = st.columns(2)
    # ---- add customer ----
    with cc1:
        st.subheader("1. Add a new customer")
        ages = q("SELECT DISTINCT age_band FROM customers ORDER BY 1")["age_band"].tolist()
        cdf = q("SELECT DISTINCT city, city_tier FROM customers ORDER BY city")
        tier_map = dict(zip(cdf["city"], cdf["city_tier"]))
        with st.form("cust_form", clear_on_submit=True):
            nm = st.text_input("Customer full name")
            a1, a2 = st.columns(2)
            age = a1.selectbox("Age band", ages)
            city_sel = a2.selectbox("City", sorted(tier_map) + ["Other (type below)"])
            b1, b2 = st.columns(2)
            new_city = b1.text_input("New city (only if you chose Other)")
            new_tier = b2.selectbox("Tier for a new city", sorted(set(tier_map.values())))
            add_c = st.form_submit_button("Add customer", type="primary", use_container_width=True)
        if add_c:
            city_final = new_city.strip().title() if city_sel.startswith("Other") else city_sel
            if not re.fullmatch(r"[A-Za-z][A-Za-z .'-]{1,60}", nm.strip()):
                st.error("Enter a valid name (letters only, at least 2 characters).")
            elif not city_final:
                st.error("Type the new city name.")
            else:
                tier_final = tier_map.get(city_final, new_tier)
                cid = next_id("customers", "customer_id", "CUST")
                insert_row("customers", {"customer_id": cid, "masked_name": mask_name(nm.strip()),
                                         "age_band": age, "city": city_final, "city_tier": tier_final})
                audit(user["username"], bank, "CUSTOMER_ADDED", f"{cid} {mask_name(nm.strip())}")
                st.session_state["cust_msg"] = (f"Customer {cid} added as {mask_name(nm.strip())} ({city_final}). "
                                                "Now open an account for them in step 2.")
                st.rerun()

    # ---- open account ----
    with cc2:
        st.subheader("2. Open an account")
        types_ = q("SELECT DISTINCT account_type FROM accounts ORDER BY 1")["account_type"].tolist()
        txn_types = sorted(df["txn_type"].unique())
        credit_type = next((t for t in txn_types if any(w in t.lower() for w in ("credit", "deposit"))), txn_types[0])
        newest_first = allc.iloc[::-1]
        with st.form("acct_form", clear_on_submit=True):
            who = st.selectbox("Customer (newest first)", newest_first["customer_id"].tolist(),
                               format_func=lambda c: f"{c} · {newest_first.set_index('customer_id').loc[c, 'masked_name']} · "
                                                     f"{newest_first.set_index('customer_id').loc[c, 'city']}")
            d1, d2 = st.columns(2)
            atype = d1.selectbox("Account type", types_)
            dep_ch = d2.selectbox("Deposit channel", sorted(df["channel"].unique()))
            opening = st.number_input("Opening deposit (₹, minimum 500)", min_value=500.0, value=5000.0, step=500.0)
            open_a = st.form_submit_button("Open account", type="primary", use_container_width=True)
        if open_a:
            acc_id = next_id("accounts", "account_id", "AC")
            insert_row("accounts", {"account_id": acc_id, "customer_id": who, "account_type": atype, "bank_name": bank})
            mrow = run("SELECT merchant_id FROM merchants WHERE merchant_name=?", ("Branch Counter",), True)
            if mrow:
                mid = mrow[0][0]
            else:
                mid = next_id("merchants", "merchant_id", "M")
                insert_row("merchants", {"merchant_id": mid, "merchant_name": "Branch Counter", "category": "Bank Deposit"})
            cust_city = allc.set_index("customer_id").loc[who, "city"]
            tinfo = {r[1]: r for r in run("PRAGMA table_info(transactions)", fetch=True)}
            t = {"account_id": acc_id, "merchant_id": mid, "bank_name": bank, "timestamp": now_s(),
                 "txn_type": credit_type, "channel": dep_ch, "amount": float(opening), "status": "Success",
                 "city": cust_city, "balance_after": float(opening)}
            tc = tinfo.get("txn_id")
            if tc is None or "INT" not in (tc[2] or "").upper():
                t["txn_id"] = "TXN" + secrets.token_hex(5).upper()
            elif not tc[5]:
                t["txn_id"] = int(run("SELECT COALESCE(MAX(txn_id),0)+1 FROM transactions", fetch=True)[0][0])
            insert_row("transactions", t)
            audit(user["username"], bank, "ACCOUNT_OPENED", f"{acc_id} for {who} deposit {opening:.0f}")
            st.cache_data.clear()
            st.session_state["cust_msg"] = (f"Account {acc_id} opened for {who} with {inr(opening)}. "
                                            "It is ready in the Payment desk tab.")
            st.rerun()

    # ---- customer 360 ----
    st.divider()
    st.subheader("3. Customer 360")
    names = df.drop_duplicates("customer_id").set_index("customer_id")["customer_name"]
    pick = st.selectbox("Find a customer", sorted(names.index.tolist()),
                        format_func=lambda c: f"{c} · {names[c]}", key="c360")
    cd = df[df["customer_id"] == pick]
    last = cd.sort_values("timestamp").groupby("account_id").tail(1)
    m = st.columns(4)
    m[0].metric("Accounts", f"{cd['account_id'].nunique()}")
    m[1].metric("Total balance", inr(last["balance_after"].sum()))
    m[2].metric("Transactions", f"{len(cd):,}")
    m[3].metric("Total spent", inr(cd.loc[cd['status'] == 'Success', 'amount'].sum()))
    st.dataframe(last[["account_id", "account_type", "balance_after"]].rename(columns={"balance_after": "balance"}),
                 width="stretch", hide_index=True)
    st.dataframe(cd.sort_values("timestamp", ascending=False)[["txn_id", "timestamp", "txn_type", "channel", "merchant_category", "amount", "status"]].head(10),
                 width="stretch", hide_index=True)

    st.subheader("All customers")
    srch = st.text_input("Search by ID, name or city")
    shown = allc if not srch else allc[allc.apply(lambda r: srch.lower() in " ".join(map(str, r.values)).lower(), axis=1)]
    st.dataframe(shown, width="stretch", hide_index=True)

# ------------------------------------------------------------------------------
# PAYMENT DESK  (real flow: authorise -> validate -> risk check -> write to DB)
# ------------------------------------------------------------------------------
with tab6:
    note("Post a real payment. It is checked against balance, limits and fraud rules, then stored in the database. "
         "Every dashboard updates with it.", "info")
    latest = df.sort_values("timestamp").groupby("account_id").tail(1).set_index("account_id")
    accounts = sorted(latest.index.tolist())
    acc = st.selectbox("Account", accounts,
                       format_func=lambda a: f"{a} · {latest.loc[a, 'customer_name']} · {latest.loc[a, 'account_type']}")
    balance = float(latest.loc[acc, "balance_after"])
    m1, m2, m3 = st.columns(3)
    m1.metric("Available balance", inr(balance))
    m2.metric("Account holder", str(latest.loc[acc, "customer_name"]))
    m3.metric("Account type", str(latest.loc[acc, "account_type"]))

    merchants = df[["merchant_id", "merchant_category"]].drop_duplicates("merchant_id").sort_values("merchant_category")
    mer_map = {r.merchant_id: r.merchant_category for r in merchants.itertuples()}
    with st.form("pay_form"):
        p1, p2, p3 = st.columns(3)
        txn_type = p1.selectbox("Transaction type", sorted(df["txn_type"].unique()))
        channel = p2.selectbox("Channel", sorted(df["channel"].unique()))
        amount = p3.number_input("Amount (₹)", min_value=1.0, value=1000.0, step=100.0)
        p4, p5 = st.columns(2)
        merchant_id = p4.selectbox("Merchant", list(mer_map.keys()), format_func=lambda m: f"{mer_map[m]} · {m}")
        cities = sorted(df["city"].unique())
        default_city = str(latest.loc[acc, "city"])
        city = p5.selectbox("City", cities, index=cities.index(default_city) if default_city in cities else 0)
        pw = st.text_input("Confirm your password to authorise", type="password")
        go = st.form_submit_button("Authorise and post payment", type="primary", use_container_width=True)

    if go:
        stored = run("SELECT password_hash FROM users WHERE username=?", (user["username"],), True)[0][0]
        if not verify_pw(pw, stored):
            audit(user["username"], bank, "PAYMENT_AUTH_FAIL", acc)
            st.error("Password did not match. Payment was not posted.")
        else:
            is_credit = any(w in txn_type.lower() for w in ("credit", "deposit", "refund"))
            problems = []
            with st.status("Processing payment", expanded=True) as stat:
                st.write("✓ Identity confirmed")
                if amount > PER_TXN_LIMIT:
                    problems.append(f"Amount exceeds the per-payment limit of {inr(PER_TXN_LIMIT)}")
                    st.write("✗ Per-payment limit")
                else:
                    st.write("✓ Per-payment limit")
                if not is_credit:
                    if amount > balance:
                        problems.append(f"Insufficient funds (balance {inr(balance)})")
                        st.write("✗ Balance check")
                    else:
                        st.write("✓ Balance check")
                    day_start = datetime.now().strftime("%Y-%m-%d 00:00:00")
                    spent = run("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE account_id=? AND status='Success' AND timestamp>=?",
                                (acc, day_start), True)[0][0]
                    if spent + amount > DAILY_DEBIT_LIMIT:
                        problems.append(f"Daily debit limit of {inr(DAILY_DEBIT_LIMIT)} would be exceeded (already {inr(spent)} today)")
                        st.write("✗ Daily limit")
                    else:
                        st.write("✓ Daily limit")
                cstats = df[df["channel"] == channel]["amount"]
                z = (amount - cstats.mean()) / cstats.std() if cstats.std() else 0
                risk_flags = []
                if z >= 3:
                    risk_flags.append(f"amount is {z:.1f} standard deviations above the {channel} average")
                if datetime.now().hour < 5 and amount > df["amount"].quantile(0.75):
                    risk_flags.append("large payment at night")
                st.write("✓ Fraud screening" if not risk_flags else "⚠ Fraud screening: flagged for review")

                status = "Failed" if problems else "Success"
                new_bal = balance if problems else (balance + amount if is_credit else balance - amount)

                info = {r[1]: r for r in run("PRAGMA table_info(transactions)", fetch=True)}
                vals = {"bank_name": bank, "account_id": acc, "merchant_id": merchant_id,
                        "timestamp": now_s(), "txn_type": txn_type, "channel": channel, "amount": float(amount),
                        "status": status, "city": city, "balance_after": float(new_bal)}
                tid_col = info.get("txn_id")
                if tid_col:
                    ctype = (tid_col[2] or "").upper()
                    if "INT" in ctype:
                        if not tid_col[5]:
                            vals["txn_id"] = int(run("SELECT COALESCE(MAX(txn_id),0)+1 FROM transactions", fetch=True)[0][0])
                    else:
                        vals["txn_id"] = "TXN" + secrets.token_hex(5).upper()
                vals = {k: (v.item() if hasattr(v, "item") else v) for k, v in vals.items() if k in info}
                conn = sqlite3.connect(DB_PATH, timeout=10)
                try:
                    cur = conn.execute(f"INSERT INTO transactions ({', '.join(vals)}) VALUES ({', '.join('?' * len(vals))})",
                                       list(vals.values()))
                    conn.commit()
                    new_id = vals.get("txn_id", cur.lastrowid)
                finally:
                    conn.close()
                st.write("✓ Saved to ledger")
                stat.update(label="Payment processed", state="complete")

            if risk_flags and status == "Success":
                run("INSERT OR REPLACE INTO alert_reviews(txn_id, bank_name, status, note, reviewer, ts) VALUES (?,?,?,?,?,?)",
                    (str(new_id), bank, "Under review", "Auto-flagged at payment desk: " + "; ".join(risk_flags), "system", now_s()))
            audit(user["username"], bank, "PAYMENT_POSTED", f"{new_id} {status} {txn_type} {amount:.2f} {acc}")
            st.cache_data.clear()

            pill = '<span class="pill ok">Success</span>' if status == "Success" else '<span class="pill bad">Failed</span>'
            reason_html = "".join(f"<div class='row'><span>Reason</span><span>{p}</span></div>" for p in problems)
            warn_html = ("<div class='row'><span>Risk review</span><span class='pill warn'>Queued in Fraud alerts</span></div>"
                         if risk_flags and status == "Success" else "")
            st.markdown(f"""
            <div class="receipt"><h3>Payment receipt {pill}</h3>
              <div class="row"><span>Reference</span><span>{new_id}</span></div>
              <div class="row"><span>Account</span><span>{acc}</span></div>
              <div class="row"><span>{txn_type} via {channel}</span><span>{inr(amount)}</span></div>
              <div class="row"><span>Merchant</span><span>{mer_map[merchant_id]}</span></div>
              <div class="row"><span>Balance after</span><span>{inr(new_bal)}</span></div>
              <div class="row"><span>Time</span><span>{vals.get('timestamp')}</span></div>
              {reason_html}{warn_html}
            </div>""", unsafe_allow_html=True)
            st.toast("Payment posted" if status == "Success" else "Payment failed and recorded")

    st.subheader("Recent activity on this account")
    rec = q("SELECT txn_id, timestamp, txn_type, channel, amount, status, balance_after FROM transactions "
            "WHERE account_id=? ORDER BY timestamp DESC LIMIT 8", (acc,))
    st.dataframe(rec, width="stretch", hide_index=True)

# ------------------------------------------------------------------------------
# REPORTS
# ------------------------------------------------------------------------------
with tab7:
    st.subheader("Download reports")
    fl = detect_anomalies(fdf)
    fl = fl[fl["flagged"]]
    d1, d2, d3 = st.columns(3)
    d1.download_button(f"Filtered transactions ({len(fdf):,} rows)", fdf.drop(columns=["date"]).to_csv(index=False).encode(),
                       f"{bank.replace(' ', '_')}_transactions.csv", "text/csv", on_click=audit,
                       args=(user["username"], bank, "EXPORT", f"transactions {len(fdf)} rows"))
    d2.download_button(f"Flagged transactions ({len(fl):,} rows)", fl.drop(columns=["date"]).to_csv(index=False).encode(),
                       f"{bank.replace(' ', '_')}_flagged.csv", "text/csv", on_click=audit,
                       args=(user["username"], bank, "EXPORT", f"flagged {len(fl)} rows"))
    best = fdf.groupby("channel").size().idxmax()
    summary = (f"# {bank}: Transaction summary\n\nPeriod: {start} to {end}\n\n"
               f"- Transactions: {len(fdf):,}\n- Amount moved: {inr(fdf['amount'].sum())}\n"
               f"- Average payment: {inr(fdf['amount'].mean())}\n- Success rate: {(fdf['status']=='Success').mean()*100:.1f}%\n"
               f"- Busiest channel: {best}\n- Flagged transactions: {len(fl):,}\n"
               f"\nGenerated by {user['full_name']} on {now_s()}\n")
    d3.download_button("Executive summary (.md)", summary.encode(), f"{bank.replace(' ', '_')}_summary.md", "text/markdown")

    st.divider()
    st.subheader("Is the difference real? Statistical comparison")
    dim = st.selectbox("Compare average transaction value across", ["channel", "city_tier", "account_type", "age_band"])
    choices = sorted(fdf[dim].unique())
    if len(choices) >= 2:
        c1, c2 = st.columns(2)
        g1 = c1.selectbox("Group A", choices, index=0)
        g2 = c2.selectbox("Group B", choices, index=1)
        res = run_hypothesis_test(fdf, dim, g1, g2)
        if res["valid"]:
            m1, m2 = st.columns(2)
            m1.metric(f"{g1} average", inr(res["mean_a"]), f"{res['n_a']:,} transactions")
            m2.metric(f"{g2} average", inr(res["mean_b"]), f"{res['n_b']:,} transactions")
            if res["significant"]:
                st.success(f"The difference is statistically significant (Welch t-test, p = {res['p_value']:.4e}).")
            else:
                st.warning(f"No significant difference (Welch t-test, p = {res['p_value']:.4f}).")
        else:
            st.info("Not enough data in one of the groups.")
    else:
        st.info("Pick a dimension with at least two groups in the current filter.")

# ------------------------------------------------------------------------------
# AUDIT LOG
# ------------------------------------------------------------------------------
with tab8:
    note("Every sign-in, payment, review and export for your bank is recorded here.", "info")
    log = q("SELECT ts AS time, username, action, detail FROM audit_log WHERE bank_name=? ORDER BY id DESC LIMIT 300", (bank,))
    st.dataframe(log, width="stretch", hide_index=True)
    st.caption(f"Session ends after {SESSION_TIMEOUT_MIN} minutes of inactivity. Accounts lock for {LOCK_MINUTES} minutes after {MAX_FAILED_LOGINS} wrong passwords.")

st.markdown(f"""
<div class="footer">
    <div><b>Banking Transaction Pattern Analysis</b> · {bank} workspace</div>
    <div>Signed in as {user['full_name']} · Python, SQLite &amp; Streamlit</div>
</div>""", unsafe_allow_html=True)