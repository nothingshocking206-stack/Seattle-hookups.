"""
Seattle Hookups — full-stack MVP backend.

Single-file FastAPI app + SQLite. Serves the mobile-first frontend from /static
and exposes a JSON API under /api/.

Run locally:
    uvicorn main:app --reload --port 8000

Environment variables (all optional):
    DB_PATH        path to the SQLite file            (default ./data/app.db)
    UPLOAD_DIR     directory for uploaded photos      (default ./uploads)
    COOKIE_SECURE  set to "1" in production (HTTPS)   (default "0" for local dev)
    SESSION_DAYS   session lifetime in days           (default 30)

Security notes (see README.md OPERATING NOTES before opening to the public):
  - Passwords are hashed with bcrypt. Sessions are random server-side tokens
    stored in the DB and delivered in an HttpOnly, SameSite=Lax cookie.
  - Every query is parameterized. Uploaded files are validated by magic bytes
    (not just extension), size-capped, and stored under random filenames.
  - 18+ is enforced at signup (date of birth) and every API route requires a
    logged-in (therefore adult) account.
"""

import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import bcrypt
from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DB_PATH", BASE_DIR / "data" / "app.db"))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", BASE_DIR / "uploads"))
COOKIE_NAME = "sh_session"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
SESSION_DAYS = int(os.environ.get("SESSION_DAYS", "30"))

MAX_PHOTOS_PER_USER = 4
MAX_PHOTO_BYTES = 5 * 1024 * 1024  # ~5 MB
MAX_MESSAGE_LEN = 2000

# Fixed list of real Seattle neighborhoods used for profiles and filters.
NEIGHBORHOODS = [
    "Capitol Hill", "Ballard", "Fremont", "Queen Anne", "Lower Queen Anne",
    "Belltown", "Downtown", "South Lake Union", "Eastlake", "First Hill",
    "Pioneer Square", "Chinatown–International District", "SoDo", "Georgetown",
    "West Seattle", "Beacon Hill", "Columbia City", "Rainier Valley",
    "University District", "Wallingford", "Green Lake", "Greenwood",
    "Phinney Ridge", "Magnolia", "Madison Park", "Montlake", "Northgate",
    "Lake City", "White Center",
]

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def get_db() -> sqlite3.Connection:
    """Open a new SQLite connection with FK enforcement and Row access."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    dob           TEXT NOT NULL,              -- ISO date YYYY-MM-DD
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
    user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    neighborhood TEXT NOT NULL,
    bio          TEXT NOT NULL DEFAULT '',
    looking_for  TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS photos (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename    TEXT NOT NULL,               -- random name on disk
    uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS swipes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    swiper_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action     TEXT NOT NULL CHECK (action IN ('like', 'pass')),
    created_at TEXT NOT NULL,
    UNIQUE (swiper_id, target_id)
);

CREATE TABLE IF NOT EXISTS matches (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user2_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE (user1_id, user2_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id   INTEGER NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    sender_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE (blocker_id, blocked_id)
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reported_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_photos_user    ON photos(user_id);
CREATE INDEX IF NOT EXISTS idx_swipes_swiper  ON swipes(swiper_id);
CREATE INDEX IF NOT EXISTS idx_swipes_target ON swipes(target_id);
CREATE INDEX IF NOT EXISTS idx_matches_u1     ON matches(user1_id);
CREATE INDEX IF NOT EXISTS idx_matches_u2     ON matches(user2_id);
CREATE INDEX IF NOT EXISTS idx_messages_match ON messages(match_id);
CREATE INDEX IF NOT EXISTS idx_blocks         ON blocks(blocker_id, blocked_id);
"""


def init_db() -> None:
    """Create schema (and only the schema — no fake users, by design)."""
    with get_db() as conn:
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def age_from_dob(dob: date) -> int:
    today = date.today()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def parse_dob(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise HTTPException(400, "dob must be a valid date in YYYY-MM-DD format")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=SESSION_DAYS)
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user_id, now.isoformat(timespec="seconds"), expires.isoformat(timespec="seconds")),
    )
    conn.commit()
    return token


def session_cookie_kwargs() -> dict:
    # NB: does NOT include "key" — call sites pass (COOKIE_NAME, token, **this).
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": COOKIE_SECURE,
        "path": "/",
        "max_age": SESSION_DAYS * 24 * 3600,
    }


def destroy_session(conn: sqlite3.Connection, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def other_user_in_match(match_row: sqlite3.Row, me: int) -> int:
    return match_row["user2_id"] if match_row["user1_id"] == me else match_row["user1_id"]


def ordered_pair(a: int, b: int) -> tuple[int, int]:
    return (a, b) if a < b else (b, a)


# --- minimal in-memory rate limiter for the auth endpoints -------------------
# (per-IP sliding window; enough to blunt credential-stuffing on a small MVP)
_RATE_BUCKETS: dict[str, list[float]] = {}
_RATE_LIMIT = 20          # max attempts
_RATE_WINDOW = 10 * 60    # per 10 minutes


def check_rate_limit(ip: str) -> None:
    now = time.time()
    bucket = [t for t in _RATE_BUCKETS.get(ip, []) if now - t < _RATE_WINDOW]
    if len(bucket) >= _RATE_LIMIT:
        raise HTTPException(429, "Too many attempts — please wait a few minutes and try again.")
    bucket.append(now)
    _RATE_BUCKETS[ip] = bucket


# --- upload validation: magic bytes, never trust the extension alone --------
MAGIC_TYPES = [
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    # WebP: RIFF....WEBF
]


def detect_image_type(head: bytes) -> str | None:
    for magic, ext in MAGIC_TYPES:
        if head.startswith(magic):
            return ext
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def photo_url(filename: str) -> str:
    return f"/uploads/{filename}"


def public_profile_dict(row: sqlite3.Row, photos: list[str]) -> dict:
    """Shape of a profile as shown to other users (never includes email/dob)."""
    return {
        "user_id": row["user_id"],
        "display_name": row["display_name"],
        "age": row["age"],
        "neighborhood": row["neighborhood"],
        "bio": row["bio"],
        "looking_for": row["looking_for"],
        "photos": photos,
    }


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class SignupIn(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=128)
    dob: str  # YYYY-MM-DD; must be 18+

    @field_validator("email")
    @classmethod
    def valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("enter a valid email address")
        return v


class LoginIn(BaseModel):
    email: str
    password: str


class ProfileIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=40)
    neighborhood: str
    bio: str = Field(default="", max_length=500)
    looking_for: str = Field(default="", max_length=200)

    @field_validator("neighborhood")
    @classmethod
    def known_neighborhood(cls, v: str) -> str:
        if v not in NEIGHBORHOODS:
            raise ValueError("choose a neighborhood from the list")
        return v


class SwipeIn(BaseModel):
    target_user_id: int
    action: str

    @field_validator("action")
    @classmethod
    def known_action(cls, v: str) -> str:
        if v not in ("like", "pass"):
            raise ValueError("action must be 'like' or 'pass'")
        return v


class MessageIn(BaseModel):
    body: str = Field(min_length=1, max_length=MAX_MESSAGE_LEN)


class BlockIn(BaseModel):
    user_id: int


class ReportIn(BaseModel):
    user_id: int
    reason: str = Field(min_length=1, max_length=1000)


# ---------------------------------------------------------------------------
# App + auth dependency
# ---------------------------------------------------------------------------

app = FastAPI(title="Seattle Hookups MVP", docs_url="/api/docs")


def current_user_id(session_token: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> int:
    """Dependency: resolve the logged-in user from the session cookie.

    Every /api route except signup/login uses this, which is also how the
    18+ requirement is enforced everywhere — only verified-adult accounts
    can hold a session.
    """
    if not session_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    with get_db() as conn:
        row = conn.execute(
            "SELECT user_id, expires_at FROM sessions WHERE token = ?", (session_token,)
        ).fetchone()
        if not row:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired — please sign in again")
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            conn.execute("DELETE FROM sessions WHERE token = ?", (session_token,))
            conn.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired — please sign in again")
        # sliding expiry
        new_exp = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
        conn.execute("UPDATE sessions SET expires_at = ? WHERE token = ?", (new_exp, session_token))
        conn.commit()
        return int(row["user_id"])


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@app.post("/api/signup", status_code=201)
def signup(payload: SignupIn, session_token: str | None = Cookie(default=None, alias=COOKIE_NAME)):
    check_rate_limit("signup")  # simple global bucket for signup abuse
    dob = parse_dob(payload.dob)
    age = age_from_dob(dob)
    if age < 18:
        # 18+ is a hard requirement: do not create the account at all.
        raise HTTPException(403, "You must be 18 or older to use this app.")
    with get_db() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE email = ?", (payload.email,)).fetchone()
        if exists:
            raise HTTPException(409, "An account with that email already exists.")
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, dob, created_at) VALUES (?, ?, ?, ?)",
            (payload.email, hash_password(payload.password), dob.isoformat(), utcnow_iso()),
        )
        user_id = cur.lastrowid
        # Log them straight in, invalidating any previous session cookie.
        destroy_session(conn, session_token)
        token = create_session(conn, user_id)
    resp = JSONResponse({"user": {"id": user_id, "email": payload.email, "age": age}}, status_code=201)
    resp.set_cookie(COOKIE_NAME, token, **session_cookie_kwargs())
    return resp


@app.post("/api/login")
def login(payload: LoginIn, session_token: str | None = Cookie(default=None, alias=COOKIE_NAME)):
    check_rate_limit("login")
    email = payload.email.strip().lower()
    with get_db() as conn:
        row = conn.execute("SELECT id, password_hash, dob FROM users WHERE email = ?", (email,)).fetchone()
        if not row or not verify_password(payload.password, row["password_hash"]):
            # Same message either way: don't reveal which accounts exist.
            raise HTTPException(401, "Email or password didn't match.")
        destroy_session(conn, session_token)
        token = create_session(conn, int(row["id"]))
    resp = JSONResponse(
        {"user": {"id": row["id"], "email": email, "age": age_from_dob(date.fromisoformat(row["dob"]))}}
    )
    resp.set_cookie(COOKIE_NAME, token, **session_cookie_kwargs())
    return resp


@app.post("/api/logout")
def logout(session_token: str | None = Cookie(default=None, alias=COOKIE_NAME)):
    with get_db() as conn:
        destroy_session(conn, session_token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


# ---------------------------------------------------------------------------
# Profiles + photos
# ---------------------------------------------------------------------------


@app.get("/api/neighborhoods")
def list_neighborhoods():
    return {"neighborhoods": NEIGHBORHOODS}


@app.get("/api/me")
def me(uid: int = Depends(current_user_id)):
    with get_db() as conn:
        user = conn.execute("SELECT id, email, dob FROM users WHERE id = ?", (uid,)).fetchone()
        profile = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (uid,)).fetchone()
        photos = [r["filename"] for r in conn.execute(
            "SELECT filename FROM photos WHERE user_id = ? ORDER BY id", (uid,))]
    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "age": age_from_dob(date.fromisoformat(user["dob"])),
        },
        "profile": dict(profile) if profile else None,
        "photos": [photo_url(f) for f in photos],
    }


@app.put("/api/profile")
def upsert_profile(payload: ProfileIn, uid: int = Depends(current_user_id)):
    now = utcnow_iso()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO profiles (user_id, display_name, neighborhood, bio, looking_for, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                 display_name=excluded.display_name, neighborhood=excluded.neighborhood,
                 bio=excluded.bio, looking_for=excluded.looking_for, updated_at=excluded.updated_at""",
            (uid, payload.display_name.strip(), payload.neighborhood,
             payload.bio.strip(), payload.looking_for.strip(), now),
        )
        conn.commit()
        profile = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (uid,)).fetchone()
    return {"profile": dict(profile)}


@app.post("/api/photos", status_code=201)
async def upload_photo(file: UploadFile = File(...), uid: int = Depends(current_user_id)):
    # Read with a hard cap so a malicious client can't stream forever.
    data = await file.read(MAX_PHOTO_BYTES + 1)
    if len(data) > MAX_PHOTO_BYTES:
        raise HTTPException(413, f"Photo too large — max {MAX_PHOTO_BYTES // (1024*1024)} MB.")
    if not data:
        raise HTTPException(400, "Empty file.")
    kind = detect_image_type(data[:12])
    if not kind:
        raise HTTPException(400, "That file isn't a JPEG, PNG, WebP, or GIF image.")
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM photos WHERE user_id = ?", (uid,)).fetchone()["c"]
        if count >= MAX_PHOTOS_PER_USER:
            raise HTTPException(400, f"You can upload up to {MAX_PHOTOS_PER_USER} photos.")
        filename = f"{uuid.uuid4().hex}.{kind}"
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        (UPLOAD_DIR / filename).write_bytes(data)  # nosec: name is server-generated
        conn.execute(
            "INSERT INTO photos (user_id, filename, uploaded_at) VALUES (?, ?, ?)",
            (uid, filename, utcnow_iso()),
        )
        conn.commit()
        photos = [r["filename"] for r in conn.execute(
            "SELECT filename FROM photos WHERE user_id = ? ORDER BY id", (uid,))]
    return {"photos": [photo_url(f) for f in photos]}


@app.get("/api/photos-meta")
def photos_meta(uid: int = Depends(current_user_id)):
    """Photo ids + urls for the current user (ids are needed to delete)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, filename FROM photos WHERE user_id = ? ORDER BY id", (uid,)
        ).fetchall()
    return {"photos": [{"id": r["id"], "url": photo_url(r["filename"])} for r in rows]}


@app.delete("/api/photos/{photo_id}")
def delete_photo(photo_id: int, uid: int = Depends(current_user_id)):
    with get_db() as conn:
        row = conn.execute("SELECT filename FROM photos WHERE id = ? AND user_id = ?", (photo_id, uid)).fetchone()
        if not row:
            raise HTTPException(404, "Photo not found.")
        conn.execute("DELETE FROM photos WHERE id = ?", (photo_id,))
        conn.commit()
    try:
        (UPLOAD_DIR / row["filename"]).unlink(missing_ok=True)
    except OSError:
        pass
    return {"ok": True}


# ---------------------------------------------------------------------------
# Discovery + matching
# ---------------------------------------------------------------------------


@app.get("/api/discover")
def discover(
    neighborhood: str | None = Query(default=None),
    min_age: int = Query(default=18, ge=18, le=99),
    max_age: int = Query(default=99, ge=18, le=99),
    limit: int = Query(default=20, ge=1, le=50),
    uid: int = Depends(current_user_id),
):
    """Browse profiles. Never returns yourself, anyone you've swiped on, or
    anyone on either side of a block."""
    if min_age > max_age:
        raise HTTPException(400, "min_age can't be above max_age.")
    params: list = [uid, uid, uid, uid]
    query = """
        SELECT p.*, u.dob FROM profiles p
        JOIN users u ON u.id = p.user_id
        WHERE p.user_id != ?
          AND p.user_id NOT IN (SELECT target_id FROM swipes WHERE swiper_id = ?)
          AND p.user_id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id = ?)
          AND p.user_id NOT IN (SELECT blocker_id FROM blocks WHERE blocked_id = ?)
    """
    if neighborhood:
        if neighborhood not in NEIGHBORHOODS:
            raise HTTPException(400, "Unknown neighborhood.")
        query += " AND p.neighborhood = ?"
        params.append(neighborhood)
    query += " ORDER BY RANDOM() LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        out = []
        for r in rows:
            age = age_from_dob(date.fromisoformat(r["dob"]))
            if not (min_age <= age <= max_age):
                continue
            photos = [pr["filename"] for pr in conn.execute(
                "SELECT filename FROM photos WHERE user_id = ? ORDER BY id", (r["user_id"],))]
            out.append(public_profile_dict({**dict(r), "age": age}, [photo_url(f) for f in photos]))
    return {"profiles": out}


@app.post("/api/swipe")
def swipe(payload: SwipeIn, uid: int = Depends(current_user_id)):
    if payload.target_user_id == uid:
        raise HTTPException(400, "You can't swipe on yourself.")
    with get_db() as conn:
        target = conn.execute(
            "SELECT p.user_id FROM profiles p WHERE p.user_id = ?", (payload.target_user_id,)
        ).fetchone()
        if not target:
            raise HTTPException(404, "That profile doesn't exist.")
        blocked = conn.execute(
            """SELECT 1 FROM blocks
               WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)""",
            (uid, payload.target_user_id, payload.target_user_id, uid),
        ).fetchone()
        if blocked:
            raise HTTPException(403, "You can't interact with this profile.")
        conn.execute(
            """INSERT INTO swipes (swiper_id, target_id, action, created_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(swiper_id, target_id) DO UPDATE SET action=excluded.action""",
            (uid, payload.target_user_id, payload.action, utcnow_iso()),
        )
        matched = False
        match_id = None
        if payload.action == "like":
            mutual = conn.execute(
                "SELECT 1 FROM swipes WHERE swiper_id = ? AND target_id = ? AND action = 'like'",
                (payload.target_user_id, uid),
            ).fetchone()
            if mutual:
                u1, u2 = ordered_pair(uid, payload.target_user_id)
                cur = conn.execute(
                    """INSERT INTO matches (user1_id, user2_id, created_at)
                       VALUES (?, ?, ?) ON CONFLICT(user1_id, user2_id) DO NOTHING""",
                    (u1, u2, utcnow_iso()),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT id FROM matches WHERE user1_id = ? AND user2_id = ?", (u1, u2)
                ).fetchone()
                matched, match_id = True, row["id"]
        conn.commit()
    return {"matched": matched, "match_id": match_id}


def _match_or_404(conn: sqlite3.Connection, match_id: int, uid: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM matches WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
        (match_id, uid, uid),
    ).fetchone()
    if not row:
        raise HTTPException(404, "Match not found.")
    return row


@app.get("/api/matches")
def list_matches(uid: int = Depends(current_user_id)):
    with get_db() as conn:
        rows = conn.execute(
            """SELECT m.*, MAX(msg.created_at) AS last_at FROM matches m
               LEFT JOIN messages msg ON msg.match_id = m.id
               WHERE m.user1_id = ? OR m.user2_id = ?
               GROUP BY m.id ORDER BY last_at DESC NULLS LAST, m.created_at DESC""",
            (uid, uid),
        ).fetchall()
        out = []
        for m in rows:
            other_id = other_user_in_match(m, uid)
            prof = conn.execute("SELECT * FROM profiles WHERE user_id = ?", (other_id,)).fetchone()
            user = conn.execute("SELECT dob FROM users WHERE id = ?", (other_id,)).fetchone()
            photos = [pr["filename"] for pr in conn.execute(
                "SELECT filename FROM photos WHERE user_id = ? ORDER BY id", (other_id,))]
            last = conn.execute(
                "SELECT body, sender_id, created_at FROM messages WHERE match_id = ? ORDER BY id DESC LIMIT 1",
                (m["id"],),
            ).fetchone()
            out.append({
                "match_id": m["id"],
                "other": public_profile_dict(
                    {**dict(prof), "age": age_from_dob(date.fromisoformat(user["dob"]))},
                    [photo_url(f) for f in photos],
                ) if prof else {"user_id": other_id},
                "last_message": dict(last) if last else None,
            })
    return {"matches": out}


@app.get("/api/matches/{match_id}/messages")
def get_messages(match_id: int, after_id: int = Query(default=0, ge=0),
                 uid: int = Depends(current_user_id)):
    """Poll for messages. Pass after_id=<last seen id> for incremental fetch."""
    with get_db() as conn:
        _match_or_404(conn, match_id, uid)
        rows = conn.execute(
            "SELECT id, sender_id, body, created_at FROM messages "
            "WHERE match_id = ? AND id > ? ORDER BY id ASC LIMIT 100",
            (match_id, after_id),
        ).fetchall()
    return {"messages": [dict(r) for r in rows]}


@app.post("/api/matches/{match_id}/messages", status_code=201)
def send_message(match_id: int, payload: MessageIn, uid: int = Depends(current_user_id)):
    body = payload.body.strip()
    if not body:
        raise HTTPException(400, "Message can't be empty.")
    with get_db() as conn:
        _match_or_404(conn, match_id, uid)
        cur = conn.execute(
            "INSERT INTO messages (match_id, sender_id, body, created_at) VALUES (?, ?, ?, ?)",
            (match_id, uid, body, utcnow_iso()),
        )
        conn.commit()
        msg = conn.execute(
            "SELECT id, sender_id, body, created_at FROM messages WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
    return {"message": dict(msg)}


# ---------------------------------------------------------------------------
# Safety: block, report, tips
# ---------------------------------------------------------------------------

SAFETY_TIPS = [
    {"title": "Meet in public first",
     "body": "Choose a busy public place for the first few meetings — a bar or café in your neighborhood, not someone's home."},
    {"title": "Tell a friend your plans",
     "body": "Share who you're meeting, where, and when with someone you trust. Check in with them during and after."},
    {"title": "Keep it on the app at first",
     "body": "Chat here before sharing your phone number, socials, or address. Anyone pressuring you to move off-app fast is a red flag."},
    {"title": "Consent is ongoing",
     "body": "Only yes means yes — and anyone can change their mind at any time. If something feels off, leave. You never owe anyone your time."},
    {"title": "Trust your gut, use the tools",
     "body": "Block anyone who makes you uncomfortable — they won't be told. Report harassment, threats, or suspected underage users and we'll review it."},
    {"title": "Protect your privacy",
     "body": "Don't share financial info, ID photos, or intimate images with people you just met. Screenshots last forever."},
]


@app.get("/api/safety")
def safety_tips():
    return {"tips": SAFETY_TIPS}


@app.post("/api/block")
def block_user(payload: BlockIn, uid: int = Depends(current_user_id)):
    if payload.user_id == uid:
        raise HTTPException(400, "You can't block yourself.")
    with get_db() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE id = ?", (payload.user_id,)).fetchone()
        if not exists:
            raise HTTPException(404, "User not found.")
        conn.execute(
            "INSERT INTO blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(blocker_id, blocked_id) DO NOTHING",
            (uid, payload.user_id, utcnow_iso()),
        )
        # Remove any match between the two so messaging stops immediately.
        u1, u2 = ordered_pair(uid, payload.user_id)
        conn.execute("DELETE FROM matches WHERE user1_id = ? AND user2_id = ?", (u1, u2))
        conn.commit()
    return {"ok": True}


@app.post("/api/report", status_code=201)
def report_user(payload: ReportIn, uid: int = Depends(current_user_id)):
    if payload.user_id == uid:
        raise HTTPException(400, "You can't report yourself.")
    reason = payload.reason.strip()
    with get_db() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE id = ?", (payload.user_id,)).fetchone()
        if not exists:
            raise HTTPException(404, "User not found.")
        conn.execute(
            "INSERT INTO reports (reporter_id, reported_id, reason, created_at) VALUES (?, ?, ?, ?)",
            (uid, payload.user_id, reason, utcnow_iso()),
        )
        # Reporting also blocks: the reported user immediately disappears
        # from the reporter's discovery, matches, and messages.
        conn.execute(
            "INSERT INTO blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(blocker_id, blocked_id) DO NOTHING",
            (uid, payload.user_id, utcnow_iso()),
        )
        u1, u2 = ordered_pair(uid, payload.user_id)
        conn.execute("DELETE FROM matches WHERE user1_id = ? AND user2_id = ?", (u1, u2))
        conn.commit()
    return {"ok": True, "note": "Report saved. The user has also been blocked from your account."}


# ---------------------------------------------------------------------------
# Frontend + uploads (served by the same process — one deployable unit)
# ---------------------------------------------------------------------------

STATIC_DIR = BASE_DIR / "static"

# Create serving directories at import time: Starlette's StaticFiles raises
# if the directory is missing, and the very first run has neither yet.
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.on_event("startup")
def on_startup():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    init_db()


# Re-mount static AFTER startup-safe dir creation is not needed; keep the
# frontend mount last so /api routes take precedence.
app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=False), name="static")
