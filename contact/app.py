import json
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import uuid
from datetime import timedelta
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash


load_dotenv()

if not os.getenv("SECRETKEY") or not os.getenv("MESSAGEKEY"):
    raise RuntimeError(
        "Create .env with SECRETKEY and MESSAGEKEY first."
    )

app = Flask(__name__, instance_relative_config=True)

app.config.update(
    SECRET_KEY=os.environ["SECRETKEY"],
    MAX_CONTENT_LENGTH=52 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIESECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

ROOT = Path(app.instance_path)
ROOT.mkdir(parents=True, exist_ok=True)

UPLOADS = ROOT / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)

DATABASE = ROOT / "conatct.sqlite3"

cipher = Fernet(os.environ["MESSAGEKEY"].encode())

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per minute"],
    storage_uri=os.getenv("RATELIMITSTORAGEURI", "memory://"),
)


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS spaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK(kind IN ('page', 'group')),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL REFERENCES users(id),
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS memberships (
    space_id INTEGER NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY(space_id, user_id)
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL REFERENCES users(id),
    space_id INTEGER REFERENCES spaces(id) ON DELETE CASCADE,
    body TEXT NOT NULL DEFAULT '',
    media TEXT,
    kind TEXT NOT NULL CHECK(kind IN ('post', 'reel')),
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS likes (
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY(post_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL REFERENCES users(id),
    recipient TEXT NOT NULL REFERENCES users(id),
    ciphertext TEXT NOT NULL,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS posts_space
ON posts(space_id, id);

CREATE INDEX IF NOT EXISTS message_pair
ON messages(sender, recipient, id);
"""


with sqlite3.connect(DATABASE) as connection:
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(SCHEMA)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    connection = g.pop("db", None)
    if connection:
        connection.close()


def one(sql, args=()):
    return db().execute(sql, args).fetchone()


def all_rows(sql, args=()):
    return db().execute(sql, args).fetchall()


def write(sql, args=()):
    with db():
        cursor = db().execute(sql, args)
    return cursor.lastrowid


def field(name, maximum, required=True):
    value = request.form.get(name, "").strip()

    if required and not value:
        abort(
            400,
            description=f"{name.capitalize()} is required.",
        )

    if len(value) > maximum:
        abort(
            400,
            description=(
                f"Invalid {name}; maximum "
                f"{maximum} characters."
            ),
        )

    return value


def logged_in(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("auth"))
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def security():
    g.nonce = secrets.token_urlsafe(24)

    g.user = one(
        """
        SELECT id, username, name
        FROM users
        WHERE id=?
        """,
        (session.get("uid"),),
    )

    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = (
            request.form.get("csrf")
            or request.headers.get("X-CSRF-Token", "")
        )

        if not secrets.compare_digest(
            token,
            session["csrf"],
        ):
            abort(
                400,
                description=(
                    "Invalid security token. "
                    "Reload and try again."
                ),
            )


@app.after_request
def headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"

    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'nonce-{g.nonce}'; "
        f"style-src 'nonce-{g.nonce}'; "
        "img-src 'self'; "
        "media-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )

    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000"
        )

    return response


@app.errorhandler(HTTPException)
def handle_http_error(error):
    if request.path.startswith("/api/"):
        return jsonify(
            error=error.description,
            code=error.code,
        ), error.code

    return render_template(
        "index.html",
        view="error",
        error=error.description,
    ), error.code


@app.route("/auth", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def auth():
    if request.method == "GET":
        if g.user:
            return redirect(url_for("home"))

        return render_template(
            "index.html",
            view="auth",
        )

    mode = request.form.get("mode")

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
        abort(
            400,
            description=(
                "Use 3–30 lowercase letters, "
                "numbers, or underscores."
            ),
        )

    if not 12 <= len(password) <= 128:
        abort(
            400,
            description=(
                "Passwords must contain "
                "12–128 characters."
            ),
        )

    if mode == "register":
        name = field("name", 60)

        uid = str(uuid.uuid4())

        try:
            write(
                """
                INSERT INTO users
                    (id, username, name, password_hash)
                VALUES (?, ?, ?, ?)
                """,
                (
                    uid,
                    username,
                    name,
                    generate_password_hash(
                        password,
                        method="scrypt",
                    ),
                ),
            )

        except sqlite3.IntegrityError:
            abort(
                409,
                description=(
                    "That username is already taken."
                ),
            )

    elif mode == "login":
        user = one(
            """
            SELECT *
            FROM users
            WHERE username=?
            """,
            (username,),
        )

        if (
            not user
            or not check_password_hash(
                user["password_hash"],
                password,
            )
        ):
            abort(
                401,
                description=(
                    "Incorrect username or password."
                ),
            )

        uid = user["id"]

    else:
        abort(400)

    session.clear()
    session["uid"] = uid
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True

    return redirect(url_for("home"))


@app.post("/logout")
@logged_in
def logout():
    session.clear()
    return redirect(url_for("auth"))


def get_space(space_id):
    space = one(
        """
        SELECT *
        FROM spaces
        WHERE id=?
        """,
        (space_id,),
    )

    if not space:
        abort(
            404,
            description="Page or group not found.",
        )

    return space


def is_member(space_id):
    return (
        one(
            """
            SELECT 1
            FROM memberships
            WHERE space_id=? AND user_id=?
            """,
            (space_id, g.user["id"]),
        )
        is not None
    )


def may_publish(space):
    return (
        space["owner"] == g.user["id"]
        or (
            space["kind"] == "group"
            and is_member(space["id"])
        )
    )


def posts_for(where="1=1", args=()):
    return all_rows(
        f"""
        SELECT
            p.*,
            u.name AS author_name,
            u.username,
            s.name AS space_name,
            s.kind AS space_kind,
            s.owner AS space_owner,

            (
                SELECT COUNT(*)
                FROM likes l
                WHERE l.post_id=p.id
            ) AS like_count,

            EXISTS(
                SELECT 1
                FROM likes l
                WHERE l.post_id=p.id
                AND l.user_id=?
            ) AS liked

        FROM posts p
        JOIN users u
            ON u.id=p.author

        LEFT JOIN spaces s
            ON s.id=p.space_id

        WHERE {where}

        ORDER BY p.id DESC
        LIMIT 100
        """,
        (g.user["id"], *args),
    )


@app.get("/")
@logged_in
def home():
    return render_template(
        "index.html",
        view="feed",
        posts=posts_for("p.kind='post'"),
    )


@app.get("/reels")
@logged_in
def reels():
    return render_template(
        "index.html",
        view="reels",
        posts=posts_for("p.kind='reel'"),
    )


def save_media(upload, reel=False):
    if not upload or not upload.filename:
        if reel:
            abort(
                400,
                description="Choose a video for your reel.",
            )
        return None

    if not reel:
        filename = f"{uuid.uuid4().hex}.jpg"

        try:
            with Image.open(upload.stream) as image:
                if image.width * image.height > 25_000_000:
                    abort(
                        400,
                        description="Image is too large.",
                    )

                image = ImageOps.exif_transpose(image)
                image.thumbnail((1920, 1920))

                image.convert("RGB").save(
                    UPLOADS / filename,
                    "JPEG",
                    quality=88,
                )

        except (
            UnidentifiedImageError,
            OSError,
            ValueError,
            Image.DecompressionBombError,
        ):
            abort(
                400,
                description=(
                    "Choose a valid JPEG, PNG, "
                    "or WebP image."
                ),
            )

        return filename

    extension = Path(upload.filename).suffix.lower()

    if extension not in {".mp4", ".webm"}:
        abort(
            400,
            description="Reels must be MP4 or WebM videos.",
        )

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=extension,
            delete=False,
            dir=UPLOADS,
        ) as temporary:
            temp_path = Path(temporary.name)
            upload.save(temporary)

        if temp_path.stat().st_size > 50 * 1024 * 1024:
            abort(
                400,
                description="Maximum video size is 50 MB.",
            )

        result = subprocess.run(
            [
                "ffprobe",
                "-v",
                "error",
                "-protocol_whitelist",
                "file",
                "-show_entries",
                "format=duration,format_name:"
                "stream=codec_type,codec_name",
                "-of",
                "json",
                str(temp_path),
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )

        info = json.loads(result.stdout)

        duration = float(
            info.get("format", {}).get("duration", 0)
        )

        format_name = info.get(
            "format",
            {},
        ).get("format_name", "")

        videos = [
            stream
            for stream in info.get("streams", [])
            if stream.get("codec_type") == "video"
        ]

        audio = [
            stream
            for stream in info.get("streams", [])
            if stream.get("codec_type") == "audio"
        ]

        expected_format = (
            "mp4" if extension == ".mp4" else "webm"
        )

        allowed_video = (
            {"h264"}
            if extension == ".mp4"
            else {"vp8", "vp9"}
        )

        allowed_audio = (
            {"aac"}
            if extension == ".mp4"
            else {"opus", "vorbis"}
        )

        valid = (
            0 < duration <= 90
            and expected_format in format_name
            and len(videos) == 1
            and videos[0].get("codec_name")
            in allowed_video
            and all(
                stream.get("codec_name")
                in allowed_audio
                for stream in audio
            )
        )

        if not valid:
            abort(
                400,
                description=(
                    "Use a video up to 90 seconds: "
                    "MP4/H.264/AAC or "
                    "WebM/VP8/VP9/Opus/Vorbis."
                ),
            )

        filename = f"{uuid.uuid4().hex}{extension}"

        temp_path.replace(UPLOADS / filename)

        return filename

    except FileNotFoundError:
        abort(
            503,
            description=(
                "Install FFmpeg on the server "
                "to enable reels."
            ),
        )

    except (
        subprocess.SubprocessError,
        ValueError,
        TypeError,
        OSError,
    ):
        abort(
            400,
            description="The video could not be validated.",
        )

    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)


@app.post("/posts")
@logged_in
@limiter.limit("20 per hour")
def create_post():
    body = field(
        "body",
        5000,
        required=False,
    )

    kind = request.form.get("kind", "post")

    if kind not in {"post", "reel"}:
        abort(400)

    raw_space = request.form.get("space_id")

    space_id = None

    if raw_space:
        if not raw_space.isdigit():
            abort(400)

        space = get_space(int(raw_space))

        if not may_publish(space):
            abort(
                403,
                description=(
                    "You cannot publish in "
                    "this page or group."
                ),
            )

        space_id = space["id"]

    media = save_media(
        request.files.get("media"),
        reel=(kind == "reel"),
    )

    if not body and not media:
        abort(
            400,
            description=(
                "Write something or attach media."
            ),
        )

    try:
        write(
            """
            INSERT INTO posts
                (author, space_id, body, media, kind)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                g.user["id"],
                space_id,
                body,
                media,
                kind,
            ),
        )

    except Exception:
        if media:
            (UPLOADS / media).unlink(missing_ok=True)
        raise

    if space_id:
        return redirect(
            url_for(
                "space_detail",
                space_id=space_id,
            )
        )

    return redirect(
        url_for(
            "reels" if kind == "reel" else "home"
        )
    )


@app.get("/media/<path:filename>")
@logged_in
def media(filename):
    if not one(
        "SELECT 1 FROM posts WHERE media=?",
        (filename,),
    ):
        abort(404)

    return send_from_directory(
        UPLOADS,
        filename,
    )


@app.post("/posts/<int:post_id>/like")
@logged_in
def like(post_id):
    if not one(
        "SELECT 1 FROM posts WHERE id=?",
        (post_id,),
    ):
        abort(404)

    args = (
        post_id,
        g.user["id"],
    )

    with db():
        existing = one(
            """
            SELECT 1
            FROM likes
            WHERE post_id=? AND user_id=?
            """,
            args,
        )

        if existing:
            db().execute(
                """
                DELETE FROM likes
                WHERE post_id=? AND user_id=?
                """,
                args,
            )
        else:
            db().execute(
                """
                INSERT INTO likes(post_id, user_id)
                VALUES (?, ?)
                """,
                args,
            )

    return redirect(url_for("home"))


@app.post("/posts/<int:post_id>/delete")
@logged_in
def delete_post(post_id):
    post = one(
        """
        SELECT
            p.*,
            s.owner AS moderator
        FROM posts p
        LEFT JOIN spaces s
            ON s.id=p.space_id
        WHERE p.id=?
        """,
        (post_id,),
    )

    if not post:
        abort(404)

    if g.user["id"] not in {
        post["author"],
        post["moderator"],
    }:
        abort(403)

    write(
        "DELETE FROM posts WHERE id=?",
        (post_id,),
    )

    if post["media"]:
        (UPLOADS / post["media"]).unlink(
            missing_ok=True
        )

    return redirect(url_for("home"))


@app.get("/spaces")
@logged_in
def spaces():
    entries = all_rows(
        """
        SELECT
            s.*,
            u.name AS owner_name,

            (
                SELECT COUNT(*)
                FROM memberships m
                WHERE m.space_id=s.id
            ) AS member_count

        FROM spaces s
        JOIN users u
            ON u.id=s.owner

        ORDER BY s.id DESC
        LIMIT 100
        """
    )

    return render_template(
        "index.html",
        view="spaces",
        spaces=entries,
    )


@app.post("/spaces")
@logged_in
@limiter.limit("10 per hour")
def create_space():
    kind = request.form.get("kind")

    if kind not in {"page", "group"}:
        abort(400)

    name = field("name", 80)

    description = field(
        "description",
        1000,
        required=False,
    )

    with db():
        cursor = db().execute(
            """
            INSERT INTO spaces
                (kind, name, description, owner)
            VALUES (?, ?, ?, ?)
            """,
            (
                kind,
                name,
                description,
                g.user["id"],
            ),
        )

        space_id = cursor.lastrowid

        db().execute(
            """
            INSERT INTO memberships(space_id, user_id)
            VALUES (?, ?)
            """,
            (
                space_id,
                g.user["id"],
            ),
        )

    return redirect(
        url_for(
            "space_detail",
            space_id=space_id,
        )
    )


@app.get("/spaces/<int:space_id>")
@logged_in
def space_detail(space_id):
    space = get_space(space_id)

    members = []

    if space["owner"] == g.user["id"]:
        members = all_rows(
            """
            SELECT
                u.id,
                u.name,
                u.username
            FROM memberships m
            JOIN users u
                ON u.id=m.user_id
            WHERE m.space_id=?
            ORDER BY u.username
            """,
            (space_id,),
        )

    count = one(
        """
        SELECT COUNT(*) AS n
        FROM memberships
        WHERE space_id=?
        """,
        (space_id,),
    )["n"]

    return render_template(
        "index.html",
        view="space",
        space=space,
        members=members,
        membercount=count,
        joined=is_member(space_id),
        canpublish=may_publish(space),
        posts=posts_for(
            "p.space_id=?",
            (space_id,),
        ),
    )


@app.post("/spaces/<int:space_id>/membership")
@logged_in
def membership(space_id):
    space = get_space(space_id)

    if space["owner"] == g.user["id"]:
        abort(
            400,
            description=(
                "Owners cannot leave "
                "their own page or group."
            ),
        )

    if is_member(space_id):
        write(
            """
            DELETE FROM memberships
            WHERE space_id=? AND user_id=?
            """,
            (
                space_id,
                g.user["id"],
            ),
        )
    else:
        write(
            """
            INSERT OR IGNORE INTO memberships
                (space_id, user_id)
            VALUES (?, ?)
            """,
            (
                space_id,
                g.user["id"],
            ),
        )

    return redirect(
        url_for(
            "space_detail",
            space_id=space_id,
        )
    )


@app.post("/spaces/<int:space_id>/manage")
@logged_in
def manage_space(space_id):
    space = get_space(space_id)

    if space["owner"] != g.user["id"]:
        abort(403)

    action = request.form.get("action")

    if action == "update":
        write(
            """
            UPDATE spaces
            SET name=?, description=?
            WHERE id=?
            """,
            (
                field("name", 80),
                field(
                    "description",
                    1000,
                    required=False,
                ),
                space_id,
            ),
        )

    elif action == "remove":
        if space["kind"] != "group":
            abort(400)

        uid = field("userid", 36)

        if uid == space["owner"]:
            abort(
                400,
                description=(
                    "You cannot remove the owner."
                ),
            )

        write(
            """
            DELETE FROM memberships
            WHERE space_id=? AND user_id=?
            """,
            (
                space_id,
                uid,
            ),
        )

    elif action == "delete":
        attachments = all_rows(
            """
            SELECT media
            FROM posts
            WHERE space_id=?
            AND media IS NOT NULL
            """,
            (space_id,),
        )

        write(
            "DELETE FROM spaces WHERE id=?",
            (space_id,),
        )

        for attachment in attachments:
            (
                UPLOADS / attachment["media"]
            ).unlink(missing_ok=True)

        return redirect(url_for("spaces"))

    else:
        abort(400)

    return redirect(
        url_for(
            "space_detail",
            space_id=space_id,
        )
    )


@app.get("/messages")
@logged_in
def messages():
    q = request.args.get(
        "q",
        "",
    ).strip()[:30]

    people = all_rows(
        """
        SELECT id, name, username
        FROM users
        WHERE id != ?
        AND username LIKE ?
        ORDER BY username
        LIMIT 50
        """,
        (
            g.user["id"],
            f"%{q.lower()}%",
        ),
    )

    peer = None
    peer_id = request.args.get("peer")

    if peer_id:
        peer = one(
            """
            SELECT id, name, username
            FROM users
            WHERE id=?
            AND id != ?
            """,
            (
                peer_id,
                g.user["id"],
            ),
        )

        if not peer:
            abort(
                404,
                description="User not found.",
            )

    return render_template(
        "index.html",
        view="messages",
        people=people,
        peer=peer,
        q=q,
    )


def get_peer(peer_id):
    if peer_id == g.user["id"]:
        abort(
            400,
            description="Choose another user.",
        )

    if not one(
        "SELECT 1 FROM users WHERE id=?",
        (peer_id,),
    ):
        abort(
            404,
            description="User not found.",
        )


@app.get("/api/messages/<peer_id>")
@logged_in
def read_messages(peer_id):
    get_peer(peer_id)

    rows = all_rows(
        """
        SELECT *
        FROM (
            SELECT
                id,
                sender,
                ciphertext,
                created
            FROM messages
            WHERE
                (sender=? AND recipient=?)
                OR
                (sender=? AND recipient=?)
            ORDER BY id DESC
            LIMIT 100
        )
        ORDER BY id
        """,
        (
            g.user["id"],
            peer_id,
            peer_id,
            g.user["id"],
        ),
    )

    return jsonify(
        [
            {
                "id": row["id"],
                "mine": (
                    row["sender"]
                    == g.user["id"]
                ),
                "text": cipher.decrypt(
                    row["ciphertext"].encode()
                ).decode(),
                "created": row["created"],
            }
            for row in rows
        ]
    )


@app.post("/api/messages/<peer_id>")
@logged_in
@limiter.limit("30 per minute")
def send_message(peer_id):
    get_peer(peer_id)

    text = field("text", 4000)

    write(
        """
        INSERT INTO messages
            (sender, recipient, ciphertext)
        VALUES (?, ?, ?)
        """,
        (
            g.user["id"],
            peer_id,
            cipher.encrypt(
                text.encode()
            ).decode(),
        ),
    )

    return jsonify(ok=True), 201


if __name__ == "__main__":
    # Codespaces needs 0.0.0.0 so port 5000 can be forwarded.
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )