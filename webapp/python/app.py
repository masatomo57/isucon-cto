import datetime
import os
import pathlib
import re
import shlex
import subprocess
import tempfile

import flask
import MySQLdb.cursors
from flask_session import Session
from jinja2 import pass_eval_context
from markupsafe import Markup, escape
from pymemcache.client.base import Client as MemcacheClient

UPLOAD_LIMIT = 10 * 1024 * 1024  # 10mb
POSTS_PER_PAGE = 20


_config = None


def config():
    global _config
    if _config is None:
        _config = {
            "db": {
                "host": os.environ.get("ISUCONP_DB_HOST", "localhost"),
                "port": int(os.environ.get("ISUCONP_DB_PORT", "3306")),
                "user": os.environ.get("ISUCONP_DB_USER", "root"),
                "db": os.environ.get("ISUCONP_DB_NAME", "isuconp"),
            },
            "memcache": {
                "address": os.environ.get(
                    "ISUCONP_MEMCACHED_ADDRESS", "127.0.0.1:11211"
                ),
            },
        }
        password = os.environ.get("ISUCONP_DB_PASSWORD")
        if password:
            _config["db"]["passwd"] = password
    return _config


_db = None


def db():
    global _db
    if _db is None:
        conf = config()["db"].copy()
        conf["charset"] = "utf8mb4"
        conf["cursorclass"] = MySQLdb.cursors.DictCursor
        conf["autocommit"] = True
        _db = MySQLdb.connect(**conf)
    return _db


def db_initialize():
    cur = db().cursor()
    sqls = [
        "DELETE FROM users WHERE id > 1000",
        "DELETE FROM posts WHERE id > 10000",
        "DELETE FROM comments WHERE id > 100000",
        "UPDATE users SET del_flg = 0",
        "UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
    ]
    for q in sqls:
        cur.execute(q)


_mcclient = None


def memcache():
    global _mcclient
    if _mcclient is None:
        conf = config()["memcache"]
        _mcclient = MemcacheClient(
            conf["address"], no_delay=True, default_noreply=False
        )
    return _mcclient


def try_login(account_name, password):
    cur = db().cursor()
    cur.execute(
        "SELECT * FROM users WHERE account_name = %s AND del_flg = 0", (account_name,)
    )
    user = cur.fetchone()

    if user and calculate_passhash(user["account_name"], password) == user["passhash"]:
        return user
    return None


def validate_user(account_name: str, password: str):
    if not re.match(r"[0-9a-zA-Z]{3,}", account_name):
        return False
    if not re.match(r"[0-9a-zA-Z_]{6,}", password):
        return False
    return True


def digest(src: str):
    # opensslのバージョンによっては (stdin)= というのがつくので取る
    out = subprocess.check_output(
        f"printf %s {shlex.quote(src)} | openssl dgst -sha512 | sed 's/^.*= //'",
        shell=True,
        encoding="utf-8",
    )
    return out.strip()


def calculate_salt(account_name: str):
    return digest(account_name)


def calculate_passhash(account_name: str, password: str):
    return digest("%s:%s" % (password, calculate_salt(account_name)))


def get_session_user():
    user = flask.session.get("user")
    if user:
        cur = db().cursor()
        cur.execute("SELECT * FROM `users` WHERE `id` = %s", (user["id"],))
        return cur.fetchone()
    return None


def make_posts(results, all_comments=False):
    if not results:
        return []

    # 必要なIDを収集
    post_ids = [p["id"] for p in results]
    user_ids_from_posts = {p["user_id"] for p in results}

    cursor = db().cursor()
    
    # 1. コメントを一括取得（最大20件に制限し、インデックスを活用）
    post_id_placeholders = ",".join(["%s"] * len(post_ids))
    
    if all_comments:
        # 全コメント取得時も20件に制限
        comment_query = f"""
            SELECT * FROM `comments` 
            WHERE `post_id` IN ({post_id_placeholders}) 
            ORDER BY `post_id`, `created_at` DESC
            LIMIT 20
        """
    else:
        # 通常時は3件×投稿数程度に制限（最大20件）
        limit_count = min(len(post_ids) * 3, 20)
        comment_query = f"""
            SELECT * FROM `comments` 
            WHERE `post_id` IN ({post_id_placeholders}) 
            ORDER BY `post_id`, `created_at` DESC
            LIMIT {limit_count}
        """
    
    cursor.execute(comment_query, tuple(post_ids))
    all_related_comments = list(cursor.fetchall())
    
    # コメントからユーザーIDを収集
    user_ids_from_comments = {c["user_id"] for c in all_related_comments}
    
    # 2. ユーザー情報を一括取得
    all_user_ids = list(user_ids_from_posts | user_ids_from_comments)
    users_by_id = {}
    if all_user_ids:
        user_id_placeholders = ",".join(["%s"] * len(all_user_ids))
        user_query = f"SELECT * FROM `users` WHERE `id` IN ({user_id_placeholders})"
        cursor.execute(user_query, tuple(all_user_ids))
        for u in cursor.fetchall():
            users_by_id[u["id"]] = u

    # 3. 投稿ごとのコメントとコメント数を組み立てる
    comments_by_post_id = {}
    comment_counts = {}
    for post_id in post_ids:
        comments_by_post_id[post_id] = []
        comment_counts[post_id] = 0

    for comment in all_related_comments:
        post_id = comment["post_id"]
        comment_counts[post_id] += 1
        # all_comments=False の場合は3件まで格納
        if all_comments or len(comments_by_post_id[post_id]) < 3:
            comment["user"] = users_by_id.get(comment["user_id"])
            comments_by_post_id[post_id].append(comment)

    # 4. 最終的な投稿リストを生成
    posts = []
    for p in results:
        p["user"] = users_by_id.get(p["user_id"])
        
        # コメントを時系列順に戻す
        post_comments = comments_by_post_id.get(p["id"], [])
        post_comments.reverse()
        
        p["comments"] = post_comments
        p["comment_count"] = comment_counts.get(p["id"], 0)
        
        # get_index以外から呼ばれた場合も想定し、del_flgチェックを残す
        if p["user"] and not p["user"]["del_flg"]:
            posts.append(p)

    return posts


# app setup
static_path = pathlib.Path(__file__).resolve().parent.parent / "public"
app = flask.Flask(__name__, static_folder=str(static_path), static_url_path="")
# app.debug = True

# Flask-Session
app.config["SESSION_TYPE"] = "memcached"
app.config["SESSION_MEMCACHED"] = memcache()
Session(app)


@app.template_global()
def image_url(post):
    ext = ""
    mime = post["mime"]
    if mime == "image/jpeg":
        ext = ".jpg"
    elif mime == "image/png":
        ext = ".png"
    elif mime == "image/gif":
        ext = ".gif"

    return "/image/%s%s" % (post["id"], ext)


# http://flask.pocoo.org/snippets/28/
_paragraph_re = re.compile(r"(?:\r\n|\r|\n){2,}")


@app.template_filter()
@pass_eval_context
def nl2br(eval_ctx, value):
    result = "\n\n".join(
        "<p>%s</p>" % p.replace("\n", "<br>\n")
        for p in _paragraph_re.split(escape(value))
    )
    if eval_ctx.autoescape:
        result = Markup(result)
    return result


# endpoints


@app.route("/initialize")
def get_initialize():
    db_initialize()
    return ""


@app.route("/login")
def get_login():
    if get_session_user():
        return flask.redirect("/")
    return flask.render_template("login.html", me=None)


@app.route("/login", methods=["POST"])
def post_login():
    if get_session_user():
        return flask.redirect("/")

    user = try_login(flask.request.form["account_name"], flask.request.form["password"])
    if user:
        flask.session["user"] = {"id": user["id"]}
        flask.session["csrf_token"] = os.urandom(8).hex()
        return flask.redirect("/")

    flask.flash("アカウント名かパスワードが間違っています")
    return flask.redirect("/login")


@app.route("/register")
def get_register():
    if get_session_user():
        return flask.redirect("/")
    return flask.render_template("register.html", me=None)


@app.route("/register", methods=["POST"])
def post_register():
    if get_session_user():
        return flask.redirect("/")

    account_name = flask.request.form["account_name"]
    password = flask.request.form["password"]
    if not validate_user(account_name, password):
        flask.flash(
            "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
        )
        return flask.redirect("/register")

    cursor = db().cursor()
    cursor.execute("SELECT 1 FROM users WHERE `account_name` = %s", (account_name,))
    user = cursor.fetchone()
    if user:
        flask.flash("アカウント名がすでに使われています")
        return flask.redirect("/register")

    query = "INSERT INTO `users` (`account_name`, `passhash`) VALUES (%s, %s)"
    cursor.execute(query, (account_name, calculate_passhash(account_name, password)))

    flask.session["user"] = {"id": cursor.lastrowid}
    flask.session["csrf_token"] = os.urandom(8).hex()
    return flask.redirect("/")


@app.route("/logout")
def get_logout():
    flask.session.clear()
    return flask.redirect("/")


@app.route("/")
def get_index():
    me = get_session_user()
    cursor = db().cursor()

    # 最適化されたクエリ（インデックスを活用）
    query = """
        SELECT p.id, p.user_id, p.body, p.created_at, p.mime
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE u.del_flg = 0
        ORDER BY p.created_at DESC
        LIMIT %s
    """
    cursor.execute(query, (POSTS_PER_PAGE,))
    results = cursor.fetchall()

    posts = make_posts(results)

    return flask.render_template("index.html", posts=posts, me=me)


@app.route("/@<account_name>")
def get_user_list(account_name):
    cursor = db().cursor()

    cursor.execute(
        "SELECT * FROM `users` WHERE `account_name` = %s AND `del_flg` = 0",
        (account_name,),
    )
    user = cursor.fetchone()
    if user is None:
        flask.abort(404)

    # LIMIT追加で最適化
    cursor.execute(
        """SELECT `id`, `user_id`, `body`, `mime`, `created_at` 
           FROM `posts` 
           WHERE `user_id` = %s 
           ORDER BY `created_at` DESC
           LIMIT %s""",
        (user["id"], POSTS_PER_PAGE),
    )
    posts = make_posts(cursor.fetchall())

    cursor.execute(
        "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = %s", (user["id"],)
    )
    comment_count = cursor.fetchone()["count"]

    cursor.execute("SELECT `id` FROM `posts` WHERE `user_id` = %s", (user["id"],))
    post_ids = [p["id"] for p in cursor]
    post_count = len(post_ids)

    commented_count = 0
    if post_count > 0:
        cursor.execute(
            "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN %s",
            (post_ids,),
        )
        commented_count = cursor.fetchone()["count"]

    me = get_session_user()

    return flask.render_template(
        "user.html",
        posts=posts,
        user=user,
        post_count=post_count,
        comment_count=comment_count,
        commented_count=commented_count,
        me=me,
    )


def _parse_iso8601(s):
    # http://bugs.python.org/issue15873
    # Ignore timezone
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[ tT](\d{2}):(\d{2}):(\d{2}).*", s)
    if not m:
        raise ValueError("Invlaid iso8601 format: %r" % (s,))
    return datetime.datetime(*map(int, m.groups()))


@app.route("/posts")
def get_posts():
    cursor = db().cursor()
    max_created_at = flask.request.args.get("max_created_at") or None
    if max_created_at:
        max_created_at = _parse_iso8601(max_created_at)
        cursor.execute(
            """SELECT `id`, `user_id`, `body`, `mime`, `created_at` 
               FROM `posts` 
               WHERE `created_at` <= %s 
               ORDER BY `created_at` DESC
               LIMIT %s""",
            (max_created_at, POSTS_PER_PAGE),
        )
    else:
        cursor.execute(
            """SELECT `id`, `user_id`, `body`, `mime`, `created_at` 
               FROM `posts` 
               ORDER BY `created_at` DESC
               LIMIT %s""",
            (POSTS_PER_PAGE,)
        )
    results = cursor.fetchall()
    posts = make_posts(results)
    return flask.render_template("posts.html", posts=posts)


@app.route("/posts/<id>")
def get_posts_id(id):
    cursor = db().cursor()

    cursor.execute("""
        SELECT p.* 
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = %s AND u.del_flg = 0
    """, (id,))
    posts = make_posts(cursor.fetchall(), all_comments=True)
    if not posts:
        flask.abort(404)

    me = get_session_user()
    return flask.render_template("post.html", post=posts[0], me=me)


@app.route("/", methods=["POST"])
def post_index():
    me = get_session_user()
    if not me:
        return flask.redirect("/login")

    if flask.request.form["csrf_token"] != flask.session["csrf_token"]:
        flask.abort(422)

    file = flask.request.files.get("file")
    if not file:
        flask.flash("画像が必要です")
        return flask.redirect("/")

    # 投稿のContent-Typeからファイルのタイプを決定する
    mime = file.mimetype
    if mime not in ("image/jpeg", "image/png", "image/gif"):
        flask.flash("投稿できる画像形式はjpgとpngとgifだけです")
        return flask.redirect("/")

    with tempfile.TemporaryFile() as tempf:
        file.save(tempf)
        tempf.flush()

        if tempf.tell() > UPLOAD_LIMIT:
            flask.flash("ファイルサイズが大きすぎます")
            return flask.redirect("/")

        tempf.seek(0)
        imgdata = tempf.read()

    query = "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (%s,%s,%s,%s)"
    cursor = db().cursor()
    cursor.execute(query, (me["id"], mime, imgdata, flask.request.form.get("body")))
    pid = cursor.lastrowid
    return flask.redirect("/posts/%d" % pid)


@app.route("/image/<id>.<ext>")
def get_image(id, ext):
    if not id:
        return ""
    id = int(id)
    if id == 0:
        return ""

    cursor = db().cursor()
    cursor.execute("SELECT * FROM `posts` WHERE `id` = %s", (id,))
    post = cursor.fetchone()

    mime = post["mime"]
    if (
        ext == "jpg"
        and mime == "image/jpeg"
        or ext == "png"
        and mime == "image/png"
        or ext == "gif"
        and mime == "image/gif"
    ):
        return flask.Response(post["imgdata"], mimetype=mime)

    flask.abort(404)


@app.route("/comment", methods=["POST"])
def post_comment():
    me = get_session_user()
    if not me:
        return flask.redirect("/login")

    if flask.request.form["csrf_token"] != flask.session["csrf_token"]:
        flask.abort(422)

    post_id = flask.request.form["post_id"]
    if not re.match(r"[0-9]+", post_id):
        return "post_idは整数のみです"
    post_id = int(post_id)

    query = (
        "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (%s, %s, %s)"
    )
    cursor = db().cursor()
    cursor.execute(query, (post_id, me["id"], flask.request.form["comment"]))

    return flask.redirect("/posts/%d" % post_id)


@app.route("/admin/banned")
def get_banned():
    me = get_session_user()
    if not me:
        flask.redirect("/login")

    if me["authority"] == 0:
        flask.abort(403)

    cursor = db().cursor()
    cursor.execute(
        "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC"
    )
    users = cursor.fetchall()

    flask.render_template("banned.html", users=users, me=me)


@app.route("/admin/banned", methods=["POST"])
def post_banned():
    me = get_session_user()
    if not me:
        flask.redirect("/login")

    if me["authority"] == 0:
        flask.abort(403)

    if flask.request.form["csrf_token"] != flask.session["csrf_token"]:
        flask.abort(422)

    cursor = db().cursor()
    query = "UPDATE `users` SET `del_flg` = %s WHERE `id` = %s"
    for id in flask.request.form.getlist("uid", type=int):
        cursor.execute(query, (1, id))

    return flask.redirect("/admin/banned")
