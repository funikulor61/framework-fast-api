from fastapi import FastAPI, Form, File, Request, Depends, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from urllib.parse import quote
from datetime import datetime
import csv, os, re, secrets, hashlib, time

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def render(request, name, **ctx):
    resp = templates.TemplateResponse(request=request, name=name, context=ctx)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def redirect(url):
    return RedirectResponse(url=url, status_code=303)


FILE_NAME = "logs.csv"
MSGS_FILE = "messages.csv"
NEWS_FILE = "news.csv"
SESSION_LIFETIME = 30 * 60
SECRET_SALT1 = "PAROL_"
SECRET_SALT2 = "_SECURITY"
ADMIN_LOGIN = "admin"
ADMIN_PASSWORD = "admin123"
MODERATOR_LOGIN = "moderator"
MODERATOR_PASSWORD = "moder123"
ROLE_OBSERVER = "Наблюдатель"
ROLE_MODERATOR = "Модератор"
ROLE_ADMIN = "Админ"
USERS_HEADER = ["Login", "Password", "Avatar", "Role"]
MSGS_HEADER = ["sender", "receiver", "text", "is_deleted_by_sender", "is_deleted_by_receiver"]
NEWS_HEADER = ["id", "title", "text", "author", "created_at", "updated_at", "updated_by"]
AVATAR_DIR = os.path.join("static", "avatars")
AVATAR_MAX_BYTES = 5 * 1024 * 1024
AVATAR_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

os.makedirs(AVATAR_DIR, exist_ok=True)


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        w.writerows(rows)


def append_csv(path, row):
    with open(path, "a", encoding="utf-8", newline="") as f:
        csv.writer(f).writerow(row)


def init_users_file():
    if not os.path.exists(FILE_NAME):
        return append_csv(FILE_NAME, USERS_HEADER)
    rows = list(csv.reader(open(FILE_NAME, encoding="utf-8", newline="")))
    if rows and rows[0][:len(USERS_HEADER)] == USERS_HEADER:
        return
    rows = [USERS_HEADER] + [(r + ["", ""])[:4] for r in rows[1:]]
    with open(FILE_NAME, "w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerows(rows)


init_users_file()
if not os.path.exists(MSGS_FILE):
    write_csv(MSGS_FILE, MSGS_HEADER, [])
if not os.path.exists(NEWS_FILE):
    write_csv(NEWS_FILE, NEWS_HEADER, [])


def now_str():
    return datetime.now().strftime("%d.%m.%Y %H:%M")


def load_news():
    return sorted(read_csv(NEWS_FILE), key=lambda r: int(r["id"]), reverse=True)


def get_news(news_id):
    return next((r for r in read_csv(NEWS_FILE) if int(r["id"]) == news_id), None)


def next_news_id():
    return max((int(r["id"]) for r in read_csv(NEWS_FILE)), default=0) + 1


def save_news_row(new_row, news_id=None):
    rows = read_csv(NEWS_FILE)
    if news_id is None:
        rows.append(dict(zip(NEWS_HEADER, new_row)))
    else:
        for r in rows:
            if int(r["id"]) == news_id:
                r.update(dict(zip(NEWS_HEADER, new_row)))
    write_csv(NEWS_FILE, NEWS_HEADER, rows)


def hash_password(password):
    return hashlib.sha256(f"{SECRET_SALT1}{password}{SECRET_SALT2}".encode()).hexdigest()


def get_user(username):
    for row in read_csv(FILE_NAME):
        if row.get("Login") == username:
            return {"password": row.get("Password"), "avatar": (row.get("Avatar") or "").strip(),
                    "role": (row.get("Role") or "").strip() or ROLE_OBSERVER}
    return None


def save_avatar(username, upload):
    if not upload or not upload.filename:
        return None
    ext = os.path.splitext(upload.filename)[1].lower()
    content = upload.file.read() if ext in AVATAR_EXTENSIONS else b""
    if not content or len(content) > AVATAR_MAX_BYTES:
        return None
    name = f"{re.sub(r'[^\w\-]+', '_', username).strip('_') or 'user'}_{secrets.token_hex(4)}{ext}"
    with open(os.path.join(AVATAR_DIR, name), "wb") as f:
        f.write(content)
    return name


# ═══════════ Сессии ═══════════
SESSIONS = {}


def create_session(username):
    sid = secrets.token_urlsafe(16)
    SESSIONS[sid] = {"user": username, "theme": "light", "expires": time.time() + SESSION_LIFETIME}
    return sid


async def get_session(request: Request):
    sid = request.query_params.get("sid")
    if not sid and request.method == "POST":
        sid = (await request.form()).get("sid")
    d = SESSIONS.get(sid) if sid else None
    if not d or time.time() > d["expires"]:
        SESSIONS.pop(sid, None)
        return {"sid": None, "user": None, "theme": "light", "stale": bool(sid)}
    return {"sid": sid, "user": d["user"], "theme": d["theme"], "stale": False}


def guard(sess):
    if sess["user"]:
        return None
    return redirect("/403" if sess["stale"] else "/login")


@app.get("/", response_class=HTMLResponse)
def main_page(request: Request):
    return render(request, "based_main.html", news=load_news())


@app.get("/main", response_class=HTMLResponse)
def home_page(request: Request, with_user: str | None = None, sess=Depends(get_session)):
    if r := guard(sess):
        return r
    user = get_user(sess["user"]) or {}
    return render(request, "main.html", username=sess["user"], password_hash=user.get("password"),
                  avatar=user.get("avatar", ""), role=user.get("role", ROLE_OBSERVER), news=load_news(),
                  chats=chat_list(sess["user"]), with_user=with_user,
                  history=chat_history(sess["user"], with_user) if with_user else [],
                  sid=sess["sid"], theme=sess["theme"])


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, sess=Depends(get_session)):
    if sess["user"]:
        return redirect(f"/main?sid={sess['sid']}")
    return render(request, "login.html")


@app.post("/login")
def login(request: Request, password: str = Form(...), username: str = Form(...)):
    username = username.strip()
    special = {(ADMIN_LOGIN, ADMIN_PASSWORD): ROLE_ADMIN,
               (MODERATOR_LOGIN, MODERATOR_PASSWORD): ROLE_MODERATOR}
    role = special.get((username, password))
    if role:
        user = get_user(username)
        if user is None:
            append_csv(FILE_NAME, [username, hash_password(password), "", role])
        elif user["password"] != hash_password(password) or user["role"] != role:
            update_user_fields(username, {"Password": hash_password(password), "Role": role})
    user = get_user(username)
    if not user or user["password"] is None:
        return render(request, "login_nouser.html")
    if user["password"] != hash_password(password):
        return render(request, "login_wrong_password.html")
    return redirect(f"/main?sid={create_session(username)}")


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, msg: str | None = None):
    return render(request, "register.html", msg=msg)


@app.post("/register")
def register(request: Request, password: str = Form(...), username: str = Form(...),
             avatar: UploadFile | None = File(None)):
    if get_user(username):
        return render(request, "user_exist.html")
    avatar_name = save_avatar(username, avatar)
    if avatar_name is None:
        return render(request, "register_avatar_error.html")
    append_csv(FILE_NAME, [username, hash_password(password), avatar_name, ""])
    return redirect(f"/main?sid={create_session(username)}")


@app.get("/logout")
def logout(sid: str | None = None):
    SESSIONS.pop(sid, None)
    return redirect("/login")


@app.get("/404", response_class=HTMLResponse)
def _404_page(request: Request):
    return render(request, "404.html")


@app.get("/403", response_class=HTMLResponse)
def _403_page(request: Request):
    return render(request, "403.html")


# ═══════════ Переписка ═══════════
def chat_list(username):
    chats = {}
    for i, row in enumerate(read_csv(MSGS_FILE)):
        if row["sender"] == username:
            partner, hidden = row["receiver"], row["is_deleted_by_sender"]
        elif row["receiver"] == username:
            partner, hidden = row["sender"], row["is_deleted_by_receiver"]
        else:
            continue
        if hidden != "True":
            chats[partner] = {"user": partner, "sender": row["sender"], "last": row["text"], "i": i}
    return sorted(chats.values(), key=lambda c: c["i"], reverse=True)


def chat_history(username, with_user):
    return [{"sender": r["sender"], "text": r["text"]} for r in read_csv(MSGS_FILE)
            if (r["sender"] == username and r["receiver"] == with_user
                and r["is_deleted_by_sender"] != "True")
            or (r["sender"] == with_user and r["receiver"] == username
                and r["is_deleted_by_receiver"] != "True")]


@app.post("/send")
def send_message(text: str = Form(""), receiver: str = Form(...), sess=Depends(get_session)):
    if r := guard(sess):
        return r
    text = text.strip()
    if text:
        append_csv(MSGS_FILE, [sess["user"], receiver, text, "False", "False"])
    return redirect(f"/main?with_user={quote(receiver)}&sid={sess['sid']}")


@app.post("/delete-chat")
def delete_chat(with_user: str = Form(...), sess=Depends(get_session)):
    if r := guard(sess):
        return r
    username = sess["user"]
    rows = read_csv(MSGS_FILE)
    for row in rows:
        if row["sender"] == username and row["receiver"] == with_user:
            row["is_deleted_by_sender"] = "True"
        elif row["sender"] == with_user and row["receiver"] == username:
            row["is_deleted_by_receiver"] = "True"
    write_csv(MSGS_FILE, MSGS_HEADER, rows)
    return redirect(f"/main?sid={sess['sid']}")


@app.get("/theme")
def toggle_theme(next: str = "/main", sess=Depends(get_session)):
    if r := guard(sess):
        return r
    d = SESSIONS[sess["sid"]]
    d["theme"] = "dark" if d["theme"] == "light" else "light"
    return redirect(next)


# ═══════════ Роли ═══════════
ROLE_PAGES = {
    "moderator": {"template": "moderator.html", "role": ROLE_MODERATOR,
                  "login": MODERATOR_LOGIN, "password": MODERATOR_PASSWORD},
    "admin": {"template": "admin.html", "role": ROLE_ADMIN,
              "login": ADMIN_LOGIN, "password": ADMIN_PASSWORD},
}


def update_user_fields(username, fields):
    rows = read_csv(FILE_NAME)
    for row in rows:
        if row.get("Login") == username:
            row.update(fields)
    write_csv(FILE_NAME, USERS_HEADER, rows)


def all_users():
    return [{"login": r.get("Login"), "role": (r.get("Role") or "").strip() or ROLE_OBSERVER,
             "avatar": (r.get("Avatar") or "").strip()} for r in read_csv(FILE_NAME)]


def recent_messages(limit=30):
    return read_csv(MSGS_FILE)[-limit:][::-1]


def render_role_page(request, sess, key, error=None):
    p = ROLE_PAGES[key]
    my_role = (get_user(sess["user"]) or {}).get("role", ROLE_OBSERVER)
    granted = my_role == ROLE_ADMIN or my_role == p["role"]
    ctx = {"username": sess["user"], "my_role": my_role, "granted": granted, "error": error,
           "sid": sess["sid"], "theme": sess["theme"]}
    if granted:
        ctx |= {"users": all_users()} if key == "admin" else {"messages": recent_messages()}
    return render(request, p["template"], **ctx)


@app.get("/moderator", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
def role_page(request: Request, sess=Depends(get_session)):
    if r := guard(sess):
        return r
    return render_role_page(request, sess, request.url.path.strip("/"))


@app.post("/moderator")
@app.post("/admin")
def role_submit(request: Request, login: str = Form(...), password: str = Form(...), sess=Depends(get_session)):
    if r := guard(sess):
        return r
    key = request.url.path.strip("/")
    p = ROLE_PAGES[key]
    if login.strip() == p["login"] and password == p["password"]:
        update_user_fields(sess["user"], {"Role": p["role"]})
        return redirect(f"/main?sid={sess['sid']}")
    return render_role_page(request, sess, key, error="Неверный логин или пароль.")


# ═══════════ Новости ═══════════
def need_role(sess, *roles):
    user = get_user(sess["user"]) if sess["user"] else None
    if user is None:
        return redirect("/403" if sess["stale"] else "/login")
    return None if user["role"] in roles else redirect(f"/main?sid={sess['sid']}")


def news_form_context(request, sess, is_edit, news_id, title, text, error):
    post_url = f"/news/{news_id}/edit?sid={sess['sid']}" if is_edit else f"/news/new?sid={sess['sid']}"
    return render(request, "news_form.html", is_edit=is_edit, title_value=title, text_value=text,
                  error=error, post_url=post_url, sid=sess["sid"], theme=sess["theme"])


@app.get("/news/new", response_class=HTMLResponse)
def news_new_page(request: Request, sess=Depends(get_session)):
    if r := need_role(sess, ROLE_ADMIN):
        return r
    return news_form_context(request, sess, False, None, "", "", None)


@app.post("/news/new")
def news_create(request: Request, title: str = Form(""), text: str = Form(""), sess=Depends(get_session)):
    if r := need_role(sess, ROLE_ADMIN):
        return r
    title, text = title.strip(), text.strip()
    if not title or not text:
        return news_form_context(request, sess, False, None, title, text, "Заполните заголовок и текст новости.")
    save_news_row([next_news_id(), title, text, sess["user"], now_str(), "", ""])
    return redirect(f"/main?sid={sess['sid']}")


@app.get("/news/{news_id}/edit", response_class=HTMLResponse)
def news_edit_page(news_id: int, request: Request, sess=Depends(get_session)):
    if r := need_role(sess, ROLE_MODERATOR, ROLE_ADMIN):
        return r
    news = get_news(news_id)
    if news is None:
        return redirect(f"/main?sid={sess['sid']}")
    return news_form_context(request, sess, True, news_id, news["title"], news["text"], None)


@app.post("/news/{news_id}/edit")
def news_update(news_id: int, request: Request, title: str = Form(""), text: str = Form(""), sess=Depends(get_session)):
    if r := need_role(sess, ROLE_MODERATOR, ROLE_ADMIN):
        return r
    news = get_news(news_id)
    if news is None:
        return redirect(f"/main?sid={sess['sid']}")
    title, text = title.strip(), text.strip()
    if not title or not text:
        return news_form_context(request, sess, True, news_id, title, text, "Заполните заголовок и текст новости.")
    save_news_row([news["id"], title, text, news["author"], news["created_at"], now_str(), sess["user"]], news_id)
    return redirect(f"/main?sid={sess['sid']}")