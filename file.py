'python -m uvicorn file:app --reload'
from fastapi import FastAPI, Form, File, Request, Depends, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from urllib.parse import quote
import csv
import os
import re
import secrets
import hashlib
import time
from datetime import datetime

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

FILE_NAME = "logs.csv"       # пользователи: Login, Password (хэш sha256), Avatar, Role
MSGS_FILE = "messages.csv"   # сообщения чата
NEWS_FILE = "news.csv"       # новости сайта
SESSION_LIFETIME = 30 * 60   # сессия живёт 30 минут

SECRET_SALT1 = "PAROL_"
SECRET_SALT2 = "_SECURITY"

# ───────────── Служебные аккаунты для получения ролей ─────────────
# Их логин/пароль вводят на странице роли (или сразу на странице входа),
# и статус пользователя меняется с «Наблюдатель» на «Модератор»/«Админ».
ADMIN_LOGIN = "admin"
ADMIN_PASSWORD = "admin123"
MODERATOR_LOGIN = "moderator"
MODERATOR_PASSWORD = "moder123"

ROLE_OBSERVER = "Наблюдатель"
ROLE_MODERATOR = "Модератор"
ROLE_ADMIN = "Админ"

# ───────────── Аватарки: папка и ограничения на загрузку ─────────────
USERS_HEADER = ["Login", "Password", "Avatar", "Role"]
AVATAR_DIR = os.path.join("static", "avatars")   # файлы складываются сюда и раздаются как /static/avatars/...
AVATAR_MAX_BYTES = 5 * 1024 * 1024               # не больше 5 МБ
AVATAR_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

os.makedirs(AVATAR_DIR, exist_ok=True)


# CSV-файлы создаются автоматически при первом запуске.
# Если logs.csv остался от старой версии (колонки Login, Password) —
# дописываем недостающие колонки Avatar и Role, пользователей не теряем.
def init_users_file():
    if not os.path.exists(FILE_NAME):
        with open(FILE_NAME, mode="w", encoding="utf-8", newline="") as file:
            csv.writer(file).writerow(USERS_HEADER)
        return
    with open(FILE_NAME, encoding="utf-8", newline="") as file:
        rows = list(csv.reader(file))
    if rows and rows[0][:len(USERS_HEADER)] == USERS_HEADER:
        return  # уже новый формат
    with open(FILE_NAME, mode="w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(USERS_HEADER)
        for row in rows[1:]:
            row = (row + ["", ""])[:4]  # старым строкам добавляем пустые Avatar/Role
            writer.writerow(row)


init_users_file()

if not os.path.exists(MSGS_FILE):
    with open(MSGS_FILE, mode="w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerow(["sender", "receiver", "text", "is_deleted_by_sender", "is_deleted_by_receiver"])

# Новости: id, заголовок, текст, автор, дата создания, дата и автор правки.
# Писать новости может только админ, редактировать — модератор и админ.
NEWS_HEADER = ["id", "title", "text", "author", "created_at", "updated_at", "updated_by"]

if not os.path.exists(NEWS_FILE):
    with open(NEWS_FILE, mode="w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerow(NEWS_HEADER)


def now_str() -> str:
    return datetime.now().strftime("%d.%m.%Y %H:%M")


def load_news():
    """Все новости, свежие сверху."""
    with open(NEWS_FILE, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    return sorted(rows, key=lambda r: int(r["id"]), reverse=True)


def get_news(news_id: int):
    """Одна новость по id или None."""
    with open(NEWS_FILE, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if int(row["id"]) == news_id:
                return row
    return None


def next_news_id() -> int:
    with open(NEWS_FILE, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    return max((int(r["id"]) for r in rows), default=0) + 1


def save_news_row(new_row: list, news_id: int | None = None):
    """Добавляет новость (news_id=None) или обновляет существующую по id."""
    with open(NEWS_FILE, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    if news_id is None:
        rows.append(dict(zip(fieldnames, new_row)))
    else:
        for row in rows:
            if int(row["id"]) == news_id:
                row.update(dict(zip(fieldnames, new_row)))

    with open(NEWS_FILE, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def hash_password(password: str) -> str:
    return hashlib.sha256(f"{SECRET_SALT1}{password}{SECRET_SALT2}".encode()).hexdigest()


def get_user(username: str):
    """Все данные пользователя или None: хэш пароля, аватарка, роль."""
    with open(FILE_NAME, encoding="utf-8", newline="") as file:
        for row in csv.DictReader(file):
            if row.get("Login") == username:
                return {
                    "password": row.get("Password"),
                    "avatar": (row.get("Avatar") or "").strip(),
                    "role": (row.get("Role") or "").strip() or ROLE_OBSERVER,
                }
    return None


def find_user_hash(username: str):
    """Хэш пароля пользователя или None, если пользователя нет."""
    user = get_user(username)
    return user["password"] if user else None


def save_avatar(username: str, upload: UploadFile | None):
    """Сохраняет аватарку в static/avatars и возвращает имя файла.

    None — если файла нет, это не картинка или он больше 5 МБ."""
    if upload is None or not upload.filename:
        return None
    ext = os.path.splitext(upload.filename)[1].lower()
    if ext not in AVATAR_EXTENSIONS:
        return None
    content = upload.file.read()
    if not content or len(content) > AVATAR_MAX_BYTES:
        return None
    # имя файла: логин (очищенный от лишних символов) + случайный суффикс,
    # чтобы аватарки разных пользователей не затирали друг друга
    safe_name = re.sub(r"[^\w\-]+", "_", username).strip("_") or "user"
    name = f"{safe_name}_{secrets.token_hex(4)}{ext}"
    with open(os.path.join(AVATAR_DIR, name), "wb") as f:
        f.write(content)
    return name


# ───────────── Сессии: живут в памяти сервера, в браузер уходит только sid в URL ─────────────
SESSIONS: dict[str, dict] = {}  # sid -> {"user", "theme", "expires"}


def create_session(username: str) -> str:
    sid = secrets.token_urlsafe(16)
    SESSIONS[sid] = {"user": username, "theme": "light", "expires": time.time() + SESSION_LIFETIME}
    return sid


async def get_session(request: Request):
    """sid берём из URL (?sid=) или из скрытого поля формы."""
    sid = request.query_params.get("sid")
    if not sid and request.method == "POST":
        form = await request.form()
        sid = form.get("sid")
    d = SESSIONS.get(sid) if sid else None
    if not d or time.time() > d["expires"]:
        return {"sid": None, "user": None, "theme": "light"}
    return {"sid": sid, "user": d["user"], "theme": d["theme"]}


@app.get("/", response_class=HTMLResponse)
def main_page(request: Request):
    # Новости видны и без входа — только чтение, без кнопок редактирования
    return templates.TemplateResponse(request=request, name="based_main.html",
                                      context={"news": load_news()})


@app.get("/main", response_class=HTMLResponse)
def home_page(request: Request, with_user: str | None = None, sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    user = get_user(sess["user"]) or {}
    return templates.TemplateResponse(
        request=request,
        name="main.html",
        context={
            "username": sess["user"],
            "password_hash": user.get("password"),       # посмотреть свой пароль (хэш)
            "avatar": user.get("avatar", ""),            # файл аватарки в /static/avatars/
            "role": user.get("role", ROLE_OBSERVER),     # Наблюдатель / Модератор / Админ
            "news": load_news(),                         # новости сайта (свежие сверху)
            "chats": chat_list(sess["user"]),
            "with_user": with_user,
            "history": chat_history(sess["user"], with_user) if with_user else [],
            "sid": sess["sid"],
            "theme": sess["theme"],
        }
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, sess=Depends(get_session)):
    if sess["user"]:
        return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)
    return templates.TemplateResponse(request=request, name="login.html")


@app.post("/login")
def login(request: Request, password: str = Form(...), username: str = Form(...)):
    username = username.strip()  # случайный пробел в логине не должен мешать входу
    # Служебные аккаунты: admin/admin123 и moderator/moder123.
    # Если такого пользователя ещё нет — создаём сразу с нужной ролью.
    # Если логин уже занят (например, вы сами зарегистрировали «admin»
    # с другим паролем) — служебная пара всё равно срабатывает:
    # пароль и роль этого аккаунта приводятся к служебным.
    special_roles = {
        (ADMIN_LOGIN, ADMIN_PASSWORD): ROLE_ADMIN,
        (MODERATOR_LOGIN, MODERATOR_PASSWORD): ROLE_MODERATOR,
    }
    if (username, password) in special_roles:
        role = special_roles[(username, password)]
        stored_hash = find_user_hash(username)
        if stored_hash is None:
            with open(FILE_NAME, mode="a", encoding="utf-8", newline="") as file:
                csv.writer(file).writerow([username, hash_password(password), "", role])
        elif stored_hash != hash_password(password) or get_user(username)["role"] != role:
            update_user_fields(username, {"Password": hash_password(password), "Role": role})

    stored_hash = find_user_hash(username)
    if stored_hash is None:
        return templates.TemplateResponse(request=request, name="login_nouser.html")
    if stored_hash != hash_password(password):
        return templates.TemplateResponse(request=request, name="login_wrong_password.html")

    sid = create_session(username)
    return RedirectResponse(url=f"/main?sid={sid}", status_code=303)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, msg: str | None = None):
    return templates.TemplateResponse(request=request, name="register.html", context={"msg": msg})


@app.post("/register")
def register(request: Request, password: str = Form(...), username: str = Form(...),
             avatar: UploadFile | None = File(None)):
    if find_user_hash(username) is not None:
        return templates.TemplateResponse(request=request, name="user_exist.html")

    avatar_name = save_avatar(username, avatar)
    if avatar_name is None:  # аватарка обязательна
        return templates.TemplateResponse(request=request, name="register_avatar_error.html")

    with open(FILE_NAME, mode="a", encoding="utf-8", newline="") as file:
        csv.writer(file).writerow([username, hash_password(password), avatar_name, ""])

    sid = create_session(username)
    return RedirectResponse(url=f"/main?sid={sid}", status_code=303)


@app.get("/logout")
def logout(sid: str | None = None):
    SESSIONS.pop(sid, None)
    return RedirectResponse(url="/login", status_code=303)


@app.get("/404", response_class=HTMLResponse)
def _404_page(request: Request):
    return templates.TemplateResponse(request=request, name="404.html")






# ═══════════ Приватные чаты: без WebSocket, без JS, без куки ═══════════
# Вместо сокетов — обычные HTML-формы и редиректы (POST-Redirect-GET).

def chat_list(username):
    """Все диалоги пользователя: у каждого последнее сообщение, свежие сверху."""
    chats = {}
    with open(MSGS_FILE, encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
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
    """История диалога с собеседником (удалённые у себя не показываем)."""
    history = []
    with open(MSGS_FILE, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            mine = row["sender"] == username and row["receiver"] == with_user and row["is_deleted_by_sender"] != "True"
            theirs = row["sender"] == with_user and row["receiver"] == username and row["is_deleted_by_receiver"] != "True"
            if mine or theirs:
                history.append({"sender": row["sender"], "text": row["text"]})
    return history


# Отправка сообщения: форма -> сохраняем в CSV -> возврат в диалог
@app.post("/send")
def send_message(text: str = Form(""), receiver: str = Form(...), sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)

    text = text.strip()
    back = f"/main?with_user={quote(receiver)}&sid={sess['sid']}"
    if not text:  # пустое сообщение просто не отправляем
        return RedirectResponse(url=back, status_code=303)

    with open(MSGS_FILE, mode="a", encoding="utf-8", newline="") as f:
        csv.writer(f).writerow([sess["user"], receiver, text, "False", "False"])
    return RedirectResponse(url=back, status_code=303)


# Удаление чата: помечаем сообщения удалёнными только у себя
@app.post("/delete-chat")
def delete_chat(with_user: str = Form(...), sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    username = sess["user"]

    with open(MSGS_FILE, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    for row in rows:
        if row["sender"] == username and row["receiver"] == with_user:
            row["is_deleted_by_sender"] = "True"
        elif row["sender"] == with_user and row["receiver"] == username:
            row["is_deleted_by_receiver"] = "True"

    with open(MSGS_FILE, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)


# Смена темы без JS и без куки: тема хранится в серверной сессии
@app.get("/theme")
def toggle_theme(next: str = "/main", sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    d = SESSIONS[sess["sid"]]
    d["theme"] = "dark" if d["theme"] == "light" else "light"
    return RedirectResponse(url=next, status_code=303)


# ═══════════ Страницы ролей: модератор и админ ═══════════
# На каждой странице можно ввести служебные логин/пароль и получить роль —
# тогда статус на главной сменится с «Наблюдатель» на «Модератор»/«Админ».
# Роль сохраняется в logs.csv, поэтому переживает выход из аккаунта.
# Админ видит обе страницы, модератор — только свою.

ROLE_PAGES = {
    "moderator": {
        "template": "moderator.html",
        "url": "/moderator",
        "role": ROLE_MODERATOR,
        "login": MODERATOR_LOGIN,
        "password": MODERATOR_PASSWORD,
    },
    "admin": {
        "template": "admin.html",
        "url": "/admin",
        "role": ROLE_ADMIN,
        "login": ADMIN_LOGIN,
        "password": ADMIN_PASSWORD,
    },
}


def update_user_fields(username: str, fields: dict):
    """Меняет указанные колонки пользователя (Role, Password) — перезаписываем logs.csv."""
    with open(FILE_NAME, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)
    for row in rows:
        if row.get("Login") == username:
            row.update(fields)
    with open(FILE_NAME, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def update_role(username: str, new_role: str):
    """Меняет роль пользователя."""
    update_user_fields(username, {"Role": new_role})


def all_users():
    """Все зарегистрированные пользователи — для панели админа."""
    with open(FILE_NAME, encoding="utf-8", newline="") as f:
        return [
            {
                "login": row.get("Login"),
                "role": (row.get("Role") or "").strip() or ROLE_OBSERVER,
                "avatar": (row.get("Avatar") or "").strip(),
            }
            for row in csv.DictReader(f)
        ]


def recent_messages(limit: int = 30):
    """Последние сообщения чатов — для панели модератора (свежие сверху)."""
    with open(MSGS_FILE, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    return rows[-limit:][::-1]


def role_page_view(request: Request, sess: dict, key: str, error: str | None = None):
    """Рендер страницы роли: форма ввода пароля или панель, если роль уже выдана."""
    p = ROLE_PAGES[key]
    user = get_user(sess["user"]) or {}
    my_role = user.get("role", ROLE_OBSERVER)
    granted = my_role == ROLE_ADMIN or my_role == p["role"]  # админ проходит везде
    context = {
        "username": sess["user"],
        "my_role": my_role,
        "granted": granted,
        "error": error,
        "sid": sess["sid"],
        "theme": sess["theme"],
    }
    if granted:
        if key == "admin":
            context["users"] = all_users()# админ видит список пользователей
        else:
            context["messages"] = recent_messages()  # модератор видит последние сообщения
    return templates.TemplateResponse(request=request, name=p["template"], context=context)


def role_page_submit(request: Request, sess: dict, key: str, login: str, password: str):
    """Проверяем служебный логин/пароль и выдаём роль текущему пользователю."""
    p = ROLE_PAGES[key]
    if login.strip() == p["login"] and password == p["password"]:
        update_role(sess["user"], p["role"])
        return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)
    return role_page_view(request, sess, key, error="Неверный логин или пароль.")


@app.get("/moderator", response_class=HTMLResponse)
def moderator_page(request: Request, sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    return role_page_view(request, sess, "moderator")


@app.post("/moderator")
def moderator_submit(request: Request, login: str = Form(...), password: str = Form(...),
                     sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    return role_page_submit(request, sess, "moderator", login, password)


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    return role_page_view(request, sess, "admin")


@app.post("/admin")
def admin_submit(request: Request, login: str = Form(...), password: str = Form(...),
                 sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    return role_page_submit(request, sess, "admin", login, password)


# ═══════════ Новости: права зависят от роли ═══════════
#   Наблюдатель — только читает.
#   Модератор  — редактирует любые новости (кнопки «Редактировать» на главной).
#   Админ      — пишет новые («Написать новость») и редактирует любые.

def news_form_context(request: Request, sess: dict, is_edit: bool, news_id: int | None,
                      title: str, text: str, error: str | None):
    """Общий рендер формы новости: и для создания, и для правки."""
    post_url = f"/news/new?sid={sess['sid']}" if not is_edit else f"/news/{news_id}/edit?sid={sess['sid']}"
    return templates.TemplateResponse(
        request=request,
        name="news_form.html",
        context={
            "is_edit": is_edit,
            "title_value": title,
            "text_value": text,
            "error": error,
            "post_url": post_url,
            "sid": sess["sid"],
            "theme": sess["theme"],
        }
    )


@app.get("/news/new", response_class=HTMLResponse)
def news_new_page(request: Request, sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    user = get_user(sess["user"]) or {}
    if user.get("role") != ROLE_ADMIN:  # писать новости может только админ
        return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)
    return news_form_context(request, sess, is_edit=False, news_id=None, title="", text="", error=None)


@app.post("/news/new")
def news_create(request: Request, title: str = Form(""), text: str = Form(""), sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    user = get_user(sess["user"]) or {}
    if user.get("role") != ROLE_ADMIN:  # на случай прямого POST мимо формы
        return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)

    title, text = title.strip(), text.strip()
    if not title or not text:
        return news_form_context(request, sess, is_edit=False, news_id=None,
                                 title=title, text=text, error="Заполните заголовок и текст новости.")

    save_news_row([next_news_id(), title, text, sess["user"], now_str(), "", ""])
    return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)


@app.get("/news/{news_id}/edit", response_class=HTMLResponse)
def news_edit_page(news_id: int, request: Request, sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    user = get_user(sess["user"]) or {}
    if user.get("role") not in (ROLE_MODERATOR, ROLE_ADMIN):  # редактировать — модератор и админ
        return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)

    news = get_news(news_id)
    if news is None:  # нет такой новости (например, устаревшая ссылка)
        return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)
    return news_form_context(request, sess, is_edit=True, news_id=news_id,
                             title=news["title"], text=news["text"], error=None)


@app.post("/news/{news_id}/edit")
def news_update(news_id: int, request: Request, title: str = Form(""), text: str = Form(""),
                sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    user = get_user(sess["user"]) or {}
    if user.get("role") not in (ROLE_MODERATOR, ROLE_ADMIN):
        return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)

    news = get_news(news_id)
    if news is None:
        return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)

    title, text = title.strip(), text.strip()
    if not title or not text:
        return news_form_context(request, sess, is_edit=True, news_id=news_id,
                                 title=title, text=text, error="Заполните заголовок и текст новости.")

    # author и created_at не трогаем — фиксируем, кто и когда правил последним
    save_news_row([news["id"], title, text, news["author"], news["created_at"], now_str(), sess["user"]],
                  news_id=news_id)
    return RedirectResponse(url=f"/main?sid={sess['sid']}", status_code=303)