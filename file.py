'python -m uvicorn file:app --reload'
from fastapi import FastAPI, Form, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from urllib.parse import quote
import csv
import os
import secrets
import hashlib
import time

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

FILE_NAME = "logs.csv"       # пользователи: Login, Password (хэш sha256)
MSGS_FILE = "messages.csv"   # сообщения чата
SESSION_LIFETIME = 30 * 60   # сессия живёт 30 минут

SECRET_SALT1 = "PAROL_"
SECRET_SALT2 = "_SECURITY"

# CSV-файлы создаются автоматически при первом запуске
if not os.path.exists(FILE_NAME):
    with open(FILE_NAME, mode="w", encoding="utf-8", newline="") as file:
        csv.writer(file).writerow(["Login", "Password"])

if not os.path.exists(MSGS_FILE):
    with open(MSGS_FILE, mode="w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerow(["sender", "receiver", "text", "is_deleted_by_sender", "is_deleted_by_receiver"])


def hash_password(password: str) -> str:
    return hashlib.sha256(f"{SECRET_SALT1}{password}{SECRET_SALT2}".encode()).hexdigest()


def find_user_hash(username: str):
    """Хэш пароля пользователя или None, если пользователя нет."""
    with open(FILE_NAME, mode="r", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            if row.get("Login") == username:
                return row.get("Password")
    return None


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
    return templates.TemplateResponse(request=request, name="based_main.html")


@app.get("/main", response_class=HTMLResponse)
def home_page(request: Request, with_user: str | None = None, sess=Depends(get_session)):
    if not sess["user"]:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="main.html",
        context={
            "username": sess["user"],
            "password_hash": find_user_hash(sess["user"]),  # посмотреть свой пароль (хэш)
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
def register(request: Request, password: str = Form(...), username: str = Form(...)):
    if find_user_hash(username) is not None:
        return templates.TemplateResponse(request=request, name="user_exist.html")

    with open(FILE_NAME, mode="a", encoding="utf-8", newline="") as file:
        csv.writer(file).writerow([username, hash_password(password)])

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