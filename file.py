"""python -m uvicorn file:app --reload"""
from fastapi import FastAPI, Form, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import csv
import os

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

white_urls = ["/", "/login", "/logout", "/register"]

FILE_NAME = 'logs.csv'

if not os.path.exists(FILE_NAME):
    with open(FILE_NAME, mode='w', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Login', 'Password'])


def get_coockie(request = Request):
    user_id = request.cookies.get('user-session')
    return user_id

@app.get("/", response_class=HTMLResponse)
def main_page(request: Request):
    return templates.TemplateResponse(request=request, name ="based_main.html")

@app.get("/home", response_class=HTMLResponse)
def home_page(request: Request, user_id: = Depends(get_coockie)):
    return templates.TemplateResponse(request=request, 
                                      name="home.html", 
                                      context={'username': 'Uzver', 
                                               'password_hash': 'asdadas'})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
def login(request: Request,
          password: str = Form(...), 
          username: str = Form(...) 
          ):
    print(request)
    print(username)
    print(password)
    with open(FILE_NAME, mode='a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, password])

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html")

@app.get("/404", response_class=HTMLResponse)
def _404_page(request: Request):
    return templates.TemplateResponse(request=request, name="404.html")
