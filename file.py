"""python -m uvicorn file:app --reload"""
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount('/static', StaticFiles(directory='static'), name='static')
app.mount('/sources', StaticFiles(directory='sources'), name='sources')
templates = Jinja2Templates(directory='templates')


try: 
    @app.get('/', response_class=HTMLResponse)
    @app.get('/home', response_class=HTMLResponse)
    def home_page(request: Request):
        return templates.TemplateResponse(request=request, name = 'home.html')
        
    @app.get('/login', response_class=HTMLResponse)
    def login_page(request: Request):
        return templates.TemplateResponse(request=request, name = 'login.html')

    @app.get('/main', response_class=HTMLResponse)
    def main_page(request: Request):
        return templates.TemplateResponse(request=request, name = 'main.html')

    @app.get('/register', response_class=HTMLResponse)
    def register_page(request: Request):
        return templates.TemplateResponse(request=request, name = 'register.html')
except:
    @app.get('/404', response_class=HTMLResponse)
    def error_page(request: Request):
        return templates.TemplateResponse(request=request, name = '404.html')

