"""python -m uvicorn main:app --reload"""
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount('/static', StaticFiles(directory='static'), name='static')
app.mount('/sources', StaticFiles(directory='sources'), name='sources')
templates = Jinja2Templates(directory='templates')

#для проверки туда ли пользователь зашел 
white_urls = ['/' , '/login' , '/logout', '/register']

@app.get('/', response_class=HTMLResponse)
def main_page(request: Request):
    return templates.TemplateResponse(request=request, name = 'home.html')