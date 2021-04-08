from typing import Optional
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="Crypto/static"), name="static")
templates = Jinja2Templates(directory="Crypto/templates")