import os
import sqlite3

from fastapi import Depends, FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from .seguridad import crear_token, usuario_actual

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://tienda-segura.example"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]


@app.get("/productos/buscar")
def buscar(q: str):
    con = sqlite3.connect("tienda.db")
    filas = con.execute("SELECT nombre, precio FROM productos WHERE nombre LIKE ?", (f"%{q}%",)).fetchall()
    return filas


@app.post("/sesion")
def crear_sesion(response: Response, usuario=Depends(usuario_actual)):
    response.set_cookie("session_id", crear_token(usuario), httponly=True, secure=True, samesite="lax")
    return {"ok": True}
