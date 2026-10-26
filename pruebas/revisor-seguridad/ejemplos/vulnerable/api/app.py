import sqlite3

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OPENAI_API_KEY = "@@OPENAI@@"


@app.get("/productos/buscar")
def buscar(q: str):
    con = sqlite3.connect("tienda.db")
    filas = con.execute(f"SELECT nombre, precio FROM productos WHERE nombre LIKE '%{q}%'").fetchall()
    return filas


@app.post("/sesion")
def crear_sesion(response: Response):
    response.set_cookie("session_id", "valor-de-ejemplo")
    return {"ok": True}
