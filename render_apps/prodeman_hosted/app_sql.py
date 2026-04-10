from __future__ import annotations

import csv
import io
import json
import os
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

USERS_FILE = DATA_DIR / "usuarios.json"
SAMPLES_FILE = DATA_DIR / "muestras.json"
HISTORY_FILE = DATA_DIR / "historial.json"
LABS_FILE = DATA_DIR / "config_labs.json"
RESP_FILE = DATA_DIR / "config_responsables.json"

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "cambia-esta-clave")
app.config["SESSION_COOKIE_NAME"] = "suite_session"


def read_json(path: Path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def load_users():
    return read_json(USERS_FILE, [])


def save_users(rows):
    write_json(USERS_FILE, rows)


def load_samples():
    return read_json(SAMPLES_FILE, [])


def save_samples(rows):
    write_json(SAMPLES_FILE, rows)


def load_history():
    return read_json(HISTORY_FILE, [])


def save_history(rows):
    write_json(HISTORY_FILE, rows)


def load_labs():
    return read_json(LABS_FILE, [])


def save_labs(rows):
    write_json(LABS_FILE, rows)


def load_responsables():
    return read_json(RESP_FILE, [])


def save_responsables(rows):
    write_json(RESP_FILE, rows)


def session_es_admin_prodeman():
    return session.get("rol") in {"admin", "superadmin"}


def registrar_evento(usuario, accion, id_muestra=None):
    rows = load_history()
    rows.insert(
        0,
        {
            "id": len(rows) + 1,
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "usuario": usuario,
            "accion": accion,
            "id_muestra": id_muestra,
        },
    )
    save_history(rows)


def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return next((u for u in load_users() if u.get("id") == uid and u.get("activo", 1)), None)


def get_password_maps():
    destino = {}
    envio = {}
    for user in load_users():
        lab = (user.get("laboratorio") or "").upper().strip()
        plain = user.get("demo_password")
        if lab and plain:
            destino[lab] = plain
            envio[lab] = plain
    destino.setdefault("ALERGENOS", "alergenos123")
    envio.setdefault("ALERGENOS", "alergenos123")
    return destino, envio, "admin123"


def visible_samples():
    rows = load_samples()
    if session.get("rol") == "admin":
        return rows
    lab = (session.get("lab") or "").upper().strip()
    visible = []
    for row in rows:
        envio = (row.get("labenvio") or "").upper()
        destino = (row.get("labdestino") or "").upper()
        if envio == lab or destino == lab:
            visible.append(row)
    return visible


@app.route("/datos", methods=["GET"])
def obtener_datos():
    if "usuario" not in session:
        return jsonify([])
    return jsonify(visible_samples())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_input = (request.form.get("usuario") or request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = next(
            (
                u for u in load_users()
                if u.get("activo", 1)
                and login_input in {
                    (u.get("correo") or "").strip().lower(),
                    (u.get("email") or "").strip().lower(),
                    (u.get("usuario") or "").strip().lower(),
                }
            ),
            None,
        )
        if user:
            stored = user.get("password_hash")
            plain = user.get("demo_password") or ""
            valid = (stored and check_password_hash(stored, password)) or (plain and password == plain)
            if valid:
                session["user_id"] = user["id"]
                session["usuario"] = user.get("correo") or user.get("email") or user.get("usuario")
                session["rol"] = user.get("rol_prodeman") or user.get("rol") or "visor"
                session["lab"] = user.get("laboratorio")
                registrar_evento(session["usuario"], "Inicio de sesion")
                return redirect(url_for("index"))
        return render_template("login.html", error="Credenciales invalidas")
    return render_template("login.html")


@app.route("/admin")
def admin_panel():
    if "usuario" not in session:
        return redirect(url_for("login"))
    if not session_es_admin_prodeman():
        return redirect(url_for("index"))
    usuarios = []
    for u in load_users():
        usuarios.append(
            {
                "id": u["id"],
                "nombre": u.get("nombre"),
                "apellido": u.get("apellido"),
                "correo": u.get("correo") or u.get("email"),
                "rol": u.get("rol_prodeman") or u.get("rol"),
                "laboratorio": u.get("laboratorio"),
                "activo": u.get("activo", 1),
            }
        )
    return render_template("admin.html", labs=load_labs(), responsables=load_responsables(), usuarios=usuarios)


@app.route("/admin/usuarios", methods=["POST"])
def admin_usuarios_api():
    if "usuario" not in session or not session_es_admin_prodeman():
        return "No autorizado", 403
    data = request.get_json()
    accion = data.get("accion")
    users = load_users()
    if accion == "guardar":
        for user in users:
            if user.get("id") == data.get("id"):
                user["nombre"] = data["nombre"]
                user["apellido"] = data["apellido"]
                user["correo"] = data["correo"]
                user["email"] = data["correo"]
                user["rol_prodeman"] = data["rol"]
                user["rol"] = data["rol"]
                user["laboratorio"] = data["laboratorio"] or None
                user["activo"] = 1 if data["activo"] else 0
                break
    elif accion == "eliminar":
        users = [u for u in users if u.get("id") != data.get("id")]
    save_users(users)
    return jsonify({"ok": True})


@app.route("/logout")
def logout():
    usuario = session.get("usuario")
    session.clear()
    if usuario:
        registrar_evento(usuario, "Cierre de sesion")
    return redirect(url_for("login"))


@app.route("/")
def index():
    if "usuario" not in session:
        return redirect(url_for("login"))
    labs = load_labs()
    labs_envio = [x["codigo"] for x in labs if x.get("tipo") in ("envio", "ambos")]
    labs_destino = [x["codigo"] for x in labs if x.get("tipo") in ("destino", "ambos")]
    responsables = [x["nombre"] for x in load_responsables()]
    return render_template("pantalla_generalsql.html", labs_envio=labs_envio, labs_destino=labs_destino, responsables=responsables)


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form.get("nombre")
        apellido = request.form.get("apellido")
        correo = request.form.get("correo")
        password = request.form.get("password")
        if not (nombre and apellido and correo and password):
            return render_template("registro.html", error="Todos los campos son obligatorios")
        users = load_users()
        if any((u.get("correo") or u.get("email")) == correo for u in users):
            return render_template("registro.html", error="Ya existe un usuario con ese correo")
        users.append(
            {
                "id": max((u.get("id", 0) for u in users), default=0) + 1,
                "nombre": nombre,
                "apellido": apellido,
                "correo": correo,
                "email": correo,
                "usuario": correo.split("@")[0],
                "password_hash": generate_password_hash(password),
                "demo_password": password,
                "rol_prodeman": "visor",
                "rol": "visor",
                "laboratorio": None,
                "activo": 1,
            }
        )
        save_users(users)
        registrar_evento(correo, "Registro de nuevo usuario")
        return redirect(url_for("login"))
    return render_template("registro.html")


@app.route("/datos", methods=["POST"])
def guardar_muestra():
    nueva = request.json or {}
    samples = load_samples()
    is_new = not nueva.get("id")
    if is_new:
        nueva["id"] = str(uuid.uuid4())
    existing = next((s for s in samples if s.get("id") == nueva["id"]), None)
    if existing:
        existing.update(nueva)
    else:
        samples.append(
            {
                "id": nueva["id"],
                "labenvio": nueva.get("labenvio"),
                "labdestino": nueva.get("labdestino"),
                "semana": nueva.get("semana"),
                "fecha": nueva.get("fecha"),
                "lote": nueva.get("lote"),
                "responsable": nueva.get("responsable"),
                "estado": nueva.get("estado", "Pendiente"),
                "comentario": nueva.get("comentario", ""),
            }
        )
    save_samples(samples)
    usuario = session.get("usuario", nueva.get("labenvio", "Desconocido"))
    accion = "Alta de muestra" if is_new else "Modificación de muestra"
    registrar_evento(usuario, f"{accion} - Lote {nueva.get('lote', '')}", nueva["id"])
    return jsonify({"ok": True, "id": nueva["id"]})


@app.route("/actualizar_estado", methods=["POST"])
def actualizar_estado():
    payload = request.json or {}
    mid = payload.get("id")
    estado = payload.get("estado")
    comentario = payload.get("comentario", "")
    samples = load_samples()
    for sample in samples:
        if sample.get("id") == mid:
            sample["estado"] = estado
            sample["comentario"] = comentario
            break
    save_samples(samples)
    usuario = session.get("usuario", "Laboratorio destino")
    if (estado or "").lower() == "aceptado":
        registrar_evento(usuario, f"Aceptación de muestra ID {mid}", mid)
    elif (estado or "").lower() == "rechazado":
        registrar_evento(usuario, f"Rechazo de muestra ID {mid} - Motivo: {comentario}", mid)
    return jsonify({"ok": True})


@app.route("/eliminar_muestra/<mid>", methods=["DELETE"])
def eliminar_muestra(mid):
    samples = [s for s in load_samples() if s.get("id") != mid]
    save_samples(samples)
    usuario = session.get("usuario", "Admin")
    registrar_evento(usuario, f"Eliminación de muestra ID {mid}", mid)
    return jsonify({"ok": True})


@app.route("/exportar_filtrado", methods=["POST"])
def exportar_filtrado():
    data = request.json or []
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["labenvio", "labdestino", "semana", "fecha", "lote", "responsable", "estado", "comentario"])
    for row in data:
        writer.writerow([row.get("labenvio"), row.get("labdestino"), row.get("semana"), row.get("fecha"), row.get("lote"), row.get("responsable"), row.get("estado"), row.get("comentario")])
    buf = io.BytesIO(output.getvalue().encode("utf-8"))
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="muestras_sql.csv", mimetype="text/csv")


@app.route("/historial")
def ver_historial():
    return jsonify(load_history())


@app.route("/ver_historial")
def ver_historial_html():
    if "usuario" not in session:
        return redirect(url_for("login"))
    return render_template("historial.html")


@app.route("/admin/labs", methods=["POST"])
def admin_labs_api():
    if "usuario" not in session or not session_es_admin_prodeman():
        return jsonify({"ok": False, "error": "No autorizado"}), 403
    data = request.get_json()
    accion = data.get("accion")
    labs = load_labs()
    if accion == "crear":
        labs.append({"codigo": data.get("codigo") or f"LAB{uuid.uuid4().hex[:5].upper()}", "nombre": data.get("nombre") or "Nuevo laboratorio", "tipo": data.get("tipo") or "ambos"})
    elif accion == "guardar":
        for lab in labs:
            if lab["codigo"] == data["codigo"]:
                lab["codigo"] = data["codigo_nuevo"]
                lab["nombre"] = data["nombre"]
                lab["tipo"] = data["tipo"]
                break
    elif accion == "eliminar":
        labs = [l for l in labs if l["codigo"] != data["codigo"]]
    save_labs(labs)
    return jsonify({"ok": True})


@app.route("/admin/responsables", methods=["POST"])
def admin_responsables_api():
    if "usuario" not in session or not session_es_admin_prodeman():
        return jsonify({"ok": False, "error": "No autorizado"}), 403
    data = request.get_json()
    accion = data.get("accion")
    responsables = load_responsables()
    if accion == "crear":
        responsables.append({"id": max((r.get("id", 0) for r in responsables), default=0) + 1, "nombre": data.get("nombre") or f"Responsable {uuid.uuid4().hex[:4]}"})
    elif accion == "guardar":
        for item in responsables:
            if item["id"] == data["id"]:
                item["nombre"] = data["nombre"]
                break
    elif accion == "eliminar":
        responsables = [r for r in responsables if r["id"] != data["id"]]
    save_responsables(responsables)
    return jsonify({"ok": True})


@app.route("/admin/cambiar_pass", methods=["POST"])
def admin_cambiar_pass():
    if "usuario" not in session or not session_es_admin_prodeman():
        return "No autorizado", 403
    data = request.get_json()
    users = load_users()
    for user in users:
        if user["id"] == data.get("id"):
            user["password_hash"] = generate_password_hash(data.get("password"))
            user["demo_password"] = data.get("password")
            break
    save_users(users)
    return jsonify({"ok": True})


@app.route("/passwords")
def obtener_passwords():
    destino, envio, _ = get_password_maps()
    return jsonify({"ok": True, "destino": destino, "envio": envio})


@app.route("/password_admin")
def obtener_password_admin():
    _, _, admin = get_password_maps()
    return jsonify({"ok": True, "admin": admin})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5002"))
    debug = os.getenv("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host="0.0.0.0", port=port, debug=debug)
