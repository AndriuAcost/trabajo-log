from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import os
import bcrypt
import hashlib
import base64

app = Flask(__name__)
app.secret_key = 'clave-secreta-supersegura'

DB_NAME = 'app.db'

# Parámetros para ofuscación reversible
RUT_SALT = b'mi_salt_superseguro'
RUT_PEPPER = b'mi_pepper_supersecreto'

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def ofuscar_rut(rut: str) -> str:
    rut_bytes = rut.encode('utf-8')
    salted = rut_bytes + RUT_SALT
    xored = xor_bytes(salted, RUT_PEPPER)
    return base64.urlsafe_b64encode(xored).decode('utf-8')

def revertir_rut(ofuscado: str) -> str:
    xored = base64.urlsafe_b64decode(ofuscado.encode('utf-8'))
    salted = xor_bytes(xored, RUT_PEPPER)
    rut_bytes = salted[:-len(RUT_SALT)]
    return rut_bytes.decode('utf-8')

def hash_religion(religion: str) -> str:
    return hashlib.sha256(religion.encode('utf-8')).hexdigest()

def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE personas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rut TEXT NOT NULL,
                nombre TEXT NOT NULL,
                apellido TEXT NOT NULL,
                religion TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                accion TEXT NOT NULL,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['contrasena'].encode('utf-8')
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM usuarios WHERE email=?', (email,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            session['email'] = email
            return redirect(url_for('index'))
        else:
            flash('Email o contraseña incorrectos', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['contrasena'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('INSERT INTO usuarios (email, password) VALUES (?, ?)', (email, hashed.decode('utf-8')))
            conn.commit()
            conn.close()
            flash('Usuario creado, ya puedes iniciar sesión', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('El email ya existe', 'error')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM logs ORDER BY fecha DESC')
    logs = c.fetchall()
    conn.close()
    return render_template('index.html', email=session['email'], logs=logs)

@app.route('/registrar', methods=['POST'])
@login_required
def registrar():
    accion = request.form.get('accion')
    if accion:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO logs (accion) VALUES (?)', (accion,))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

@app.route('/personas')
@login_required
def listar_personas():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM personas')
    personas = c.fetchall()
    conn.close()
    personas_desofuscadas = []
    for p in personas:
        personas_desofuscadas.append({
            'id': p['id'],
            'rut': revertir_rut(p['rut']),
            'nombre': p['nombre'],
            'apellido': p['apellido'],
            'religion': p['religion'],  # mostramos el hash como está
        })
    return render_template('personas.html', personas=personas_desofuscadas)

@app.route('/personas/nuevo', methods=['GET', 'POST'])
@login_required
def crear_persona():
    if request.method == 'POST':
        rut = request.form['rut']
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        religion = request.form['religion']
        rut_ofuscado = ofuscar_rut(rut)
        religion_hashed = hash_religion(religion)
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO personas (rut, nombre, apellido, religion) VALUES (?, ?, ?, ?)',
                  (rut_ofuscado, nombre, apellido, religion_hashed))
        conn.commit()
        conn.close()
        return redirect(url_for('listar_personas'))
    return render_template('crear_persona.html')

@app.route('/personas/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_persona(id):
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        rut = request.form['rut']
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        religion = request.form['religion']
        rut_ofuscado = ofuscar_rut(rut)
        religion_hashed = hash_religion(religion)
        c.execute('UPDATE personas SET rut=?, nombre=?, apellido=?, religion=? WHERE id=?',
                  (rut_ofuscado, nombre, apellido, religion_hashed, id))
        conn.commit()
        conn.close()
        return redirect(url_for('listar_personas'))
    else:
        c.execute('SELECT * FROM personas WHERE id=?', (id,))
        persona = c.fetchone()
        conn.close()
        if persona:
            persona_dict = dict(persona)
            persona_dict['rut'] = revertir_rut(persona_dict['rut'])
            return render_template('editar_persona.html', persona=persona_dict)
        else:
            return 'Persona no encontrada', 404

@app.route('/personas/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_persona(id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM personas WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('listar_personas'))

if __name__ == '__main__':
    app.run(debug=True)
