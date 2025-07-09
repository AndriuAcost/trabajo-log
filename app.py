from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import os
import bcrypt  # Para hash de contraseñas

app = Flask(__name__)
app.secret_key = 'clave-secreta-supersegura'

DB_NAME = 'app.db'

# Crear la base de datos y tablas si no existen
def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # Usuarios: id, usuario, password(hashed)
        c.execute('''
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        # Personas: id, nombre, email
        c.execute('''
            CREATE TABLE personas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                email TEXT NOT NULL
            )
        ''')
        # Logs: id, accion, fecha default actual
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

# Conexión a DB
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # para acceder con nombre de columnas
    return conn

# Decorador para rutas protegidas
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Ruta: login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['contrasena'].encode('utf-8')
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM usuarios WHERE usuario=?', (usuario,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            session['usuario'] = usuario
            return redirect(url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos', 'error')
    return render_template('login.html')

# Ruta: registro de nuevo usuario
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['contrasena'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('INSERT INTO usuarios (usuario, password) VALUES (?, ?)', (usuario, hashed.decode('utf-8')))
            conn.commit()
            conn.close()
            flash('Usuario creado, ya puedes iniciar sesión', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('El usuario ya existe', 'error')
    return render_template('register.html')

# Ruta: cerrar sesión
@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

# Página principal con listado de logs y bienvenida
@app.route('/')
@login_required
def index():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM logs ORDER BY fecha DESC')
    logs = c.fetchall()
    conn.close()
    return render_template('index.html', usuario=session['usuario'], logs=logs)

# Registrar acción en logs
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

# CRUD Personas

# Listar personas
@app.route('/personas')
@login_required
def listar_personas():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM personas')
    personas = c.fetchall()
    conn.close()
    return render_template('personas.html', personas=personas)

# Crear persona
@app.route('/personas/nuevo', methods=['GET', 'POST'])
@login_required
def crear_persona():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO personas (nombre, email) VALUES (?, ?)', (nombre, email))
        conn.commit()
        conn.close()
        return redirect(url_for('listar_personas'))
    return render_template('crear_persona.html')

# Editar persona
@app.route('/personas/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_persona(id):
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        c.execute('UPDATE personas SET nombre=?, email=? WHERE id=?', (nombre, email, id))
        conn.commit()
        conn.close()
        return redirect(url_for('listar_personas'))
    else:
        c.execute('SELECT * FROM personas WHERE id=?', (id,))
        persona = c.fetchone()
        conn.close()
        if persona:
            return render_template('editar_persona.html', persona=persona)
        else:
            return 'Persona no encontrada', 404

# Eliminar persona
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
