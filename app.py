import os
import sqlite3
import json
import time
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
import bcrypt
import pyotp
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "super-secret-key-fista"
DB_FILE = 'fista.db'
LOG_FILE = 'audit.log.jsonl'
BACKUP_DIR = 'backups'

if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

# Fernet key for backup encryption
BACKUP_KEY_FILE = 'backup.key'
if os.path.exists(BACKUP_KEY_FILE):
    with open(BACKUP_KEY_FILE, 'rb') as kf:
        BACKUP_KEY = kf.read()
else:
    BACKUP_KEY = Fernet.generate_key()
    with open(BACKUP_KEY_FILE, 'wb') as kf:
        kf.write(BACKUP_KEY)

fernet = Fernet(BACKUP_KEY)

ROLES_PERMISSIONS = {
    'ADMIN_IT': ['server_admin', 'site_admin', 'backup_admin', 'view_logs', 'manage_users', 'approve_access', 'revoke_access', 'review_access'],
    'COORDENACAO': ['approve_access', 'request_removal', 'view_audit_summary'],
    'PARCERIAS': ['edit_company_data'],
    'FINANCEIRO': ['edit_financial_data'],
    'MARKETING': ['edit_content'],
    'STAFF_OPERACIONAL': ['view_operational_data'],
    'VALIDADOR_EVENTO': ['validate_qr'],
    'BACKUP_OPERATOR': ['backup_create', 'backup_restore', 'backup_view_status']
}

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_FILE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def append_only_log(user, role, action, resource, old_value="", new_value="", result="success"):
    ip = request.remote_addr if request else "127.0.0.1"
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "user": user,
        "role": role,
        "action": action,
        "resource": resource,
        "old_value": old_value,
        "new_value": new_value,
        "ip": ip,
        "result": result
    }
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            mfa_secret TEXT,
            role TEXT,
            justification TEXT,
            approved_by TEXT,
            expiration_date TEXT,
            is_active INTEGER DEFAULT 1,
            revoked INTEGER DEFAULT 0
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            target_role TEXT,
            system TEXT,
            justification TEXT,
            requested_duration INTEGER,
            requested_by TEXT,
            status TEXT DEFAULT 'pendente',
            created_at TEXT,
            processed_at TEXT,
            processed_by TEXT
        )''')
        db.commit()

        # Seed initial users
        cursor = db.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            demo_users = [
                ('admin.it', 'PasswordForte123!', 'ADMIN_IT'),
                ('developer.it', 'Developer123!', 'ADMIN_IT'),
                ('operations.it', 'Operations123!', 'STAFF_OPERACIONAL'),
                ('coordenacao', 'Coordenacao123!', 'COORDENACAO'),
                ('backups.operator', 'Backups123!', 'BACKUP_OPERATOR')
            ]
            print("\n" + "="*50)
            print("CHAVES MFA PARA UTILIZADORES DEMO:")
            print("="*50)
            for username, password, role in demo_users:
                pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                mfa_secret = pyotp.random_base32()
                expiration = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")
                db.execute('''INSERT INTO users (username, password_hash, mfa_secret, role, justification, approved_by, expiration_date)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''', (username, pw_hash, mfa_secret, role, "Demo user setup", "system", expiration))
                print(f"User: {username}")
                print(f"Password: {password}")
                print(f"MFA Secret: {mfa_secret}")
                print("-" * 30)
            db.commit()
            print("="*50 + "\n")

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # Verificação em tempo real do estado da conta (Revogação Imediata)
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        if user:
            is_valid, msg = check_user_status(user)
            if not is_valid:
                session.clear()
                flash(f"A sua sessão foi terminada: {msg}", 'danger')
                return redirect(url_for('login'))
            
            # Sincronizar a role da sessão com a base de dados (Elevação imediata)
            session['role'] = user['role']
                
        return f(*args, **kwargs)
    return decorated_function

def requires_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user_role = session.get('role')
            perms = ROLES_PERMISSIONS.get(user_role, [])
            if permission not in perms:
                append_only_log(session.get('username'), user_role, "acesso_negado", request.path, result="failure")
                return render_template('denied.html'), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_user_status(user):
    if user['revoked']:
        return False, "Conta revogada."
    if not user['is_active']:
        return False, "Conta inativa."
    if user['expiration_date'] and datetime.strptime(user['expiration_date'], "%Y-%m-%d") < datetime.now():
        return False, "Acesso expirado."
    return True, ""

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mfa_token = request.form['mfa']

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user:
            is_valid, msg = check_user_status(user)
            if not is_valid:
                append_only_log(username, user['role'], "login", "sistema", result="failure_account_status")
                flash(msg, 'danger')
                return render_template('login.html')

            if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                totp = pyotp.TOTP(user['mfa_secret'])
                if totp.verify(mfa_token):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    append_only_log(username, user['role'], "login", "sistema", result="success")
                    return redirect(url_for('dashboard'))
                else:
                    append_only_log(username, user['role'], "login", "sistema", result="failure_mfa")
                    flash("Código MFA inválido.", 'danger')
            else:
                append_only_log(username, user['role'], "login", "sistema", result="failure_password")
                flash("Credenciais inválidas.", 'danger')
        else:
            append_only_log(username, "UNKNOWN", "login", "sistema", result="failure_user_not_found")
            flash("Credenciais inválidas.", 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        append_only_log(session['username'], session['role'], "logout", "sistema")
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    active_users = sum(1 for u in users if u['is_active'] and not u['revoked'] and (not u['expiration_date'] or datetime.strptime(u['expiration_date'], "%Y-%m-%d") >= datetime.now()))
    expired_users = sum(1 for u in users if u['expiration_date'] and datetime.strptime(u['expiration_date'], "%Y-%m-%d") < datetime.now())
    
    reqs = db.execute("SELECT COUNT(*) FROM access_requests WHERE status = 'pendente'").fetchone()[0]
    
    backups = len(os.listdir(BACKUP_DIR))
    
    recent_logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            for line in reversed(lines[-10:]):
                try:
                    recent_logs.append(json.loads(line.strip()))
                except:
                    pass

    return render_template('dashboard.html', active_users=active_users, expired_users=expired_users, pending_requests=reqs, backup_count=backups, recent_logs=recent_logs)

@app.route('/users')
@login_required
@requires_permission('manage_users')
def users():
    db = get_db()
    all_users = db.execute("SELECT * FROM users").fetchall()
    
    users_list = []
    for u in all_users:
        u_dict = dict(u)
        u_dict['is_expired'] = u_dict['expiration_date'] and datetime.strptime(u_dict['expiration_date'], "%Y-%m-%d") < datetime.now()
        users_list.append(u_dict)
        
    return render_template('users.html', users=users_list)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@requires_permission('manage_users')
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        justification = request.form['justification']
        expiration_date = request.form['expiration_date']
        
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        mfa_secret = pyotp.random_base32()
        
        db = get_db()
        try:
            db.execute('''INSERT INTO users (username, password_hash, mfa_secret, role, justification, approved_by, expiration_date)
                          VALUES (?, ?, ?, ?, ?, ?, ?)''', (username, pw_hash, mfa_secret, role, justification, session['username'], expiration_date))
            db.commit()
            append_only_log(session['username'], session['role'], "criação_utilizador", username, new_value=role)
            flash(f"Utilizador criado com sucesso! MFA Secret: {mfa_secret} (GUARDE ESTE VALOR)", 'success')
            return redirect(url_for('users'))
        except sqlite3.IntegrityError:
            flash("Username já existe.", 'danger')
            
    return render_template('create_user.html')

@app.route('/users/toggle/<int:user_id>', methods=['POST'])
@login_required
@requires_permission('manage_users')
def toggle_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        new_status = 0 if user['is_active'] else 1
        db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        db.commit()
        append_only_log(session['username'], session['role'], "alteração_estado", user['username'], str(user['is_active']), str(new_status))
        flash("Estado do utilizador alterado.", 'success')
    return redirect(url_for('users'))

@app.route('/users/revoke/<int:user_id>', methods=['POST'])
@login_required
@requires_permission('revoke_access')
def revoke_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        db.execute("UPDATE users SET revoked = 1, is_active = 0 WHERE id = ?", (user_id,))
        db.commit()
        append_only_log(session['username'], session['role'], "revogação_acesso", user['username'])
        flash("Acesso revogado com sucesso.", 'success')
    return redirect(request.referrer or url_for('users'))

@app.route('/access_requests')
@login_required
def access_requests():
    db = get_db()
    reqs = db.execute("SELECT * FROM access_requests WHERE status = 'pendente'").fetchall()
    return render_template('access_requests.html', requests=reqs)

@app.route('/access_requests/create', methods=['POST'])
@login_required
def create_request():
    target_role = request.form['target_role']
    system = request.form['system']
    duration = int(request.form['requested_duration'])
    justification = request.form['justification']
    
    db = get_db()
    db.execute('''INSERT INTO access_requests (username, target_role, system, justification, requested_duration, requested_by, created_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?)''', (session['username'], target_role, system, justification, duration, session['username'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()
    append_only_log(session['username'], session['role'], "pedido_acesso", system, new_value=target_role)
    flash("Pedido de acesso submetido com sucesso.", 'success')
    return redirect(url_for('access_requests'))

@app.route('/access_requests/process/<int:req_id>', methods=['POST'])
@login_required
@requires_permission('approve_access')
def process_request(req_id):
    action = request.form['action'] # 'approve' or 'reject'
    status = 'aprovado' if action == 'approve' else 'rejeitado'
    
    db = get_db()
    req_data = db.execute("SELECT * FROM access_requests WHERE id = ?", (req_id,)).fetchone()
    if req_data:
        if action == 'approve':
            # Calcular nova expiração e atualizar utilizador
            new_expiry = (datetime.now() + timedelta(days=req_data['requested_duration'])).strftime("%Y-%m-%d")
            db.execute("UPDATE users SET role = ?, expiration_date = ?, is_active = 1, revoked = 0 WHERE username = ?",
                       (req_data['target_role'], new_expiry, req_data['username']))
            
        db.execute("UPDATE access_requests SET status = ?, processed_at = ?, processed_by = ? WHERE id = ?",
                   (status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), session['username'], req_id))
        db.commit()
        append_only_log(session['username'], session['role'], "processamento_pedido", req_data['system'], new_value=status)
        flash(f"Pedido {status} com sucesso.", 'success')
    return redirect(url_for('access_requests'))

@app.route('/logs')
@login_required
@requires_permission('view_logs')
def logs():
    append_only_log(session['username'], session['role'], "visualização_logs", "audit.log.jsonl")
    log_lines = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            log_lines = [line.strip() for line in f.readlines()[-100:]] # Last 100 lines
    return render_template('logs.html', logs=log_lines)

@app.route('/backups')
@login_required
def backups():
    # Both ADMIN_IT and BACKUP_OPERATOR can access this, so we check roles manually if we didn't use @requires_permission
    if session.get('role') not in ['ADMIN_IT', 'BACKUP_OPERATOR']:
        append_only_log(session.get('username'), session.get('role'), "acesso_negado", request.path, result="failure")
        return render_template('denied.html'), 403
        
    backup_files = []
    for f in os.listdir(BACKUP_DIR):
        if f.endswith('.enc'):
            path = os.path.join(BACKUP_DIR, f)
            size = os.path.getsize(path)
            with open(path, 'rb') as file:
                content = file.read()
                file_hash = hashlib.sha256(content).hexdigest()
            backup_files.append({
                'filename': f,
                'size': size,
                'hash': file_hash,
                'created_at': datetime.fromtimestamp(os.path.getctime(path)).strftime("%Y-%m-%d %H:%M:%S")
            })
            
    backup_files.sort(key=lambda x: x['created_at'], reverse=True)
    return render_template('backups.html', backups=backup_files)

@app.route('/backups/create', methods=['POST'])
@login_required
def create_backup():
    if session.get('role') not in ['ADMIN_IT', 'BACKUP_OPERATOR']:
        append_only_log(session.get('username'), session.get('role'), "acesso_negado", request.path, result="failure")
        return render_template('denied.html'), 403
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"fista_db_{timestamp}.sqlite.enc"
    filepath = os.path.join(BACKUP_DIR, filename)
    
    with open(DB_FILE, 'rb') as db_file:
        data = db_file.read()
        encrypted_data = fernet.encrypt(data)
        
    with open(filepath, 'wb') as enc_file:
        enc_file.write(encrypted_data)
        
    append_only_log(session['username'], session['role'], "criação_backup", filename)
    flash(f"Backup cifrado {filename} criado com sucesso.", 'success')
    return redirect(url_for('backups'))

@app.route('/backups/restore/<filename>', methods=['POST'])
@login_required
def restore_backup(filename):
    if session.get('role') not in ['ADMIN_IT', 'BACKUP_OPERATOR']:
        append_only_log(session.get('username'), session.get('role'), "acesso_negado", request.path, result="failure")
        return render_template('denied.html'), 403
        
    filepath = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(filepath):
        # Simulate restore
        append_only_log(session['username'], session['role'], "restauro_backup", filename)
        flash(f"Simulação de restauro do backup {filename} concluída com sucesso.", 'success')
    return redirect(url_for('backups'))

@app.route('/review_access')
@login_required
@requires_permission('review_access')
def review_access():
    db = get_db()
    append_only_log(session['username'], session['role'], "revisão_acessos", "utilizadores_admin")
    # Fetch administrative users
    admins = db.execute("SELECT * FROM users WHERE role IN ('ADMIN_IT', 'BACKUP_OPERATOR')").fetchall()
    
    admin_list = []
    for u in admins:
        u_dict = dict(u)
        u_dict['is_expired'] = u_dict['expiration_date'] and datetime.strptime(u_dict['expiration_date'], "%Y-%m-%d") < datetime.now()
        admin_list.append(u_dict)
        
    return render_template('review_access.html', admins=admin_list)

@app.route('/review_access/renew/<int:user_id>', methods=['POST'])
@login_required
@requires_permission('review_access')
def renew_access(user_id):
    db = get_db()
    new_expiration = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
    db.execute("UPDATE users SET expiration_date = ?, is_active = 1, revoked = 0 WHERE id = ?", (new_expiration, user_id))
    db.commit()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    append_only_log(session['username'], session['role'], "renovação_acesso", user['username'], new_value=new_expiration)
    flash(f"Acesso de {user['username']} renovado por 30 dias.", 'success')
    return redirect(url_for('review_access'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
