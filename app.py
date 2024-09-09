from flask import Flask, request, jsonify, send_from_directory, render_template, url_for, redirect, send_file
from werkzeug.utils import secure_filename
import shortuuid
import os
from datetime import datetime
import zipfile
import sqlite3
import threading
import time
import shutil
from datetime import timedelta
from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.formatters import HtmlFormatter
from pygments.util import ClassNotFound
import json
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Add this line
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DATABASE = 'data.db'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database setup and helper functions
def get_db():
    db = getattr(threading.current_thread(), '_database', None)
    if db is None:
        db = threading.current_thread()._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(threading.current_thread(), '_database', None)
    if db is not None:
        db.close()

# Initialize database
init_db()

# Add this function to delete old files
def delete_old_files():
    while True:
        db = get_db()
        cursor = db.cursor()
        
        # Delete files older than 30 days
        thirty_days_ago = datetime.now() - timedelta(days=30)
        cursor.execute("SELECT vanity, type, data FROM content WHERE created_at < ?", (thirty_days_ago,))
        old_files = cursor.fetchall()
        
        for vanity, content_type, data in old_files:
            if content_type == 'file':
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{vanity}_{data}')
                if os.path.exists(file_path):
                    os.remove(file_path)
            elif content_type == 'folder':
                folder_path = os.path.join(app.config['UPLOAD_FOLDER'], vanity)
                if os.path.exists(folder_path):
                    shutil.rmtree(folder_path)
        
        cursor.execute("DELETE FROM content WHERE created_at < ?", (thirty_days_ago,))
        db.commit()
        
        time.sleep(86400)  # Sleep for 24 hours

# Start the cleanup thread
cleanup_thread = threading.Thread(target=delete_old_files)
cleanup_thread.daemon = True
cleanup_thread.start()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def hash_password(password):
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt + key

    @staticmethod
    def verify_password(stored_password, provided_password):
        salt = stored_password[:32]
        stored_key = stored_password[32:]
        new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return stored_key == new_key

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        return User(user[0], user[1], user[2])
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/content/<vanity>')
def content(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ?", (vanity,))
    target = cursor.fetchone()
    
    if target:
        content_type, content_data = target[1], target[2]
        if content_type == 'pastebin':
            try:
                lexer = guess_lexer(content_data)
                language = lexer.aliases[0]
            except ClassNotFound:
                language = 'text'
                lexer = get_lexer_by_name(language)
            
            formatter = HtmlFormatter(style='monokai', linenos=True, cssclass="source")
            highlighted_code = highlight(content_data, lexer, formatter)
            css = formatter.get_style_defs('.source')
            return render_template('content.html', 
                                   highlighted_content=highlighted_code, 
                                   css=css, 
                                   raw_content=content_data,
                                   created_at=target[3],
                                   vanity=vanity,
                                   language=language)
        elif content_type == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{vanity}_{content_data}')
            file_info = {
                'name': content_data,
                'size': os.path.getsize(file_path),
                'modified_at': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'url': url_for('download_file', vanity=vanity)
            }
            return render_template('file.html', **file_info)
        elif content_type == 'url':
            return render_template('content.html', url=content_data)
    return 'Not Found', 404

@app.route('/download/<vanity>', methods=['GET'])
def download_file(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ? AND type = 'file'", (vanity,))
    target = cursor.fetchone()
    if target:
        filename = f'{vanity}_{target[2]}'
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    return 'Not Found', 404

@app.route('/upload/pastebin', methods=['POST'])
def upload_pastebin():
    content = request.form['content']
    vanity = shortuuid.uuid()[:6]
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO content (vanity, type, data, created_at) VALUES (?, ?, ?, ?)",
                   (vanity, 'pastebin', content, created_at))
    db.commit()
    
    return jsonify({'vanity': vanity})

@app.route('/upload/file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file:
        vanity = shortuuid.uuid()[:6]
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f'{vanity}_{filename}')
        file.save(filepath)
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO content (vanity, type, data) VALUES (?, ?, ?)",
                       (vanity, 'file', filename))
        db.commit()
        
        return jsonify({'vanity': vanity})

def save_file(file, folder_path):
    filename = secure_filename(file.filename)
    file_path = os.path.join(folder_path, filename)
    file.save(file_path)

def handle_uploaded_folder(files, base_path):
    for file in files:
        if file.filename.endswith('/'):  
            subfolder_path = os.path.join(base_path, secure_filename(file.filename))
            os.makedirs(subfolder_path, exist_ok=True)
            handle_uploaded_folder(request.files.getlist(file.filename), subfolder_path) 
        else:
            save_file(file, base_path)

@app.route('/upload/folder', methods=['POST'])
def upload_folder():
    if 'file' not in request.files:
        return 'No files uploaded', 400
    
    files = request.files.getlist('file')
    if not files:
        return 'No files selected', 400
    
    vanity = shortuuid.uuid()[:6]
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], vanity)
    os.makedirs(folder_path)

    handle_uploaded_folder(files, folder_path)
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO content (vanity, type, data) VALUES (?, ?, ?)",
                   (vanity, 'folder', ','.join([file.filename for file in files])))
    db.commit()

    return jsonify({'vanity': vanity})

@app.route('/shorten', methods=['POST'])
def shorten_url():
    original_url = request.form['url']
    vanity = shortuuid.uuid()[:6]
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO content (vanity, type, data) VALUES (?, ?, ?)",
                   (vanity, 'url', original_url))
    db.commit()

    return jsonify({'vanity': vanity})

@app.route('/<vanity>', methods=['GET'])
def redirect_vanity(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ?", (vanity,))
    target = cursor.fetchone()
    
    if target:
        content_type, content_data = target[1], target[2]
        if content_type == 'pastebin':
            try:
                lexer = guess_lexer(content_data)
                language = lexer.aliases[0]
            except ClassNotFound:
                language = 'text'
                lexer = get_lexer_by_name(language)
            
            formatter = HtmlFormatter(style='monokai', linenos=True, cssclass="source")
            highlighted_code = highlight(content_data, lexer, formatter)
            css = formatter.get_style_defs('.source')
            return render_template('content.html', 
                                   highlighted_content=highlighted_code,
                                   css=css, 
                                   raw_content=content_data,
                                   created_at=target[3],
                                   vanity=vanity,
                                   language=language)
        elif content_type == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{vanity}_{content_data}')
            file_info = {
                'name': content_data,
                'size': os.path.getsize(file_path),
                'modified_at': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'url': url_for('download_file', vanity=vanity)
            }
            return render_template('file.html', **file_info)
        elif content_type == 'folder':
            return redirect(url_for('folder_content', vanity=vanity))
        elif content_type == 'url':
            return render_template('content.html', content=content_data, url=content_data)
    return render_template('404.html'), 404

@app.route('/<vanity>/raw', methods=['GET'])
def raw_vanity(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ? AND type = 'pastebin'", (vanity,))
    target = cursor.fetchone()
    
    if target:
        return target[2], 200, {'Content-Type': 'text/plain; charset=utf-8'}
    return 'Not Found', 404

@app.route('/folder/<vanity>', methods=['GET'])
def folder_content(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ? AND type = 'folder'", (vanity,))
    target = cursor.fetchone()
    if target:
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], vanity)
        files = []
        for root, _, filenames in os.walk(folder_path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                relative_path = os.path.relpath(file_path, folder_path)
                file_url = url_for('download_folder_file', vanity=vanity, file_name=relative_path)
                files.append({'name': relative_path, 'url': file_url})
        
        # Pagination
        per_page = 10
        page = int(request.args.get('page', 1))
        start = (page - 1) * per_page
        end = start + per_page
        total_files = len(files)
        files = files[start:end]

        prev_url = url_for('folder_content', vanity=vanity, page=page-1) if page > 1 else None
        next_url = url_for('folder_content', vanity=vanity, page=page+1) if end < total_files else None

        download_all_url = url_for('download_folder_as_zip', vanity=vanity)
        
        # Get the current folder name
        current_folder = os.path.basename(folder_path)

        return render_template('folder.html', 
                               files=files, 
                               prev_url=prev_url, 
                               next_url=next_url, 
                               download_all_url=download_all_url,
                               current_folder=current_folder)
    
    return 'Not Found', 404

@app.route('/folder/<vanity>/download', methods=['GET'])
def download_folder_as_zip(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ? AND type = 'folder'", (vanity,))
    target = cursor.fetchone()
    if target:
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], vanity)
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{vanity}.zip')
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, folder_path))
        
        return send_from_directory(app.config['UPLOAD_FOLDER'], f'{vanity}.zip', as_attachment=True)
    return 'Not Found', 404

@app.route('/folder/<vanity>/<file_name>', methods=['GET'])
def download_folder_file(vanity, file_name):
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], vanity)
    file_path = os.path.join(folder_path, file_name)
    if os.path.isfile(file_path):
        return send_from_directory(folder_path, file_name, as_attachment=True)
    return 'Not Found', 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return "Username already exists"
        hashed_password = User.hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_password))
        db.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and User.verify_password(user[2], password):
            login_user(User(user[0], user[1], user[2]))
            return redirect(url_for('user_files', username=username))
        return "Invalid username or password"
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/user/<username>')
def user_files(username):
    if current_user.is_authenticated and current_user.username == username:
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
        files = os.listdir(user_folder)
        return render_template('user_files.html', username=username, files=files)
    return "Unauthorized", 401

@app.route('/user/<username>/upload', methods=['POST'])
@login_required
def upload_user_file(username):
    if current_user.username != username:
        return "Unauthorized", 401
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, filename)
        file.save(file_path)
        return redirect(url_for('user_files', username=username))

@app.route('/user/<username>/delete/<filename>', methods=['POST'])
@login_required
def delete_user_file(username, filename):
    if current_user.username != username:
        return "Unauthorized", 401
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect(url_for('user_files', username=username))

@app.route('/user/<username>/rename', methods=['POST'])
@login_required
def rename_user_file(username):
    if current_user.username != username:
        return "Unauthorized", 401
    old_filename = request.form['old_filename']
    new_filename = secure_filename(request.form['new_filename'])
    old_path = os.path.join(app.config['UPLOAD_FOLDER'], username, old_filename)
    new_path = os.path.join(app.config['UPLOAD_FOLDER'], username, new_filename)
    if os.path.exists(old_path):
        os.rename(old_path, new_path)
    return redirect(url_for('user_files', username=username))

@app.route('/<username>')
@app.route('/<username>/')
@app.route('/<username>/<path:filename>')
def serve_user_page(username, filename=None):
    print(f"Accessing user page: {username}, filename: {filename}")  # Debug print

    # Check if the username exists in the database
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        print(f"User {username} not found")  # Debug print
        return "User not found", 404

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    print(f"User folder path: {user_folder}")  # Debug print
    
    if not os.path.exists(user_folder):
        print(f"User folder does not exist for {username}")  # Debug print
        os.makedirs(user_folder)  # Create the folder if it doesn't exist

    if filename is None or filename == '':
        # Try to serve index.html
        index_path = os.path.join(user_folder, 'index.html')
        print(f"Checking for index.html at: {index_path}")  # Debug print
        if os.path.exists(index_path):
            print(f"Serving index.html for {username}")  # Debug print
            return send_file(index_path)
        else:
            print(f"No index.html found, listing files for {username}")  # Debug print
            # If no index.html, list all files
            files = os.listdir(user_folder)
            print(f"Files in {username}'s folder: {files}")  # Debug print
            return render_template('user_files_public.html', username=username, files=files)
    else:
        # Serve the requested file
        file_path = os.path.join(user_folder, filename)
        print(f"Attempting to serve file: {file_path}")  # Debug print
        if os.path.exists(file_path) and os.path.isfile(file_path):
            print(f"Serving file: {file_path}")  # Debug print
            return send_file(file_path)
        else:
            print(f"File not found: {file_path}")  # Debug print
            return "File not found", 404

@app.route('/debug/users')
def debug_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users")
    users = cursor.fetchall()
    
    user_files = {}
    for user in users:
        username = user[0]
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        if os.path.exists(user_folder):
            user_files[username] = os.listdir(user_folder)
        else:
            user_files[username] = []
    
    return jsonify(user_files)

@app.route('/user/<username>/edit/<path:filename>', methods=['GET', 'POST'])
@login_required
def edit_file(username, filename):
    if current_user.username != username:
        return "Unauthorized", 401
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, filename)
    
    if request.method == 'POST':
        content = request.form['content']
        with open(file_path, 'w') as file:
            file.write(content)
        return redirect(url_for('user_files', username=username))
    
    if os.path.exists(file_path) and os.path.isfile(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
        return render_template('edit_file.html', username=username, filename=filename, content=content)
    else:
        return "File not found", 404

if __name__ == '__main__':
    app.run(debug=True, port=7123)
