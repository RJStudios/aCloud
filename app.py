from flask import Flask, request, jsonify, send_from_directory, render_template, url_for, redirect, send_file, session
from werkzeug.utils import secure_filename
import shortuuid
import os
from datetime import datetime, timedelta
import zipfile
import sqlite3
import threading
import time
import shutil
from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.formatters import HtmlFormatter
from pygments.util import ClassNotFound
import json
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_remembered
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Add this line
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DATABASE = 'data.db'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)  # Set cookie to expire after 30 days

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
    if current_user.is_authenticated:
        return render_template('index.html', user=current_user)
    return render_template('index.html', user=None)

@app.route('/u/<username>')
@app.route('/u/<username>/')
@app.route('/u/<username>/<path:filename>')
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

    current_path = os.path.join(user_folder, filename.rstrip('/') if filename else '')
    if not os.path.exists(current_path):
        return "Folder or file not found", 404

    if os.path.isfile(current_path):
        return send_file(current_path)

    # Check if we should ignore index.html
    ignore_index = session.get(f'ignore_index_{username}', False)

    # Check for index.html
    index_path = os.path.join(current_path, 'index.html')
    if os.path.exists(index_path) and not ignore_index:
        return send_file(index_path)

    # Directory listing
    files = []
    folders = []
    for item in os.listdir(current_path):
        item_path = os.path.join(current_path, item)
        relative_path = os.path.relpath(item_path, user_folder)
        if os.path.isfile(item_path):
            files.append({'name': item, 'path': relative_path})
        else:
            folders.append({'name': item, 'path': relative_path})

    parent_folder = os.path.dirname(filename.rstrip('/')) if filename else None
    current_folder = os.path.basename(current_path)

    # Generate the correct parent folder URL
    parent_url = None
    if parent_folder:
        parent_url = url_for('serve_user_page', username=username, filename=parent_folder)
    elif filename:  # If we're in a subfolder, parent is the root
        parent_url = url_for('serve_user_page', username=username)

    return render_template('user_files_public.html', 
                           username=username, 
                           files=files, 
                           folders=folders, 
                           current_path=filename.rstrip('/') if filename else '',
                           parent_url=parent_url,
                           current_folder=current_folder)

@app.route('/<path:path>')
def redirect_vanity(path):
    parts = path.rstrip('/').split('/')
    vanity = parts[0]
    subpath = '/'.join(parts[1:]) if len(parts) > 1 else ''

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
        
        # Create user directory
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and User.verify_password(user[2], password):
            user_obj = User(user[0], user[1], user[2])
            login_user(user_obj, remember=remember)
            return redirect(url_for('user_files', username=username))
        return "Invalid username or password"
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dash/<username>')
@app.route('/dash/<username>/')
@app.route('/dash/<username>/<path:subpath>')
@login_required
def user_files(username, subpath=''):
    if current_user.username != username:
        return "Unauthorized", 401
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    current_path = os.path.join(user_folder, subpath.rstrip('/'))
    
    # Create user folder if it doesn't exist
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    
    if not os.path.exists(current_path):
        return "Folder not found", 404
    
    if not os.path.isdir(current_path):
        return "Not a directory", 400
    
    items = []
    folders = []
    for item in os.listdir(current_path):
        item_path = os.path.join(current_path, item)
        relative_path = os.path.relpath(item_path, user_folder)
        if os.path.isfile(item_path):
            items.append({'name': item, 'type': 'file', 'path': relative_path})
        else:
            items.append({'name': item, 'type': 'folder', 'path': relative_path})
            folders.append(relative_path)
    
    parent_folder = os.path.dirname(subpath.rstrip('/')) if subpath else None
    current_folder = os.path.basename(current_path)
    
    # Check if index.html exists in the current folder
    index_exists = 'index.html' in [item['name'] for item in items if item['type'] == 'file']
    
    # Get the current setting for ignoring index.html
    ignore_index = session.get(f'ignore_index_{username}', False)
    
    return render_template('user_files.html', 
                           username=username, 
                           items=items, 
                           folders=folders, 
                           current_path=subpath.rstrip('/'),
                           parent_folder=parent_folder,
                           current_folder=current_folder,
                           index_exists=index_exists,
                           ignore_index=ignore_index)

@app.route('/dash/<username>/toggle_index')
@login_required
def toggle_index(username):
    if current_user.username != username:
        return "Unauthorized", 401
    
    current_setting = session.get(f'ignore_index_{username}', False)
    session[f'ignore_index_{username}'] = not current_setting
    
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/upload', methods=['POST'])
@login_required
def upload_user_file(username):
    if current_user.username != username:
        return "Unauthorized", 401
    subpath = request.form.get('subpath', '').rstrip('/')
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        file.save(file_path)
        return redirect(url_for('user_files', username=username, subpath=subpath))

@app.route('/dash/<username>/delete/<filename>', methods=['POST'])
@login_required
def delete_user_file(username, filename):
    if current_user.username != username:
        return "Unauthorized", 401
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/rename', methods=['POST'])
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

@app.route('/dash/<username>/create_folder', methods=['POST'])
@login_required
def create_folder(username):
    if current_user.username != username:
        return "Unauthorized", 401
    subpath = request.form.get('subpath', '').rstrip('/')
    folder_name = secure_filename(request.form['folder_name'])
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath, folder_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    return redirect(url_for('user_files', username=username, subpath=subpath))

@app.route('/dash/<username>/delete_folder/<folder_name>', methods=['POST'])
@login_required
def delete_folder(username, folder_name):
    if current_user.username != username:
        return "Unauthorized", 401
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, folder_name)
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/rename_folder', methods=['POST'])
@login_required
def rename_folder(username):
    if current_user.username != username:
        return "Unauthorized", 401
    old_foldername = request.form['old_foldername']
    new_foldername = secure_filename(request.form['new_foldername'])
    old_path = os.path.join(app.config['UPLOAD_FOLDER'], username, old_foldername)
    new_path = os.path.join(app.config['UPLOAD_FOLDER'], username, new_foldername)
    if os.path.exists(old_path):
        os.rename(old_path, new_path)
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/move_item', methods=['POST'])
@login_required
def move_item(username):
    if current_user.username != username:
        return "Unauthorized", 401
    item_name = request.form['item_name']
    item_type = request.form['item_type']
    destination_folder = request.form['destination_folder']
    source_path = os.path.join(app.config['UPLOAD_FOLDER'], username, item_name)
    dest_path = os.path.join(app.config['UPLOAD_FOLDER'], username, destination_folder, item_name)
    if os.path.exists(source_path):
        shutil.move(source_path, dest_path)
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/copy_item', methods=['POST'])
@login_required
def copy_item(username):
    if current_user.username != username:
        return "Unauthorized", 401
    item_name = request.form['item_name']
    item_type = request.form['item_type']
    destination_folder = request.form['destination_folder']
    source_path = os.path.join(app.config['UPLOAD_FOLDER'], username, item_name)
    dest_path = os.path.join(app.config['UPLOAD_FOLDER'], username, destination_folder, item_name)
    if os.path.exists(source_path):
        if item_type == 'file':
            shutil.copy2(source_path, dest_path)
        else:
            shutil.copytree(source_path, dest_path)
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/edit/<path:filename>', methods=['GET', 'POST'])
@login_required
def edit_file(username, filename):
    if current_user.username != username:
        return "Unauthorized", 401

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, filename)
    if not os.path.exists(file_path):
        return "File not found", 404

    if request.method == 'POST':
        content = request.form['content']
        with open(file_path, 'w') as f:
            f.write(content)
        return redirect(url_for('user_files', username=username))

    with open(file_path, 'r') as f:
        content = f.read()

    return render_template('edit_file.html', filename=filename, content=content)

@app.route('/debug/users')
def debug_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    return jsonify(users)

if __name__ == '__main__':
    app.run(debug=True)
