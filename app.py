from flask import Flask, request, jsonify, send_from_directory, render_template, url_for, redirect, send_file, session, make_response, flash, g, Response, current_app
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
import secrets

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Add this line
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DATABASE = 'data.db'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)  # Set cookie to expire after 30 day

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database setup and helper functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
        print("Database initialized with users and content tables.")

# Call init_db() when the application starts
with app.app_context():
    init_db()

def migrate_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Check if is_private column exists
        cursor.execute("PRAGMA table_info(content)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_private' not in columns:
            print("Adding is_private column to content table")
            cursor.execute("ALTER TABLE content ADD COLUMN is_private INTEGER DEFAULT 0")
            db.commit()

# Call migrate_db() after init_db()
with app.app_context():
    init_db()
    migrate_db()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Add this function near the top of your file, after the imports
def get_username(user_id):
    if user_id is None:
        return 'Anonymous'
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return user[0] if user else 'Unknown'

# Add this function to delete old files
def delete_old_files():
    with app.app_context():
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
    def __init__(self, id, username, password_hash, api_key=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.api_key = api_key

    @staticmethod
    def hash_password(password):
        return password  # Store passwords in plaintext for simplicity

    @staticmethod
    def verify_password(stored_password, provided_password):
        return stored_password == provided_password

    @staticmethod
    def generate_api_key():
        return secrets.token_urlsafe(32)

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        # Print debug information
        print(f"User data: {user}")
        # Check if we have all required fields
        if len(user) >= 4:
            return User(user[0], user[1], user[2], user[3])
        else:
            print(f"Incomplete user data for user_id: {user_id}")
            return None
    print(f"No user found for user_id: {user_id}")
    return None

@app.route('/')
def index():
    try:
        if current_user.is_authenticated:
            return render_template('index.html', user=current_user)
    except Exception as e:
        print(f"Error in index route: {str(e)}")
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

@app.route('/<vanity>', methods=['GET', 'POST'])
def redirect_vanity(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT content.*, users.username FROM content LEFT JOIN users ON content.user_id = users.id WHERE content.vanity = ?", (vanity,))
    content = cursor.fetchone()
    
    print(f"Fetched content for vanity {vanity}: {content}")
    
    if content:
        content_type, content_data, created_at, user_id, is_private, password, username = content[1], content[2], content[3], content[4], content[5], content[6], content[7]
        
        print(f"Debug - Vanity: {vanity}, Type: {content_type}, Is Private: {is_private}, Password: {password}")
        print(f"User ID: {user_id}, Username: {username}")
        
        if content_type == 'url':
            return redirect(content_data)
        elif content_type == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], content_data)
            if os.path.exists(file_path):
                return send_file(file_path)
            else:
                return "File not found", 404
        elif content_type == 'pastebin':
            if is_private:
                if request.method == 'POST':
                    entered_password = request.form.get('password')
                    print(f"Entered password: {entered_password}")
                    print(f"Stored password: {password}")
                    if password and entered_password:
                        if entered_password == password:
                            print("Password match!")
                            return render_pastebin(content_data, created_at, user_id, username, vanity, is_private)
                        else:
                            print("Password mismatch!")
                            return render_template('password_prompt.html', vanity=vanity, error="Incorrect password")
                    else:
                        print(f"Missing password. Entered: {entered_password}, Stored: {password}")
                        return render_template('password_prompt.html', vanity=vanity, error="An error occurred. Please try again.")
                return render_template('password_prompt.html', vanity=vanity)
            else:
                return render_pastebin(content_data, created_at, user_id, username, vanity, is_private)
    
    return "Not found", 404

def render_pastebin(content_data, created_at, user_id, username, vanity, is_private):
    try:
        lexer = guess_lexer(content_data)
        language = lexer.aliases[0]
    except ClassNotFound:
        language = 'text'
        lexer = get_lexer_by_name(language)
    
    formatter = HtmlFormatter(style='monokai', linenos=True, cssclass="source")
    highlighted_code = highlight(content_data, lexer, formatter)
    css = formatter.get_style_defs('.source')
    return render_template('pastebin.html', 
                           content={'data': content_data, 'user_id': user_id, 'username': username or 'Anonymous'},
                           highlighted_content=highlighted_code,
                           css=css, 
                           raw_content=content_data,
                           language=language,
                           created_at=created_at,
                           vanity=vanity,
                           is_private=is_private)

@app.route('/<vanity>/raw')
def raw_vanity(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ? AND type = 'pastebin'", (vanity,))
    target = cursor.fetchone()
    
    if target:
        return target[2], 200, {'Content-Type': 'text/plain; charset=utf-8'}
    return 'Not Found', 404

# Replace the LoginForm and RegistrationForm classes with simple classes
class LoginForm:
    def __init__(self, username, password, remember):
        self.username = username
        self.password = password
        self.remember = remember

class RegistrationForm:
    def __init__(self, username, password):
        self.username = username
        self.password = password

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form
        form = LoginForm(username, password, remember)
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (form.username,))
        user = cursor.fetchone()
        if user and User.verify_password(user[2], form.password):
            user_obj = User(user[0], user[1], user[2], user[3])
            login_user(user_obj, remember=form.remember)
            return redirect(url_for('user_files', username=form.username))
        return "Invalid username or password"
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        api_key = User.generate_api_key()  # Generate API key
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return "Username already exists"
        hashed_password = User.hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)",
                       (username, hashed_password, api_key))
        db.commit()
        
        # Create user directory
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
        
        return redirect(url_for('login'))
    return render_template('register.html')

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
    
    # Fetch user's uploads (including files, pastebins, and shortened URLs)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE user_id = ?", (current_user.id,))
    user_uploads = cursor.fetchall()
    
    uploads = []
    for upload in user_uploads:
        uploads.append({
            'type': upload[1],
            'vanity': upload[0],
            'data': upload[2],
            'created_at': upload[3],
            'is_private': upload[5]
        })
    
    parent_folder = os.path.dirname(subpath.rstrip('/')) if subpath else None
    current_folder = os.path.basename(current_path)
    
    ignore_index = session.get(f'ignore_index_{username}', False)

    return render_template('user_files.html', 
                           username=username, 
                           items=items, 
                           folders=folders, 
                           uploads=uploads,
                           current_path=subpath.rstrip('/'),
                           parent_folder=parent_folder,
                           current_folder=current_folder,
                           ignore_index=ignore_index)

@app.route('/dash/<username>/toggle_index', methods=['POST'])
@login_required
def toggle_index(username):
    if current_user.username != username:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    current_setting = session.get(f'ignore_index_{username}', False)
    new_setting = not current_setting
    session[f'ignore_index_{username}'] = new_setting
    
    return jsonify({"success": True, "ignore_index": new_setting})

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

@app.route('/dash/<username>/delete/<path:filename>', methods=['POST'])
@login_required
def delete_user_file(username, filename):
    if current_user.username != username:
        return "Unauthorized", 401
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, filename)
    try:
        if os.path.exists(file_path):
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        return redirect(url_for('user_files', username=username))
    except PermissionError:
        return "Permission denied: Unable to delete the file or folder", 403
    except Exception as e:
        return f"An error occurred: {str(e)}", 500


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
        # Get the directory path to redirect back to
        dir_path = os.path.dirname(filename)
        return redirect(url_for('user_files', username=username, subpath=dir_path))

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

@app.route('/upload/pastebin', methods=['POST'])
def upload_pastebin():
    try:
        print("Received request to upload pastebin")
        data = request.get_json()
        print(f"Received JSON data: {data}")

        if not data or 'content' not in data:
            print("Error: Content is missing from the request")
            return jsonify({'success': False, 'error': 'Content is required'}), 400

        content = data['content']
        password = data.get('password')
        print(f"Content: {content[:50]}...") # Print first 50 characters of content
        print(f"Password received from client: {password}")

        is_private = 1 if password else 0
        print(f"Is private: {is_private}")

        vanity = shortuuid.uuid()[:8]
        print(f"Generated vanity: {vanity}")
        
        user_id = current_user.id if current_user.is_authenticated else None
        print(f"User ID: {user_id}")
        
        db = get_db()
        cursor = db.cursor()
        
        if is_private:
            print(f"Inserting private pastebin into database with password: {password}")
            cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id, is_private, password) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (vanity, 'pastebin', content, datetime.now(), user_id, is_private, password))
            print(f"Executed SQL with values: {vanity}, pastebin, {content[:50]}..., {datetime.now()}, {user_id}, {is_private}, {password}")
        else:
            print("Inserting public pastebin into database")
            cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id, is_private) VALUES (?, ?, ?, ?, ?, ?)",
                           (vanity, 'pastebin', content, datetime.now(), user_id, is_private))
            print(f"Executed SQL with values: {vanity}, pastebin, {content[:50]}..., {datetime.now()}, {user_id}, {is_private}")
        
        db.commit()
        print("Database commit successful")
        
        # Verify the inserted data
        cursor.execute("SELECT * FROM content WHERE vanity = ?", (vanity,))
        inserted_data = cursor.fetchone()
        print(f"Inserted data: {inserted_data}")
        
        short_url = url_for('redirect_vanity', vanity=vanity, _external=True)
        deletion_url = url_for('delete_content', vanity=vanity, _external=True)
        print(f"Generated short URL: {short_url}")
        print(f"Generated deletion URL: {deletion_url}")

        return jsonify({'success': True, 'vanity': vanity, 'url': short_url, 'deletion_url': deletion_url}), 200
    except Exception as e:
        print(f"Exception occurred in upload_pastebin: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/shorten', methods=['POST'])
def shorten_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'success': False, 'error': 'URL is required'}), 400

        long_url = data['url']
        vanity = shortuuid.uuid()[:8]
        
        user_id = current_user.id if current_user.is_authenticated else None
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
                       (vanity, 'url', long_url, datetime.now(), user_id))
        db.commit()
        
        short_url = f"{request.host_url}{vanity}"
        return jsonify({'success': True, 'vanity': vanity, 'short_url': short_url}), 200
    except Exception as e:
        print("Exception occurred:", str(e))
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/edit/content/<vanity>', methods=['GET', 'POST'])
@login_required
def edit_content(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ? OR data LIKE ?", (vanity, f"{vanity}%"))
    content = cursor.fetchone()

    if not content or content[4] != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    content_type, content_data = content[1], content[2]

    if request.method == 'POST':
        new_content = request.form.get('content')
        if new_content is not None:
            cursor.execute("UPDATE content SET data = ? WHERE vanity = ?", (new_content, content[0]))
            db.commit()
            return redirect(url_for('redirect_vanity', vanity=content[0]))

    if content_type == 'file':
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], content_data)
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                file_content = file.read()
            return render_template('edit_content.html', content=file_content, vanity=content[0], content_type=content_type)
    elif content_type == 'pastebin':
        return render_template('edit_content.html', content=content_data, vanity=content[0], content_type=content_type)

    return jsonify({'success': False, 'error': 'Unsupported content type for editing'}), 400

@app.route('/edit_password/<vanity>', methods=['GET', 'POST'])
@login_required
def edit_password(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ?", (vanity,))
    content = cursor.fetchone()

    if not content or content[4] != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    if request.method == 'POST':
        data = request.get_json()
        action = data.get('action')
        if action == 'update':
            new_password = data.get('new_password')
            cursor.execute("UPDATE content SET password = ?, is_private = 1 WHERE vanity = ?", (new_password, vanity))
            db.commit()
            return jsonify({'success': True})
        elif action == 'remove':
            cursor.execute("UPDATE content SET is_private = 0, password = NULL WHERE vanity = ?", (vanity,))
            db.commit()
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Invalid action'})

    return render_template('edit_password.html', vanity=vanity)

@app.route('/delete/content/<vanity>', methods=['POST'])
@login_required
def delete_content(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ? OR data LIKE ?", (vanity, f"{vanity}%"))
    content = cursor.fetchone()

    if not content or content[4] != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    cursor.execute("DELETE FROM content WHERE vanity = ? OR data LIKE ?", (vanity, f"{vanity}%"))
    db.commit()

    # If it's a file, delete the actual file from the filesystem
    if content[1] == 'file':
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], content[2])
        if os.path.exists(file_path):
            os.remove(file_path)

    return jsonify({'success': True}), 200

@app.route('/<vanity>/info')
def content_info(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ?", (vanity,))
    content = cursor.fetchone()
    
    if content:
        content_type, content_data, created_at, user_id = content[1], content[2], content[3], content[4]
        
        username = get_username(user_id)
        
        file_size = None
        is_media = False
        if content_type == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], content_data)
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                file_extension = os.path.splitext(content_data)[1].lower()
                is_media = file_extension in ['.jpg', '.jpeg', '.png', '.gif', '.mp3', '.wav', '.mp4', '.webm']
        
        info = {
            'type': content_type,
            'vanity': content_data if content_type == 'file' else vanity,
            'data': content_data,
            'created_at': created_at,
            'username': username,
            'file_size': file_size,
            'is_media': is_media
        }
        
        return render_template('content_info.html', info=info)
    
    return render_template('404.html'), 404

@app.route('/sharex-config')
@login_required
def generate_sharex_config():
    base_url = request.url_root.replace('http://', 'https://', 1).rstrip('/')
    config = {
        "Version": "13.7.0",
        "Name": "aCloud",
        "DestinationType": "ImageUploader, TextUploader, FileUploader, URLShortener",
        "RequestMethod": "POST",
        "RequestURL": f"{base_url}/api/upload",
        "Headers": {
            "X-API-Key": current_user.api_key
        },
        "Body": "MultipartFormData",
        "FileFormName": "file",
        "TextFormName": "text",
        "URLShortenerFormName": "url",
        "URL": "$json:url$",
        "DeletionURL": "$json:deletion_url$"
    }
    
    response = make_response(json.dumps(config, indent=2))
    response.headers.set('Content-Type', 'application/json')
    response.headers.set('Content-Disposition', 'attachment', filename='aCloud_ShareX.sxcu')
    return response

@app.route('/api/upload', methods=['POST'])
def api_upload():
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({'error': 'API key is missing'}), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'error': 'Invalid API key'}), 401

    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if file:
            filename = secure_filename(file.filename)
            extension = os.path.splitext(filename)[1].lower()
            
            if extension == '.txt':
                # Handle text files as pastebins
                content = file.read().decode('utf-8')
                vanity = shortuuid.uuid()[:8]
                
                cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
                               (vanity, 'pastebin', content, datetime.now(), user[0]))
                db.commit()
                
                url = url_for('redirect_vanity', vanity=vanity, _external=True, _scheme='https')
                delete_url = url_for('delete_content', vanity=vanity, _external=True, _scheme='https')
            else:
                # Handle other file types
                vanity = shortuuid.uuid()[:8]
                new_filename = f"{vanity}{extension}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                file.save(file_path)
                
                cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
                               (vanity, 'file', new_filename, datetime.now(), user[0]))
                db.commit()
                
                url = url_for('redirect_vanity', vanity=new_filename, _external=True, _scheme='https')
                delete_url = url_for('delete_content', vanity=new_filename, _external=True, _scheme='https')
            
            return json.dumps({
                'status': 'success',
                'url': url.replace('/download', ''),
                'deletion_url': delete_url,
            })
    elif 'text' in request.form:
        content = request.form['text']
        vanity = shortuuid.uuid()[:8]
        
        cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
                       (vanity, 'pastebin', content, datetime.now(), user[0]))
        db.commit()
        
        url = url_for('redirect_vanity', vanity=vanity, _external=True, _scheme='https')
        delete_url = url_for('delete_content', vanity=vanity, _external=True, _scheme='https')
        
        return json.dumps({
            'status': 'success',
            'url': url.replace('/download', ''),
            'deletion_url': delete_url,
        })
    elif 'url' in request.form:
        long_url = request.form['url']
        vanity = shortuuid.uuid()[:8]
        
        cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
                       (vanity, 'url', long_url, datetime.now(), user[0]))
        db.commit()
        
        short_url = url_for('redirect_vanity', vanity=vanity, _external=True, _scheme='https')
        delete_url = url_for('delete_content', vanity=vanity, _external=True, _scheme='https')
        
        return json.dumps({
            'status': 'success',
            'url': short_url.replace('/download', ''),
            'deletion_url': delete_url,
        })

    return jsonify({'error': 'No file, text, or URL content provided'}), 400

@app.route('/dash/<username>/create_new_file', methods=['POST'])
@login_required
def create_new_file(username):
    if current_user.username != username:
        return "Unauthorized", 401
    subpath = request.form.get('subpath', '').rstrip('/')
    file_name = request.form['file_name']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath, file_name)
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            f.write('')
        flash(f"File '{file_name}' created successfully.", 'success')
    else:
        flash(f"File '{file_name}' already exists.", 'error')
    return redirect(url_for('user_files', username=username, subpath=subpath))

@app.route('/dash/<username>/get_folders')
@login_required
def get_folders(username):
    if current_user.username != username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    subpath = request.args.get('path', '')
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath)
    
    if not os.path.exists(folder_path):
        return jsonify({'error': 'Folder not found'}), 404
    
    folders = [f for f in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, f))]
    return jsonify(folders)

@app.route('/dash/<username>/get_folders_and_files')
@login_required
def get_folders_and_files(username):
    if current_user.username != username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    subpath = request.args.get('path', '')
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath)
    
    if not os.path.exists(folder_path):
        return jsonify({'error': 'Folder not found'}), 404
    
    folders = []
    files = []
    for item in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item)
        if os.path.isdir(item_path):
            folders.append(item)
        else:
            files.append(item)
    
    return jsonify({'folders': folders, 'files': files})

@app.route('/dash/<username>/create_folder', methods=['POST'])
@login_required
def create_folder(username):
    if current_user.username != username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if request.is_json:
        data = request.get_json()
        folder_name = data.get('folder_name')
        subpath = data.get('subpath', '').rstrip('/')
    else:
        folder_name = request.form.get('folder_name')
        subpath = request.form.get('subpath', '').rstrip('/')
    
    if not folder_name:
        return jsonify({'error': 'Folder name is required'}), 400
    
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath, folder_name)
    
    if os.path.exists(folder_path):
        return jsonify({'error': 'Folder already exists'}), 400
    
    try:
        os.makedirs(folder_path)
        if request.is_json:
            return jsonify({'success': True, 'message': 'Folder created successfully'})
        else:
            flash(f"Folder '{folder_name}' created successfully.", 'success')
            return redirect(url_for('user_files', username=username, subpath=subpath))
    except Exception as e:
        if request.is_json:
            return jsonify({'error': str(e)}), 500
        else:
            flash(f"Error creating folder: {str(e)}", 'error')
            return redirect(url_for('user_files', username=username, subpath=subpath))

@app.route('/dash/<username>/rename', methods=['POST'])
@login_required
def rename_user_file(username):
    if current_user.username != username:
        return "Unauthorized", 401
    
    old_filename = request.form['old_filename']
    new_filename = secure_filename(request.form['new_filename'])
    item_type = request.form['item_type']
    current_path = request.form.get('current_path', '').rstrip('/')
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    full_current_path = os.path.join(user_folder, current_path)
    
    old_path = os.path.join(full_current_path, old_filename)
    new_path = os.path.join(full_current_path, new_filename)
    
    if not os.path.exists(old_path):
        flash(f"The {item_type} '{old_filename}' does not exist.", 'error')
        return redirect(url_for('user_files', username=username, subpath=current_path))
    
    try:
        os.rename(old_path, new_path)
        flash(f"Successfully renamed {item_type} from '{old_filename}' to '{new_filename}'.", 'success')
    except OSError as e:
        flash(f"Error renaming {item_type}: {str(e)}", 'error')
    
    return redirect(url_for('user_files', username=username, subpath=current_path))

@app.route('/upload/file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400
    if file:
        try:
            filename = secure_filename(file.filename)
            extension = os.path.splitext(filename)[1].lower()
            vanity = shortuuid.uuid()[:8]
            vanity_with_extension = f"{vanity}{extension}"
            new_filename = vanity_with_extension
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], new_filename)
            
            file.save(file_path)
            
            user_id = current_user.id if current_user.is_authenticated else None
            
            db = get_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id) VALUES (?, ?, ?, ?, ?)",
                           (vanity_with_extension, 'file', new_filename, datetime.now(), user_id))
            db.commit()
            
            short_url = url_for('redirect_vanity', vanity=vanity_with_extension, _external=True)
            deletion_url = url_for('delete_content', vanity=vanity_with_extension, _external=True)
            
            return jsonify({
                'success': True,
                'vanity': vanity_with_extension,
                'url': short_url,
                'deletion_url': deletion_url,
                'filename': new_filename
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    return jsonify({'success': False, 'error': 'Unknown error occurred'}), 500

if __name__ == '__main__':
    # Start the cleanup thread
    cleanup_thread = threading.Thread(target=delete_old_files)
    cleanup_thread.daemon = True
    cleanup_thread.start()

    app.run(host='0.0.0.0', port=7123, debug=True)