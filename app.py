from flask import Flask, request, jsonify, send_from_directory, render_template, url_for, redirect
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

app = Flask(__name__)
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
            return render_template('content.html', content=content_data, created_at=target[3])
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
            return render_template('content.html', content=content_data, created_at=target[3])
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
            return render_template('content.html', url=content_data)
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

if __name__ == '__main__':
    app.run(debug=True, port=7123)
