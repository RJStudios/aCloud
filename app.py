from flask import Flask, request, jsonify, send_from_directory, render_template, url_for, redirect
from werkzeug.utils import secure_filename
import shortuuid
import os
from datetime import datetime
import zipfile

app = Flask(__name__)
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

data_store = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/content/<vanity>')
def content(vanity):
    target = data_store.get(vanity)
    if target:
        if target['type'] == 'pastebin':
            return render_template('content.html', content=target['content'], created_at=target['created_at'])
        elif target['type'] == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{vanity}_{target["filename"]}')
            file_info = {
                'name': target['filename'],
                'size': os.path.getsize(file_path),
                'modified_at': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'url': url_for('download_file', vanity=vanity)
            }
            return render_template('file.html', **file_info)
        elif target['type'] == 'url':
            return render_template('content.html', url=target['url'])
    return 'Not Found', 404

@app.route('/download/<vanity>', methods=['GET'])
def download_file(vanity):
    target = data_store.get(vanity)
    if target and target['type'] == 'file':
        filename = f'{vanity}_{target["filename"]}'
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    return 'Not Found', 404

@app.route('/upload/pastebin', methods=['POST'])
def upload_pastebin():
    content = request.form['content']
    vanity = shortuuid.uuid()[:6]
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data_store[vanity] = {'type': 'pastebin', 'content': content, 'created_at': created_at}

    html_content = render_template('content.html', content=content, created_at=created_at)
    html_file_path = os.path.join('templates', f'{vanity}.html')
    with open(html_file_path, 'w') as f:
        f.write(html_content)
    
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
        data_store[vanity] = {'type': 'file', 'filename': filename}

        file_info = {
            'name': filename,
            'size': os.path.getsize(filepath),
            'modified_at': datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
            'url': url_for('download_file', vanity=vanity)
        }
        html_content = render_template('file.html', **file_info)
        html_file_path = os.path.join('templates', f'{vanity}.html')
        with open(html_file_path, 'w') as f:
            f.write(html_content)

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
    
    data_store[vanity] = {'type': 'folder', 'files': [file.filename for file in files]}

    return jsonify({'vanity': vanity})

@app.route('/shorten', methods=['POST'])
def shorten_url():
    original_url = request.form['url']
    vanity = shortuuid.uuid()[:6]
    data_store[vanity] = {'type': 'url', 'url': original_url}

    html_content = f'<html><body><script>window.location.href="{original_url}";</script></body></html>'
    html_file_path = os.path.join('templates', f'{vanity}.html')
    with open(html_file_path, 'w') as f:
        f.write(html_content)

    return jsonify({'vanity': vanity})

@app.route('/<vanity>', methods=['GET'])
def redirect_vanity(vanity):
    target = data_store.get(vanity)
    
    if target:
        if target['type'] == 'pastebin':
            return render_template(f'{vanity}.html')
        elif target['type'] == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{vanity}_{target["filename"]}')
            file_info = {
                'name': target['filename'],
                'size': os.path.getsize(file_path),
                'modified_at': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'url': url_for('download_file', vanity=vanity)
            }
            return render_template('file.html', **file_info)
        elif target['type'] == 'folder':
            return redirect(url_for('folder_content', vanity=vanity))
        elif target['type'] == 'url':
            return render_template('content.html', url=target['url'])
    return render_template('404.html'), 404

@app.route('/<vanity>/raw', methods=['GET'])
def raw_vanity(vanity):
    target = data_store.get(vanity)
    
    if target:
        if target['type'] == 'pastebin':
            return render_template(f'{vanity}raw.html')

    return render_template('404.html'), 404

@app.route('/folder/<vanity>', methods=['GET'])
def folder_content(vanity):
    target = data_store.get(vanity)
    if target and target['type'] == 'folder':
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

        return render_template('folder.html', files=files, prev_url=prev_url, next_url=next_url)
    
    return 'Not Found', 404

@app.route('/folder/<vanity>/download', methods=['GET'])
def download_folder_as_zip(vanity):
    target = data_store.get(vanity)
    if target and target['type'] == 'folder':
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
