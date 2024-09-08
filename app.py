from flask import Flask, request, jsonify, send_from_directory, render_template, url_for, redirect
from werkzeug.utils import secure_filename
import shortuuid
import os
from datetime import datetime

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
    html_content = render_template('raw.html', content=content)
    html_file_path = os.path.join('templates', f'{vanity}raw.html')
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
@app.route('/<vanity>/raw', methods=['GET'])
ef redirect_vanity(vanity):
    target = data_store.get(vanity)
    if target:
        if target['type'] == 'pastebin':
            return render_template(f'{vanity}raw.html')
        elif target['type'] == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{vanity}_{target["filename"]}')
            file_info = {
                'name': target['filename'],
                'size': os.path.getsize(file_path),
                'modified_at': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'url': url_for('download_file', vanity=vanity)
            }
            return render_template(f'{vanity}.html', **file_info)
        elif target['type'] == 'url':
            return render_template(f'{vanity}.html')
    return 'Not Found', 404

if __name__ == '__main__':
    app.run(debug=True)
