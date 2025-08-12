import os
import secrets
import base64
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from flask import send_from_directory
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import io
import logging

# --- Basic Flask App Setup ---
app = Flask(__name__)
CORS(app)


@app.route('/')
def serve_ui():
    return send_from_directory('.', 'index.html')


# --- Configuration ---
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# --- Encryption/Decryption Logic ---
CHUNK_SIZE = 64 * 1024


def encrypt_stream(input_stream, output_stream, key):
    """Encrypts a file stream chunk by chunk."""
    aesgcm = AESGCM(key)
    while True:
        chunk = input_stream.read(CHUNK_SIZE)
        if not chunk:
            break
        nonce = secrets.token_bytes(12)
        encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
        output_stream.write(len(nonce).to_bytes(2, 'big'))
        output_stream.write(nonce)
        output_stream.write(len(encrypted_chunk).to_bytes(4, 'big'))
        output_stream.write(encrypted_chunk)
    output_stream.seek(0)


def decrypt_stream(input_stream, output_stream, key):
    """Decrypts a file stream chunk by chunk."""
    aesgcm = AESGCM(key)
    while True:
        nonce_len_bytes = input_stream.read(2)
        if not nonce_len_bytes:
            break
        nonce_len = int.from_bytes(nonce_len_bytes, 'big')
        nonce = input_stream.read(nonce_len)
        enc_len_bytes = input_stream.read(4)
        if not enc_len_bytes:
            raise ValueError("Encrypted file is truncated or corrupt.")
        enc_len = int.from_bytes(enc_len_bytes, 'big')
        encrypted_chunk = input_stream.read(enc_len)
        if len(encrypted_chunk) < enc_len:
            raise ValueError("Encrypted file is truncated or corrupt.")
        decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
        output_stream.write(decrypted_chunk)
    output_stream.seek(0)


# --- API Endpoints ---
@app.route('/generate-key', methods=['GET'])
def generate_key_endpoint():
    """Generates a new AES-256 key and returns it."""
    try:
        key = secrets.token_bytes(32)
        return jsonify({"key": key.hex(), "success": True})
    except Exception as e:
        logging.error(f"Key generation failed: {e}")
        return jsonify({"error": "Key generation failed", "success": False}), 500


@app.route('/encrypt', methods=['POST'])
def encrypt_file_endpoint():
    """Endpoint to encrypt an uploaded file."""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part", "success": False}), 400
        if 'key' not in request.form:
            return jsonify({"error": "No key provided", "success": False}), 400

        file = request.files['file']
        key_hex = request.form['key']
        output_format = request.form.get('format', 'text')

        if file.filename == '':
            return jsonify({"error": "No selected file", "success": False}), 400

        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 32:
                raise ValueError("Invalid key length.")
        except ValueError:
            return jsonify({"error": "Invalid key format", "success": False}), 400

        file.seek(0)
        input_stream = io.BytesIO(file.read())
        input_stream.seek(0)
        output_stream = io.BytesIO()

        encrypt_stream(input_stream, output_stream, key)

        if output_format == 'text':
            encrypted_data = output_stream.getvalue()
            text_data = base64.b64encode(encrypted_data).decode('utf-8')

            text_content = f"""ENCRYPTED FILE DATA
Original File: {file.filename}
Encryption: AES-256-GCM
Format: Base64

==== DATA START ====
{text_data}
==== DATA END ====
"""

            text_stream = io.BytesIO(text_content.encode('utf-8'))
            output_filename = f"{secure_filename(file.filename)}.encrypted.txt"

            return send_file(
                text_stream,
                as_attachment=True,
                download_name=output_filename,
                mimetype='text/plain'
            )
        else:
            output_filename = f"{secure_filename(file.filename)}.enc"
            return send_file(
                output_stream,
                as_attachment=True,
                download_name=output_filename,
                mimetype='application/octet-stream'
            )

    except Exception as e:
        logging.error(f"Encryption error: {e}")
        return jsonify({"error": f"Encryption failed: {str(e)}", "success": False}), 500


@app.route('/decrypt', methods=['POST'])
def decrypt_file_endpoint():
    """Endpoint to decrypt an uploaded file."""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part", "success": False}), 400
        if 'key' not in request.form:
            return jsonify({"error": "No key provided", "success": False}), 400

        file = request.files['file']
        key_hex = request.form['key']

        if file.filename == '':
            return jsonify({"error": "No selected file", "success": False}), 400

        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 32:
                raise ValueError("Invalid key length.")
        except ValueError:
            return jsonify({"error": "Invalid key format", "success": False}), 400

        if file.filename.endswith('.encrypted.txt'):
            content = file.read().decode('utf-8')
            start_marker = "==== DATA START ===="
            end_marker = "==== DATA END ===="

            start_idx = content.find(start_marker)
            end_idx = content.find(end_marker)

            if start_idx == -1 or end_idx == -1:
                return jsonify({"error": "Invalid encrypted file format", "success": False}), 400

            base64_data = content[start_idx + len(start_marker):end_idx].strip()
            encrypted_data = base64.b64decode(base64_data)
            input_stream = io.BytesIO(encrypted_data)
        else:
            file.seek(0)
            input_stream = io.BytesIO(file.read())

        input_stream.seek(0)
        output_stream = io.BytesIO()

        decrypt_stream(input_stream, output_stream, key)

        original_filename = secure_filename(file.filename)
        if original_filename.endswith('.encrypted.txt'):
            output_filename = original_filename.replace('.encrypted.txt', '')
        elif original_filename.endswith('.enc'):
            output_filename = original_filename[:-4]
        else:
            output_filename = f"{original_filename}.dec"

        return send_file(
            output_stream,
            as_attachment=True,
            download_name=output_filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return jsonify({"error": f"Decryption failed: {str(e)}", "success": False}), 400


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=5000, debug=True)
