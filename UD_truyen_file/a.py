from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import hashlib

app = Flask(__name__)

# Tải khóa công khai
with open('public.pem', 'r') as f:
    public_key = RSA.import_key(f.read())

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']
    signature = request.form['signature'].encode()

    file_data = file.read()

    # Xác thực chữ ký
    try:
        pkcs1_15.new(public_key).verify(hashlib.sha256(file_data), signature)
        with open('received_file.txt', 'wb') as f:
            f.write(file_data)
        return jsonify({'message': 'File uploaded and verified successfully!'}), 200
    except (ValueError, TypeError):
        return jsonify({'message': 'Invalid signature!'}), 403

if __name__ == '__main__':
    app.run(debug=True)