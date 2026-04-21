from flask import Flask, request, jsonify

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

app = Flask(__name__)

server_private_key = rsa.generate_private_key(
    public_exponent=65537,  
    key_size=2048          

server_public_key = server_private_key.public_key()

# Сценарий 1 - Проверка подписи клиента
@app.route("/verify", methods=["POST"])
def verify():

       data = request.json

    message = data["message"].encode()

    signature = bytes.fromhex(data["signature"])

        client_public_key = serialization.load_pem_public_key(
        data["public_key"].encode()
    )

    try:
            client_public_key.verify(
            signature,           
            message,             
            padding.PKCS1v15(),  
            hashes.SHA256()      
        )

        return jsonify({"status": "valid"})

    except:
        return jsonify({"status": "invalid"})


# Сценарий 2 - Сервер подписывает сообщение
@app.route("/sign", methods=["GET"])
def sign():

    message = "Hello from server"

        signature = server_private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

      return jsonify({
        "message": message,
        "signature": signature.hex()
    })

@app.route("/public_key", methods=["GET"])
def get_public_key():

        public_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return jsonify({"public_key": public_pem})


if __name__ == "__main__":
    app.run(debug=True)