# Импортируем Flask для создания сервера
from flask import Flask, request, jsonify

# Импортируем инструменты для криптографии (хеш, ключи, подпись)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Создаём объект сервера
app = Flask(__name__)


# Генерация ключей сервера


# Закрытый ключ (секретный, хранится только на сервере)
server_private_key = rsa.generate_private_key(
    public_exponent=65537,  # стандартное значение
    key_size=2048           # длина ключа
)

# Открытый ключ (можно передавать клиенту)
server_public_key = server_private_key.public_key()

# Сценарий 1: Проверка подписи клиента
@app.route("/verify", methods=["POST"])
def verify():

    # Получаем JSON от клиента
    data = request.json

    # Извлекаем сообщение и переводим в байты
    message = data["message"].encode()

    # Получаем подпись и переводим из строки hex в байты
    signature = bytes.fromhex(data["signature"])

    # Загружаем публичный ключ клиента из строки
    client_public_key = serialization.load_pem_public_key(
        data["public_key"].encode()
    )

    try:
        # Проверяем подпись
        client_public_key.verify(
            signature,           # подпись
            message,             # сообщение
            padding.PKCS1v15(),  # схема подписи
            hashes.SHA256()      # алгоритм хеширования
        )

        # Если подпись верная то..
        return jsonify({"status": "valid"})

    except:
        # Если ошибка проверки
        return jsonify({"status": "invalid"})

# Сценарий 2: Сервер подписывает сообщение
@app.route("/sign", methods=["GET"])
def sign():

    # Создаём сообщение
    message = "Hello from server"

    # Подписываем сообщение закрытым ключом сервера
    signature = server_private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Возвращаем сообщение и подпись клиенту
    return jsonify({
        "message": message,
        "signature": signature.hex()
    })

# Отправка публичного ключа сервера
@app.route("/public_key", methods=["GET"])
def get_public_key():

    # Преобразуем ключ в текстовый формат (PEM)
    public_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return jsonify({"public_key": public_pem})


#Запуск сервера

if __name__ == "__main__":
    app.run(debug=True)