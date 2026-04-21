import requests

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

BASE_URL = "http://127.0.0.1:5000"

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

def scenario1():

    message = input("Message: ")

    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    r = requests.post(BASE_URL + "/verify", json={
        "message": message,
        "signature": signature.hex(),
        "public_key": public_pem
    })

    print("Server verification:", r.json())

def scenario2():
    r = requests.get(BASE_URL + "/public_key")
    server_public_key = serialization.load_pem_public_key(
        r.json()["public_key"].encode()
    )

    r = requests.get(BASE_URL + "/sign")
    data = r.json()

    message = data["message"]
    signature = bytes.fromhex(data["signature"])

    try:
        server_public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        print("Valid signature")

    except:
        print("Invalid signature")


#  Меню
while True:
    print("\n1. Client sign")
    print("2. Server sign")
    print("3. Exit")

    choice = input("> ")

    if choice == "1":
        scenario1()
    elif choice == "2":
        scenario2()
    elif choice == "3":
        break