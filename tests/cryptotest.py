from manager.crypto import encrypt, decrypt

vault = {
    "entries": [
        {
            "title": "GitHub",
            "username": "test@example.com",
            "password": "supersecret",
        }
    ]
}

password = "my-master-password"

encrypted = encrypt(vault, password)
print(encrypted.decode())

decrypted = decrypt(encrypted, password)
print(decrypted)