import base64, os, binascii, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def serialize_public_key(key):
    public_pem = key.public_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # file = open(name + "_public.pem", "w")
    # file.write(public_pem)
    # file.close()
    return public_pem


def serialize_private_key(key, name):
    private_pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption())
    file = open(name + "_private.pem", "w")
    file.write(private_pem)
    file.close()
    return private_pem


def keygen():
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=4096,
                                           backend=default_backend())
    
    public_key = private_key.public_key()

    return private_key, public_key


def create_hash(msg):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(msg)
    msg_digest = digest.finalize()
    return base64.b64encode(msg_digest)


def symmetric_encryption(sym_key, message):
    iv = os.urandom(96)
    encryptor = Cipher(algorithms.AES(sym_key), mode=modes.GCM(iv),
                       backend=default_backend()).encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag


def symmetric_decryption(sym_key, iv, tag, message):
    decryptor = Cipher(algorithms.AES(sym_key), mode=modes.GCM(iv, tag),
                       backend=default_backend()).decryptor()
    plaintext = decryptor.update(message) + decryptor.finalize()
    return plaintext


def generate_key_from_password(password, salt):
    kdf = Scrypt(salt=salt,
                 length=32,
                 n=2 ** 14,
                 r=8,
                 p=1,
                 backend=default_backend())
    key = kdf.derive(password)
    return key


def generate_password_hash(username, password):
    hash = hashes.Hash(hashes.SHA512(), default_backend())
    hash.update(username + password)
    salt = hash.finalize()
    kdf = Scrypt(salt=salt,
                 length=32,
                 n=2 ** 14,
                 r=8,
                 p=1,
                 backend=default_backend())

    password_hash = kdf.derive(password)
    return binascii.hexlify(password_hash)


def create_password_hash():
    passwords = {"sushant": generate_password_hash("sushant", "sushant@1"),
                 "rohit": generate_password_hash("rohit", "rohit@2"),
                 "user3": generate_password_hash("user3", "user3@3")}
    file = open("passwords.json", "w")
    file.write(json.dumps(passwords))
    file.close()




def load_users():
    file = open("passwords.json", "r")
    data = json.loads(file.read())
    file.close()
    return data


def load_public_key(key):
    with open(key, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


def load_private_key(key):
    with open(key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def asymmetric_encryption(key, message):
    encrypted_message = key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


def asymmetric_decryption(key, message):
    decrypted_message = key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_message


def sign_message(key, message):
    if type(key) == str:
        pvt_key = load_private_key(key)
    else:
        pvt_key = key
    signature = pvt_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(key, sign, message):
    if type(key)== str:
        pub_key = load_public_key(key)
    else:
        pub_key = key
    try:
        signature = pub_key.verify(sign,
                                   message, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
                                   hashes.SHA256()
                                   )
        return "VERIFIED"
    except:
        return "FAIL"

# signature = sign_message("sushant_private.pem", "hi")
# valid = verify_signature("sushant_public.pem", signature, "hi")
# print valid