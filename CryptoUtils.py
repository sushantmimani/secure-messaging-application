import base64, os, binascii, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes, ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def serialize_keys(key,name, type):
    if type == "private":
        private_pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm=serialization.NoEncryption())
        file = open(name+"_private.pem", "w")
        file.write(private_pem)
        file.close()

    elif type == "public":
        public_pem = key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
        file = open(name+"_public.pem", "w")
        file.write(public_pem)
        file.close()


def keygen():
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=4096,
                                           backend=default_backend())
    public_key = private_key.public_key()

    # serialize_keys(private_key, "server","private")
    # serialize_keys(public_key, "server", "public")

    return private_key, public_key


def hashFunc(msg):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(msg)
    msg_digest = digest.finalize()
    return base64.b64encode(msg_digest)


def symmetric_encryption(self, sym_key, iv, payload, ad):
    encryptor = ciphers.Cipher(algorithms.AES(sym_key), mode=modes.GCM(iv),
                               backend=self.backend).encryptor()
    encryptor.authenticate_additional_data(ad)
    ciphertext = encryptor.update(payload) + encryptor.finalize()
    return encryptor.tag, ciphertext


def generate_key_from_password(password):
    salt = os.urandom(16)
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


def createhash():
    passwords = {}
    passwords["sushant"]=generate_password_hash("sushant", "sushant@1")
    passwords["rohit"] = generate_password_hash("rohit", "rohit@2")
    passwords["user3"] = generate_password_hash("user3", "user3@3")
    print passwords
    file = open("passwords.json","w")
    file.write(json.dumps(passwords))
    file.close()



def load_users():
    file = open("passwords.json", "r")
    data = file.read()
    print data
load_users()