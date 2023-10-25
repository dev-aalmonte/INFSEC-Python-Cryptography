from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from os import urandom, path
from sys import argv
import base64

# Params

if len(argv) != 5 or (argv[1] != "--encrypt" and argv[1] != "--decrypt"):
    print("Usage: fcrypt.py --encrypt <receiver-public-key> <plaintext-file> <encrypted-file>")
    print("       fcrypt.py --decrypt <receiver-private-key> <encrypted-file> <decrypted-file>")
    exit(1)

read_file_name = argv[3]
write_file_name = argv[4]

if not path.isfile(read_file_name):
    print(f"Error: could not find file {read_file_name}")
    exit(1)

# Setup
data = b""

with open(read_file_name, "rb") as read_file_fp:
    data = read_file_fp.read()

# Generate key object

param_key = RSA.import_key(
            base64.b64decode(
            argv[2].replace("-----BEGIN RSA PRIVATE KEY-----", "")\
                   .replace("-----END RSA PRIVATE KEY-----", "")\
                   .replace("-----BEGIN PUBLIC KEY-----", "")\
                   .replace("-----END PUBLIC KEY-----", "")\
                   .replace("\n", "")
))

if argv[1] == "--encrypt":
    key = urandom(16)
    # Data Encryption
    # use "key" to encript "data"
    aes_encript_object = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = aes_encript_object.encrypt_and_digest(data)
    nonce = aes_encript_object.nonce

    # Key Encription
    rsa_encrypt_object = PKCS1_OAEP.new(param_key)
    key_ciphertext = rsa_encrypt_object.encrypt(key)

    # Message Concatenation
    concentrated_message = b"" + ciphertext + b"\n|---|\n" + tag + b"\n|---|\n" + nonce + b"\n|---|\n" + key_ciphertext
    # print("During Encryption / Decryption Process")
    # print(concentrated_message)

    with open(write_file_name, "bw") as wfp:
        wfp.write(concentrated_message)

elif argv[1] == "--decrypt":

    # Message De-Concatenation
    separated_message = data.split(b"\n|---|\n")
    ciphertext = separated_message[0]
    tag = separated_message[1]
    nonce = separated_message[2]
    key_ciphertext = separated_message[3]

    # Key Dencryption
    rsa_decrypt_object = PKCS1_OAEP.new(param_key)
    decrypted_key = rsa_decrypt_object.decrypt(key_ciphertext)

    # Message Decryption
    aes_decrypt_object = AES.new(decrypted_key, AES.MODE_GCM, nonce=nonce)
    decrypted_message = aes_decrypt_object.decrypt_and_verify(ciphertext, tag)

    # print("After Encryption / Decryption Process")
    # print(decrypted_message)

    with open(write_file_name, "wb") as wfp:
        wfp.write(decrypted_message)
