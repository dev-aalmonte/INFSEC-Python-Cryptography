from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

data = "Hello World!"

sender_private_key = RSA.generate(2048)
sender_public_key = sender_private_key.public_key()

receiver_private_key = RSA.generate(2048)
receiver_public_key = receiver_private_key.public_key()

print("Hello")
print("Hello World")
print("Bye")

# this is a comment by Dang!
