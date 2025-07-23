from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import base64

# Step 1: Generate RSA key pair
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

# Step 2: Generate AES key
aes_key = get_random_bytes(16)

# Step 3: Encrypt AES key using RSA public key
rsa_cipher = PKCS1_OAEP.new(public_key)
encrypted_aes_key = rsa_cipher.encrypt(aes_key)

# Step 4: Encrypt a message using AES
message = b"Secure Communication Using Cryptography"
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)
nonce = cipher_aes.nonce  # Save nonce for decryption

# Step 5: Sign the original message using RSA private key
hash_msg = SHA256.new(message)
signature = pkcs1_15.new(private_key).sign(hash_msg)

# Transmit these values
print("Encrypted AES key:", base64.b64encode(encrypted_aes_key).decode())
print("AES Encrypted message:", base64.b64encode(ciphertext).decode())
print("AES Nonce:", base64.b64encode(nonce).decode())
print("Digital Signature:", base64.b64encode(signature).decode())

# Step 6: Decryption (Simulating receiver side)

# Decrypt AES key using RSA private key
rsa_dec_cipher = PKCS1_OAEP.new(private_key)
decrypted_aes_key = rsa_dec_cipher.decrypt(encrypted_aes_key)

# Decrypt message using AES
cipher_aes_dec = AES.new(decrypted_aes_key, AES.MODE_EAX, nonce=nonce)
decrypted_message = cipher_aes_dec.decrypt(ciphertext)

# Verify digital signature
hash_dec = SHA256.new(decrypted_message)
try:
    pkcs1_15.new(public_key).verify(hash_dec, signature)
    print("Signature is valid. Message:", decrypted_message.decode())
except (ValueError, TypeError):
    print("Signature is invalid.")