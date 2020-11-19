from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from util.constants import AES_KEY_SIZE, NONCE_SIZE
def encrypt_aes_gcm_128(msg, encryption_key):
    nonce = get_random_bytes(NONCE_SIZE)
    aesCipher = AES.new(encryption_key[:AES_KEY_SIZE], AES.MODE_GCM, nonce=nonce)
    ciphertext, mac = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, nonce, mac)
def decrypt_aes_gcm_128(ciphertext, nonce, tag, decryption_key):
    decryption_key= decryption_key[:AES_KEY_SIZE]
    aesCipher = AES.new(decryption_key, AES.MODE_GCM, nonce=nonce)
    return aesCipher.decrypt_and_verify(ciphertext, tag)
