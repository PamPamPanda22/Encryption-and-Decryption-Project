from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt(plain_text, key):
    iv = get_random_bytes(16) #salting
    cipher = AES.new(key, AES.MODE_CFB, iv) #initializing the cipher
    encrypted_text = cipher.encrypt(plain_text.encode('utf-8')) #encrypting the plain text (utf-8 turns it into byte format)
    encoded = base64.b64encode(iv + encrypted_text).decode('utf-8') #encode into base64 which also makes sure its in byte format plus easy transmission
    return encoded

def decrypt(encoded, key):
    decoded = base64.b64decode(encoded)
    iv = decoded[:16] #objectifying the first 16 bytes
    encrypted_text = decoded[16:] #objectifying the last 16 bytes
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plain_text = cipher.decrypt(encrypted_text).decode('utf-8')
    return plain_text

def main():
    Pinapple = input("Please enter what you'd like to encrypt: ")
    key = get_random_bytes(16) 
    encrypted_message = encrypt(Pinapple,key)
    decrypted_message = decrypt(encrypted_message, key)
    print(f"This is your encrypted message: {encrypted_message}")
    print(f"This is your dencrypted message: {decrypted_message}")

if __name__== "__main__" :
    main()



