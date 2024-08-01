from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt(plain_text, key):
    iv = get_random_bytes(16) #salting
    cipher = AES.new(key, AES.MODE_CFB, iv) #initializing the cipher
    encrypted_text = cipher.encrypt(plain_text.encode('utf-8')) #encrypting the plain text (utf-8 turns the plain text into byte format)
    encoded = base64.b64encode(iv + encrypted_text).decode('utf-8') #encode into base64 which enables easy transmission in byte format
    return encoded

def decrypt(encoded, key):
    decoded = base64.b64decode(encoded)
    iv = decoded[:16] #objectifying the first 16 bytes of encrypted text
    encrypted_text = decoded[16:] #objectifying the last 16 bytes
    cipher = AES.new(key, AES.MODE_CFB, iv) #initializing the decipher 
    plain_text = cipher.decrypt(encrypted_text).decode('utf-8') #decrypt the encrypted text, then decode from utf-8 format to plain text
    return plain_text

def main():
    Pinapple = input("Please enter what you'd like to encrypt: ")
    key = get_random_bytes(16) #generates a random 16bit key 
    encrypted_message = encrypt(Pinapple,key) #utilizes our encrypt and decrypt functions
    decrypted_message = decrypt(encrypted_message, key)
    print(f"This is your encrypted message: {encrypted_message}") #print our plain and encrypted text
    print(f"This is your dencrypted message: {decrypted_message}")

if __name__== "__main__" :
    main()



