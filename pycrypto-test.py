from tkinter import *
# AES 256 encryption/decryption using pycrypto library
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

#password = input("Enter encryption password: ")
password = "17"

def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


def encryptMessage():
    pt = e1.get()
    ct = encrypt(pt, password)
    e2.insert(0, ct)

def decryptMessage():
    ct1 = e3.get()
    pt1 = decrypt(ct1, password)
    e4.insert(0, pt1)

# creating labels and positioning them on the grid
root = Tk()
root.title("CRYPTOGRAPHY")
root.geometry("800x600")

obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')

label1 = Label(root, text ='plain text')
label1.grid(row = 10, column = 1)
label2 = Label(root, text ='encrypted text')
label2.grid(row = 11, column = 1)
l3 = Label(root, text ="cipher text")
l3.grid(row = 10, column = 10)
l4 = Label(root, text ="decrypted text")
l4.grid(row = 11, column = 10)

# creating entries and positioning them on the grid
e1 = Entry(root)
e1.grid(row = 10, column = 2)
e2 = Entry(root)
e2.grid(row = 11, column = 2)
e3 = Entry(root)
e3.grid(row = 10, column = 11)
e4 = Entry(root)
e4.grid(row = 11, column = 11)

# creating encryption button to produce the output
ent = Button(root, text = "encrypt", bg ="red", fg ="white", command = encryptMessage)
ent.grid(row = 13, column = 2)

# creating decryption button to produce the output
b2 = Button(root, text = "decrypt", bg ="green", fg ="white", command = decryptMessage)
b2.grid(row = 13, column = 11)


root.mainloop()
