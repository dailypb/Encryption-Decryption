""" 

Cryptography Application 
Name: Marvellous Timilehin Ojo 
Student ID: 22547636
REFERENCES:
15% From notes 
40% https://cryptography.io/en/latest/
10% https://pypi.org/project
5%  https://www.geeksforgeeks.org/security-of-rsa/
10% https://pycryptodome.readthes.io/
5%  https://pillow.readthedocs.io/en/stable/reference/Image.html
10%  https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/#:~:text=Asymmetric%20encryption%20uses%20two%20keys,key%20can%20decrypt%20the%20message.
5%  https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption

"""

import cryptography # To Import crytography module for generating, storing keys and performing RSA encryption and decryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa  # Key to generate RSA  keys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import tkinter as tk # To import files
from tkinter import filedialog #inmporting dialog for selecting and importing multiple files
import random   # for generating the random characters for generating 256bit key for the AES encryption/Decryption
import docx2txt  # used for reading and converting the .doc files
import os
import PyPDF2  # To read and convert the .pdf files 
import base64
from pycryptodome import Random
from pycryptodome.Cipher import AES  #importing AES algorithm from the crypto library
from pycryptodome.Util.Padding import pad, unpad
import io
import PIL.Image
from pycryptodome.Util.Padding import pad

BLOCK_SIZE = 32  # setting the block size of the data for AES encryption/ decryption

def generate_keys(directory, key):
    # Generating both the private and public RSA Key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    # Serializing and saving the Private Key first
    private_key_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key.encode('utf-8'))
    )
    with open(f'{directory}/private_key.pem', 'wb') as f:
        f.write(private_key_data)
    
    # Serializing and saving the Public Key 
    public_key_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f'{directory}/public_key.pem', 'wb') as f:
        f.write(public_key_data)

def load_private_key(directory, key):
        #### Reading and Loading the Keys from these files....
    with open(f"{directory}/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=key.encode('utf-8'),
                backend=default_backend()
                )

    return private_key
#Loading the private key from a given folder and key
def load_public_key(directory):
        ## loading the public key....    
    with open(f"{directory}/public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
                )  
    return public_key



#Function for adding padding bits during AES encryption
def pad_bits(data):
# Calculating the number of padding bits required
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
# Adding the padding bits to the data
    padded_data = data + (padding * chr(padding))
    return padded_data


#Function for removing padding bits during AES decryption
def remove_pad(data):
    return data[:-ord(data[len(data)-1:])]


def encrypt_data(pub_key, plaintext):
# Generating a random key and initialization vector
    key = os.urandom(16)
    iv = Random.new().read(AES.block_size)
# Creating a cipher object for encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
# Encrypting the key using the public key
    encrypted_key = encrypt_with_public_key(pub_key, key)
# Encoding the initialization vector and encrypted data
    encoded = base64.b64encode(iv + cipher.encrypt(pad(plaintext.encode(), BLOCK_SIZE)))
    return encrypted_key, encoded



def encrypt_using_key(encryption_key, plaintext):
# Generating a random initialization vector
    iv = Random.new().read(AES.block_size)
# Creating a cipher object for encryption
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
# Encoding the initialization vector and encrypted data
    encoded = base64.b64encode(iv + cipher.encrypt(pad(plaintext.encode(), BLOCK_SIZE)))
    return encoded


def encrypt_img(pub_key, image):
    # Adding padding to the image data
    image = pad(image, BLOCK_SIZE)
    # Generating a random key and initialization vector
    key = os.urandom(16)
    iv = Random.new().read(AES.block_size)
    # Creating a cipher object for encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Encoding the initialization vector and encrypted image
    encoded = base64.b64encode(iv + cipher.encrypt(image))
    # Encrypting the key using the public key
    encrypted_key = encrypt_with_public_key(pub_key, key)
    return encrypted_key, encoded




def encrypt_with_public_key(public_key, key):
    # Using OAEP padding with SHA256 hash algorithm
    ciphertext = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext



def decrypt_data(decryption_key, encoded_data):
    # Decoding the encoded data
    encoded_data = base64.b64decode(encoded_data)
    # Extracting the initialization vector
    iv = encoded_data[:AES.block_size]
    # Creating a cipher object for decryption
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv)
    # Removing padding from the decrypted data
    plaintext = remove_pad(cipher.decrypt(encoded_data[AES.block_size:])).decode('utf-8')
    # Saving the decrypted data to a file
    with open(f"{directory}/decrypted/{file_name}", 'w') as cipher_file:
            cipher_file.write(plaintext)
    return plaintext


def decrypt_using_key(decryption_key, encoded_data):
    # Decoding the encoded data
    encoded_data = base64.b64decode(encoded_data)
    # Extracting the initialization vector
    iv = encoded_data[:AES.block_size]
    # Creating a cipher object for decryption
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv)
    # Removing padding from the decrypted data
    plaintext = remove_pad(cipher.decrypt(encoded_data[AES.block_size:])).decode('utf-8')
    # Saving the decrypted data to a file
    with open(f"{directory}/decrypted/{file_name}", 'w') as cipher_file:
        cipher_file.write(plaintext)
    return plaintext


def decrypt_image(key, enc):
    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = cipher.decrypt(enc[AES.block_size:])
    # with open(f"{directory}/decrypted/{file_name}", 'w') as cipher_file:
    #     cipher_file.write(plain_text)

    imageStream = io.BytesIO(plain_text)
    imageFile = PIL.Image.open(imageStream)
    imageFile.save(file_name)

    im = PIL.Image.open(file_name)
    im.show()
    return plain_text



def decrypt_with_private_key(private_key, ciphertext):
    # Using OAEP padding with SHA256 hash algorithm
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


if __name__ == '__main__':
    print("Hello, Choose an operation to perform")
    while True:
        
        print("\t1. Create new user")
        print("\t2. Encrypt")
        print("\t3. Decrypt")
        print("\tq. Exit")

        choice = input("Enter choice operation: ")
        if choice == '1':
            while True:
                directory = input("Enter new username: ") # To create user account
                
                if not os.path.exists(directory):
                    os.makedirs(directory)
                    os.makedirs(f"{directory}/encrypted")
                    os.makedirs(f"{directory}/decrypted")
                    break
                else:
                    print("User already exists, Select new username")

            while True:
                key = input("Enter passphrase.\nThis will be used to sign your private key: ")
                if len(key) >= 1:
                    break
                else:
                    print("Enter valid passphrase")

            generate_keys(directory, key) # Generating the keys for the user

            print("keys generated successfully!")


        elif choice == '2':
            
            while True:
                try:
                    directory = input("Enter username: ")
                    key = input("Enter passphrase: ")
                    private_key = load_private_key(directory, key)
                    break

                except ValueError:
                    print("Incorrect username or passphrase") # Authenticating the user

            while True:
                print("1. Encrypt text")
                print("2. Encrypt file(s)")
                print("3. Encrypt an image")
                print("4. Back to Menu")

                choice = input("input choice operation: ") # Choosing operation to perform

                if choice == '4':
                    break

                elif choice not in ['1', '2', '3']:
                    print("Invalid choice")
                    continue

                while True:
                    directory = input("Enter username of recipent: ")
                    if os.path.exists(directory):
                        break
                    else:
                        print("User does not exist. Enter correct username") # user authentication

                public_key = load_public_key(directory)

                if choice == '1':
                    text = input("Enter your text: ")
                    file_name = input("Enter file name to store encrypted text: ")
                    encrypted_key, cipher = encrypt_data(public_key, text) # encrypting the data
                    print("Text encryption successful")
                    print(cipher)

                     # Digital signature of data
                    signature = private_key.sign(
                        cipher,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    print("Signed successfully")
                    print(signature)

                    with open(f"{directory}/encrypted/{file_name}", 'wb') as cipher_file:
                        cipher_file.write(b"START OF SIGNATURE\n")
                        cipher_file.write(signature)
                        cipher_file.write(b"\nEND OF SIGNATURE\n")
                        cipher_file.write(b"START OF ENCRYPTED KEY\n")
                        cipher_file.write(encrypted_key)
                        cipher_file.write(b"\nEND OF ENCRYPTED KEY\n")
                        cipher_file.write(cipher)
                        
                    

                elif choice == '2':
                    print("Select file")
                    root = tk.Tk()
                    root.withdraw()
                    root.call('wm', 'attributes', '.', '-topmost', True)
                    files = filedialog.askopenfilename(multiple=True) # Selecting file for encryption
                    var = root.tk.splitlist(files)
                    print("Files selected successfully")

                    for f in var:
                        file_name, extension = os.path.splitext(f)

                        if extension == ".txt":
                            with open(f, 'r') as file:
                                text = file.read()

                        elif extension==".docx":
                            text = docx2txt.process(f) #reading and encoding the data of word file

                        elif extension==".pdf":
                            pdfFileObj = open(f, 'rb')  # creating a pdf file object
                            pdfReader = PyPDF2.PdfFileReader(pdfFileObj) # creating a pdf reader object
                            pageObj = pdfReader.getPage(0) # creating a page object 
                            text = pageObj.extractText() # extracting text from page
                            pdfFileObj.close() # closing the pdf file object

                        else:
                            print("Select file to encrypt")
                            continue

                        file_name = file_name.split("/")[-1] + ".txt"
                        encrypted_key, cipher = encrypt_data(public_key, text) # To encrypt the data
                        print("File encryption successful")
                        print(cipher)

                        signature = private_key.sign(
                            cipher,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        print("Signed successfully")
                        print(signature)

                        with open(f"{directory}/encrypted/{file_name}", 'wb') as cipher_file:
                            cipher_file.write(b"START OF SIGNATURE\n")
                            cipher_file.write(signature)
                            cipher_file.write(b"\nEND OF SIGNATURE\n")
                            cipher_file.write(b"START OF ENCRYPTED KEY\n")
                            cipher_file.write(encrypted_key)
                            cipher_file.write(b"\nEND OF ENCRYPTED KEY\n")
                            cipher_file.write(cipher)

                elif choice == '3':
                    print("Select images only")
                    root = tk.Tk()
                    root.withdraw()
                    root.call('wm', 'attributes', '.', '-topmost', True)
                    files = filedialog.askopenfilename(multiple=True) # user selection of file they wish to encrypt
                    var = root.tk.splitlist(files)
                    print("Files selected successfully")

                    for f in var:
                        with open(f, 'rb') as file:
                            image = file.read()
                        
                        file_name = f.split("/")[-1]
                        encrypted_key, cipher = encrypt_img(public_key, image) # To encrypt image
                        print("Image encrypted successfully")
                        print(cipher)
                       # Digital signature of image
                        signature = private_key.sign(
                            cipher,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        print("Signed successfully") # confirmation of signature
                        print(signature)

                        with open(f"{directory}/encrypted/{file_name}", 'wb') as cipher_file:
                            cipher_file.write(b"START OF SIGNATURE\n")
                            cipher_file.write(signature)
                            cipher_file.write(b"\nEND OF SIGNATURE\n")
                            cipher_file.write(b"START OF ENCRYPTED KEY\n")
                            cipher_file.write(encrypted_key)
                            cipher_file.write(b"\nEND OF ENCRYPTED KEY\n")
                            cipher_file.write(cipher)
                
        elif choice == '3':
            while True:
                try:
                    directory = input("Enter your username: ")
                    key = input("Enter your passphrase: ")
                    private_key = load_private_key(directory, key)
                    break

                except ValueError:
                    print("Incorrect username or passphrase")

            while True:
                print("1. Decrypt a file") # selecting operation to be performed
                print("2. Decrypt image")
                print("3. Back to menu")

                choice = input("Select your choice: ")

                if choice == '1':
                    print("Files available for decryption: ") # to display list of encrypted files available for decryption
                    for file in os.listdir(f"{directory}/encrypted"):
                        print(file)

                    file_name = input("Enter cipher text file path: ") # user specifies the file for decryption
                    key = b''
                    signature = b''
                    with open(f"{directory}/encrypted/{file_name}", 'rb') as cipher_file:
                        line = cipher_file.readline()
                        for line in cipher_file:
                            if line.decode('utf-8', "ignore").strip() == 'END OF SIGNATURE':
                                line.decode('utf-8', "ignore").strip()
                                break
                            else:
                                signature += line

                        line = cipher_file.readline()
                        for line in cipher_file:
                            if line.decode('utf-8', "ignore").strip() == 'END OF ENCRYPTED KEY':
                                line.decode('utf-8', "ignore").strip()
                                break
                            else:
                                key += line

                        text = cipher_file.read()

                    
                    key = key[:-1]
                    signature = signature[:-1]

                    while True:
                        user_name = input("Enter username of sender: ") # verification of sender
                        if os.path.exists(user_name):
                            break
                        else:
                            print("User not found, Enter correct username")

            # loading the sender public key and verifying signature
                    public_key = load_public_key(user_name) 

                    try:
                        public_key.verify(
                            signature,
                            text,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )

                        print(f"The signature of {file_name} is valid")

                    except cryptography.exceptions.InvalidSignature:
                        print("The signature is not valid")
                        continue

                    

                    key = decrypt_with_private_key(private_key, key) # decrypt the key
                    plain_text = decrypt_data(key, text)

                    print("\nDecrypted Message")
                    print(plain_text) 
                    print()

                elif choice == '2':

                    while True:
                        user_name = input("Enter username of sender: ") # Validats the sender
                        if os.path.exists(user_name):
                            break
                        else:
                            print("User not found, Enter correct username")

                    public_key = load_public_key(user_name) # loading the public key

                    print("Select images only") # selecting the image to decrypt
                    root = tk.Tk()
                    root.withdraw()
                    root.call('wm', 'attributes', '.', '-topmost', True)
                    files = filedialog.askopenfilename(multiple=False) 
                    var = root.tk.splitlist(files)
                    print("Files selected successfully")
                    key = b''
                    signature = b''

                    for file_name in var:
                        with open(file_name, 'rb') as cipher_file:
                            line = cipher_file.readline()
                            for line in cipher_file:
                                if line.decode('utf-8', "ignore").strip() == 'END OF SIGNATURE':
                                    line.decode('utf-8', "ignore").strip()
                                    break
                                else:
                                    signature += line

                            line = cipher_file.readline()
                            for line in cipher_file:
                                if line.decode('utf-8', "ignore").strip() == 'END OF ENCRYPTED KEY':
                                    line.decode('utf-8', "ignore").strip()
                                    break
                                else:
                                    key += line

                            text = cipher_file.read()

                        
                        key = key[:-1]
                        signature = signature[:-1]

                        try:
                            public_key.verify( # verifying the signature of sender
                                signature,
                                text,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256()
                            )

                            print(f"The signature of {file_name} is valid")

                        except cryptography.exceptions.InvalidSignature:
                            print("The signature is not valid")
                            continue
                            
                        file_name = file_name.split('/')[-1]
                        file_name = f"{directory}/decrypted/{file_name}" 
                        print(file_name)
                        key = decrypt_with_private_key(private_key, key) # decryption of key
                        print(key)
                        plain_text = decrypt_image(key, text) # decryption of image

                        print("\nDecrypted Image")


                elif choice == '3':
                    break
        
        elif choice == 'q':
            break

        else:
            print("Invalid choice")


                    

