from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Signature import PKCS1_v1_5 as PK
import zlib
import base64
import sys, os
from Crypto.Hash import SHA256
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from db.databaseAWSRDS import *
import time

def sign_blob(blob, private_key):
    #compress the data first
    blob = zlib.compress(blob)

    #In determining the chunk size, determine the private key length used in bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    #in chunks
    chunk_size = 86
    offset = 0
    end_loop = False
    signed =  b""

    # sign the message by using sender's private key
    signer = PK.new(RSA.importKey(private_key))
    
    while not end_loop:
        #The chunk
        chunk = blob[offset:offset + chunk_size]
        digest = SHA256.new()
        digest.update(chunk)
        
        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file
        #so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))

        #Append the encrypted chunk to the overall encrypted file
        signed += signer.sign(digest)

        #Increase the offset by chunk size
        offset += chunk_size

    print("[ The file is signed ]")

    return signed

def verify_blob(signed_blob, original, public_key):
    original = zlib.compress(original)

    #In determining the chunk size, determine the private key length used in bytes.
    #The data will be in decrypted in chunks
    chunk_size = 128
    offset = 0
    verification = True

    og_chunk_size = 86
    og_offset = 0

    verifier = PKCS115_SigScheme(RSA.importKey(public_key))

    #keep loop going as long as we have chunks to decrypt
    while offset < len(signed_blob):
        #The chunk
        chunk = signed_blob[offset: offset + chunk_size]
        #The og chunk
        og_chunk = original[og_offset:og_offset + og_chunk_size]

        hash = SHA256.new(og_chunk)
        try:
            # verify the signed message
            verifier.verify(hash, chunk)
        except:
            print("[ Signature is Invalid. ]")
            verification = False

        #Increase the offset by chunk size
        offset += chunk_size
        og_offset += og_chunk_size

    #return the decompressed decrypted data
    return verification

def encrypt_blob(blob, public_key):
    #Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    #compress the data first
    blob = zlib.compress(blob)

    #In determining the chunk size, determine the private key length used in bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    #in chunks
    chunk_size = 86
    offset = 0
    end_loop = False
    encrypted =  b""

    while not end_loop:
        #The chunk
        chunk = blob[offset:offset + chunk_size]

        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file
        #so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))

        #Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    print("[ The file is encrypted ]")
    #Base 64 encode the encrypted file
    return base64.b64encode(encrypted)

def decrypt_blob(encrypted_blob, private_key):

    #Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    #Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted_blob)

    #In determining the chunk size, determine the private key length used in bytes.
    #The data will be in decrypted in chunks
    chunk_size = 128
    offset = 0
    decrypted = b""

    #keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        #The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]

        #Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    
    #return the decompressed decrypted data
    return zlib.decompress(decrypted)

# Use RSA to generate CA's key pairs
# KeyPair = RSA.generate(bits=1024)

# privKey = KeyPair.exportKey('PEM')
# pubKey = KeyPair.publickey().exportKey('PEM')

database = DatabaseAWSRDS()
filepath = input(r'')

pubKey = database.getStudentPublicKey('alice')
privKey = database.getStudentPrivateKey('alice')

# Read the cat image file as binary
print('Original\n')
with open(filepath, 'rb') as file:
    original = file.read()
print('--------------')

# Encrypt the cat image file 
print('Encrypt\n')
encrypted_file = encrypt_blob(original, pubKey)
print('--------------')

# Save the encrypted file into the database
database.insertFile('a', 'b', '2022', 'ENCRYPTED', None, encrypted_file, None, None, 'test.jpg')
# Wait 5 seconds for saving the data
time.sleep(5)
# Get the encrypted file from the databse
files = database.getReceivedFiles('b')

# Compare two encrypted files
print(files[0][0], files[0][1])
encrypted_file2 = files[0][5]
print(encrypted_file[0:200])
print(encrypted_file2[0:200])
print('\n')
print(encrypted_file[-500:])
print(encrypted_file2[-500:])

# Decrypt
print('Decrypt\n')

# Decrypted file with original encrypted format
filepath2 = os.getcwd() + "\\og_test.jpg"
# Decrypted file with database encrypted format
filepath3 = os.getcwd() + "\\db_test.jpg"

with open(filepath2, 'wb') as file:
    decrypted = decrypt_blob(encrypted_file, privKey)
    file.write(decrypted)

with open(filepath3, 'wb') as file:
    decrypted = decrypt_blob(encrypted_file2, privKey)
    file.write(decrypted)

print("[ Encrypted file is decrypted and saved]")
# except:
#     print("[ Invalid private key ]")
print('--------------')
# signed_blob = sign_blob(original, privKey)
# verification = verify_blob(signed_blob, original, pubKey)
# print(verification)