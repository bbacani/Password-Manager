from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA512
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import sys

li = []
salt_li = []


# Creates empty files for saving data.
def create_files():
    file = open("cipher.txt", "w")
    file.close()

    file = open("salt.txt", "w")
    file.close()


# Opens files and stores its content to lists.
def open_files():
    with open("cipher.txt", "r") as a_file:
        for line in a_file:
            li.append(line.strip())

    with open("salt.txt", "r") as a_file:
        for line in a_file:
            salt_li.append(line.strip())


# Saves updated data to files.
def save_files():
    new_li = [x + "\n" for x in li]
    new_salt_li = [x + "\n" for x in salt_li]

    file = open("cipher.txt", "w")
    file.writelines(new_li)
    file.close()

    file = open("salt.txt", "w")
    file.writelines(new_salt_li)
    file.close()


# Checks if address is already saved.
def check(master_password, address):
    open_files()
    # Iterates through each salt.
    for salt in salt_li:
        # Generates 64 byte derived key from master password and address along with salt.
        # It carries out 1000000 iterations and uses HMAC-SHA512 as a pseudorandom function.
        keys = PBKDF2(master_password + address, bytes.fromhex(salt), dkLen=64, count=1000000, hmac_hash_module=SHA512)
        for el in li:
            # Creates new AES-GCM cipher to encrypt address.
            cipher = AES.new(keys[:32], AES.MODE_GCM, nonce=bytes.fromhex(salt))
            # Padding
            data = pad(address.encode(), AES.block_size)
            # Encrypts data and generates digest.
            ciphertext, tag = cipher.encrypt_and_digest(data)
            # If address already exists, removes it, its password and its salt.
            if el == ciphertext.hex():
                # Removes password tag
                li.remove(li[li.index(ciphertext.hex()) + 2])
                # Removes password
                li.remove(li[li.index(tag.hex()) + 1])
                # Removes address
                li.remove(ciphertext.hex())
                # Removes address tag
                li.remove(tag.hex())
                # Removes salt
                salt_li.remove(salt)


# Encryption
def put(master_password, address, password):
    check(master_password, address)

    # Generates random 16 bytes for salt.
    salt = get_random_bytes(16)
    # Appends salt to list.
    salt_li.append(salt.hex())
    # Generates 64 byte derived key from master password and address along with salt.
    # It carries out 1000000 iterations and uses HMAC-SHA512 as a pseudorandom function.
    keys = PBKDF2(master_password + address, salt, dkLen=64, count=1000000, hmac_hash_module=SHA512)

    # Creates new AES-GCM cipher to encrypt address.
    cipher = AES.new(keys[:32], AES.MODE_GCM, nonce=salt)
    # Encrypts data and generates digest.
    ciphertext, tag = cipher.encrypt_and_digest(pad(address.encode(), AES.block_size))
    # Appends address ciphertext to list.
    li.append(ciphertext.hex())
    # Appends address tag to list.
    li.append(tag.hex())

    # Creates new AES-GCM cipher to encrypt password.
    cipher = AES.new(keys[32:], AES.MODE_GCM, nonce=salt)
    # Encrypts data and generates digest.
    ciphertext, tag = cipher.encrypt_and_digest(pad(password.encode(), AES.block_size))
    # Appends password ciphertext to list.
    li.append(ciphertext.hex())
    # Appends password tag to list.
    li.append(tag.hex())

    save_files()


# Decryption
def get(master_password, address):
    open_files()
    # Iterates through each salt.
    for salt in salt_li:
        # Generates 64 byte derived key from master password and address along with salt.
        # It carries out 1000000 iterations and uses HMAC-SHA512 as a pseudorandom function.
        keys = PBKDF2(master_password + address, bytes.fromhex(salt), dkLen=64, count=1000000, hmac_hash_module=SHA512)
        # Iterates through each ciphertext.
        for el in li:
            # Returns plaintext form ciphertext or continues to next if it fails.
            try:
                # Creates new AES-GCM cipher to encrypt address.
                cipher = AES.new(keys[32:], AES.MODE_GCM, nonce=bytes.fromhex(salt))
                # Decrypts data and verifies digest.
                data = cipher.decrypt_and_verify(bytes.fromhex(el), bytes.fromhex(li[li.index(el) - len(li) + 1]))
                # Unpadding
                plaintext = unpad(data, AES.block_size)
                return str(plaintext.decode())
            except ValueError:
                continue
    # Returns false if password isn't set or if integrity is violated.
    return False


# Reading arguments
if sys.argv[1] == 'init':
    create_files()
    print("Password manager initialized.")
elif sys.argv[1] == 'put':
    put(sys.argv[2], sys.argv[3], sys.argv[4])
    print("Stored password for " + sys.argv[3])
elif sys.argv[1] == 'get':
    result = get(sys.argv[2], sys.argv[3])
    print("Data breach.") if result is False else print("Password for " + sys.argv[2] + " is: " + result)
else:
    print("Command doesn't exist.")
