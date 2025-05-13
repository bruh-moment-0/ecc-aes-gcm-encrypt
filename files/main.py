import os
import json
import time
import base64
import secrets
import string
import logging
import threading
from tkinter import Tk, Menu, Frame, Label, Button, BooleanVar, StringVar, filedialog, messagebox, simpledialog, WORD, CHAR, PhotoImage, scrolledtext, END, Entry, Checkbutton
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
KDF_ITERATIONS = 100_000
KEY_LENGTH = 32
IV_LENGTH = 16
SALT_LENGTH = 16
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    logging.info("BASE_DIR set to %s", BASE_DIR)
except NameError:
    BASE_DIR = os.getcwd()
    logging.info("BASE_DIR set to current working directory: %s", BASE_DIR)
def encryptAESCBC(data: str, password: str) -> tuple:
    logging.info("Entered encryptAESCBC with data length: %d", len(data))
    try:
        salt = get_random_bytes(SALT_LENGTH)
        iv = get_random_bytes(IV_LENGTH)
        key = PBKDF2(password, salt, dkLen=KEY_LENGTH, count=KDF_ITERATIONS)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad_length = AES.block_size - len(data) % AES.block_size
        padded_data = data + pad_length * chr(pad_length)
        ciphertext = cipher.encrypt(padded_data.encode())
        result = (base64.b64encode(ciphertext).decode(), base64.b64encode(salt).decode(), base64.b64encode(iv).decode())
        logging.info("encryptAESCBC successful")
        return result
    except Exception as e:
        logging.error("Error in encryptAESCBC: %s", e)
        raise
def decryptAESCBC(ciphertext_b64: str, password: str, salt_b64: str, iv_b64: str) -> str:
    logging.info("Entered decryptAESCBC")
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        salt = base64.b64decode(salt_b64)
        iv = base64.b64decode(iv_b64)
        key = PBKDF2(password, salt, dkLen=KEY_LENGTH, count=KDF_ITERATIONS)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext).decode()
        pad_length = ord(decrypted_data[-1])
        result = decrypted_data[:-pad_length]
        logging.info("decryptAESCBC successful")
        return result
    except Exception as e:
        logging.error("Error in decryptAESCBC: %s", e)
        raise
def encdeckey(private_key_str: str, public_key_str: str) -> tuple:
    logging.info("Entered encdeckey")
    try:
        private_key_obj = serialization.load_pem_private_key(private_key_str.encode('utf-8'), password=None)
        public_key_obj = serialization.load_pem_public_key(public_key_str.encode('utf-8'))
        logging.info("encdeckey successful")
        return private_key_obj, public_key_obj
    except Exception as e:
        logging.error("Error in encdeckey: %s", e)
        raise
def encrypt(private_key, public_key, message: str) -> str:
    logging.info("Entered encrypt with message length: %d", len(message))
    try:
        salt = secrets.token_bytes(16)
        shared_secret = private_key.exchange(ec.ECDH(), public_key)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        symmetric_key = kdf.derive(shared_secret)
        nonce = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        encrypted_data = salt + nonce + ciphertext + encryptor.tag
        result = base64.b64encode(encrypted_data).decode('utf-8')
        logging.info("encrypt successful")
        return result
    except Exception as e:
        logging.error("Error in encrypt: %s", e)
        raise
def decrypt(private_key, public_key, encrypted_message: str) -> str:
    logging.info("Entered decrypt")
    try:
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[32:-16]
        shared_secret = private_key.exchange(ec.ECDH(), public_key)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        symmetric_key = kdf.derive(shared_secret)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        result = plaintext.decode('utf-8')
        logging.info("decrypt successful")
        return result
    except Exception as e:
        logging.error("Error in decrypt: %s", e)
        raise
def writejson(filename: str, content: dict, mode='w', indent=4) -> None:
    logging.info("Writing JSON to %s", filename)
    try:
        with open(filename, mode) as file:
            json.dump(content, file, indent=indent)
        logging.info("writejson successful")
    except Exception as e:
        logging.error("Error writing JSON to %s: %s", filename, e)
        raise
def readjson(filename: str) -> dict:
    logging.info("Reading JSON from %s", filename)
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
        logging.info("readjson successful")
        return data
    except Exception as e:
        logging.error("Error reading JSON from %s: %s", filename, e)
        raise
def writebin64(filename: str, content: str) -> None:
    logging.info("Writing binary data to %s", filename)
    try:
        with open(filename, 'wb') as file:
            file.write(base64.b64decode(content))
        logging.info("writebin64 successful")
    except Exception as e:
        logging.error("Error writing binary data to %s: %s", filename, e)
        raise
def readbin64(filename: str) -> str:
    logging.info("Reading binary data from %s", filename)
    try:
        with open(filename, 'rb') as file:
            data = base64.b64encode(file.read()).decode('utf-8')
        logging.info("readbin64 successful")
        return data
    except Exception as e:
        logging.error("Error reading binary data from %s: %s", filename, e)
        raise
def getextension(file_path: str) -> str:
    logging.info("Getting file extension for %s", file_path)
    ext = file_path.rsplit(".", 1)[-1] if "." in file_path else ""
    logging.info("Extension is: %s", ext)
    return ext
def update_ettextoutarea(text: str):
    ettextoutarea.delete(1.0, END)
    ettextoutarea.insert(END, text)
def savekey():
    logging.info("Entered savekey")
    root.withdraw()
    dialog = PasswordDialog(root, title="Enter or generate a password for saving keys...")
    keypass = dialog.result
    root.wm_deiconify()
    if not keypass:
        logging.info("No password provided for saving keys")
        return
    if not otherpublic.get():
        messagebox.showwarning("Warning", "Receiver public key is not provided.")
        logging.warning("Receiver public key is not provided")
    if not public.get() or not private.get():
        messagebox.showerror("Error", "Public and/or private key is missing. Please generate the keys first.")
        logging.error("Public and/or private key is missing")
        return
    data = {"key": {"public": public.get(), "public2": otherpublic.get()}}
    try:
        cipher_text, salt, iv = encryptAESCBC(private.get(), keypass)
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")
        logging.error("Encryption failed in savekey: %s", e)
        return
    data["key"]["private"] = {"cipher": cipher_text, "salt": salt, "iv": iv}
    data["meta"] = {"savetime": time.time()}
    filepath = os.path.join(BASE_DIR, f"keys_{int(time.time())}.keys")
    try:
        writejson(filepath, data)
    except Exception as e:
        messagebox.showerror("Error", f"Saving keys failed: {e}")
        logging.error("Saving keys failed in savekey: %s", e)
        return
    messagebox.showinfo("Information", f"Keys have been saved to:\n{filepath}")
    logging.info("savekey completed successfully")
def loadkey():
    logging.info("Entered loadkey")
    filepath = filedialog.askopenfilename(filetypes=[("KEYS File", "*.keys")])
    if filepath:
        root.withdraw()
        dialog = PasswordDialog(root, title="Enter or generate a password for loading keys...")
        keypass = dialog.result
        root.wm_deiconify()
        if not keypass:
            logging.info("No password provided for loading keys")
            return
        try:
            data = readjson(filepath)
        except Exception as e:
            messagebox.showerror("Error", f"Loading file failed: {e}")
            logging.error("Loading file failed in loadkey: %s", e)
            return
        public.set(data["key"]["public"])
        otherpublic.set(data["key"]["public2"])
        cipher = data["key"]["private"]["cipher"]
        salt = data["key"]["private"]["salt"]
        iv = data["key"]["private"]["iv"]
        try:
            private.set(decryptAESCBC(cipher, keypass, salt, iv))
        except Exception as e:
            messagebox.showerror("Error", f"Error while loading the .KEYS file: {e}.")
            logging.error("Decryption failed in loadkey: %s", e)
            return
        savetime = data["meta"]["savetime"]
        if (time.time() - savetime) // (60 * 60 * 24) > 0:
            messagebox.showwarning("Warning", "The .KEYS file is older than one day. Please generate a new .KEYS file.")
            logging.warning("Loaded .KEYS file is older than one day")
        privatekeyarea.config(state="normal")
        privatekeyarea.delete(1.0, END)
        privatekeyarea.insert(END, private.get())
        privatekeyarea.config(state="disabled")
        publickeyarea.config(state="normal")
        publickeyarea.delete(1.0, END)
        publickeyarea.insert(END, public.get())
        publickeyarea.config(state="disabled")
        if otherpublic.get():
            otherpublickeyarea.delete(1.0, END)
            otherpublickeyarea.insert(END, otherpublic.get())
        messagebox.showinfo("Information", ".KEYS file has been loaded.")
        logging.info("loadkey completed successfully")
    else:
        messagebox.showerror("Error", "File path is empty. Please select a valid path.")
        logging.error("No file path selected in loadkey")
        return
def setotherpublic():
    logging.info("Entered setotherpublic")
    public_key_text = otherpublickeyarea.get("1.0", END).rstrip('\n')
    if public_key_text.startswith("-----BEGIN PUBLIC KEY-----") and public_key_text.endswith("-----END PUBLIC KEY-----"):
        otherpublic.set(public_key_text)
        messagebox.showinfo("Info", "The receiver's public key has been set.")
        otherpublickeyarea.delete(1.0, END)
        otherpublickeyarea.insert(END, public_key_text)
        logging.info("Receiver public key set successfully")
    else:
        messagebox.showerror("Error", "Invalid public key format. Please enter a valid key.")
        logging.error("Invalid public key format in setotherpublic")
def generatekeys():
    logging.info("Entered generatekeys")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    private.set(private_pem.decode('utf-8').rstrip('\n'))
    privatekeyarea.config(state="normal")
    privatekeyarea.delete(1.0, END)
    privatekeyarea.insert(END, private.get())
    privatekeyarea.config(state="disabled")
    public.set(public_pem.decode('utf-8').rstrip('\n'))
    publickeyarea.config(state="normal")
    publickeyarea.delete(1.0, END)
    publickeyarea.insert(END, public.get())
    publickeyarea.config(state="disabled")
    logging.info("generatekeys completed successfully")
def etenc():
    logging.info("Entered etenc")
    intext = ettextinarea.get("1.0", END).strip()
    if not intext:
        messagebox.showerror("Error", "The input text area is empty. Please provide valid text.")
        logging.error("etenc: input text area is empty")
        return
    if not private.get():
        messagebox.showerror("Error", "Private key is missing. Please generate a set of keys.")
        logging.error("etenc: private key is missing")
        return
    if not otherpublic.get():
        messagebox.showerror("Error", "Receiver public key is missing. Please provide a valid key.")
        logging.error("etenc: receiver public key is missing")
        return
    def thread_task():
        try:
            priv, pub = encdeckey(private.get(), otherpublic.get())
            outtext = encrypt(priv, pub, intext)
            logging.info("Text encryption successful in thread")
            root.after(0, lambda: update_ettextoutarea(outtext))
        except Exception as e:
            logging.error("etenc: encryption failed: %s", e)
            root.after(0, lambda: messagebox.showerror("Error", f"Error while encrypting text: {e}."))
    threading.Thread(target=thread_task).start()
def etdec():
    logging.info("Entered etdec")
    intext = ettextinarea.get("1.0", END).strip()
    if not intext:
        messagebox.showerror("Error", "The input text area is empty. Please provide valid text.")
        logging.error("etdec: input text area is empty")
        return
    if not private.get():
        messagebox.showerror("Error", "Private key is missing. Please generate a set of keys.")
        logging.error("etdec: private key is missing")
        return
    if not otherpublic.get():
        messagebox.showerror("Error", "Receiver public key is missing. Please provide a valid key.")
        logging.error("etdec: receiver public key is missing")
        return
    def thread_task():
        try:
            priv, pub = encdeckey(private.get(), otherpublic.get())
            outtext = decrypt(priv, pub, intext)
            logging.info("Text decryption successful in thread")
            root.after(0, lambda: update_ettextoutarea(outtext))
        except Exception as e:
            logging.error("etdec: decryption failed: %s", e)
            root.after(0, lambda: messagebox.showerror("Error", f"Error while decrypting text: {e}."))
    threading.Thread(target=thread_task).start()
def etsave():
    logging.info("Entered etsave")
    filepath = filedialog.asksaveasfilename(filetypes=[("ECC AES-GCM Encrypted Text File Format", "*.eccaesgcmtf")])
    if not filepath:
        messagebox.showerror("Error", "File path is empty. Please select a valid path.")
        logging.error("etsave: no file path selected")
        return
    if not filepath.endswith(".eccaesgcmtf"):
        filepath = filepath + ".eccaesgcmtf"
    intext = ettextinarea.get("1.0", END).strip()
    if not intext:
        messagebox.showerror("Error", "The input text area is empty. Please provide valid text.")
        logging.error("etsave: input text area is empty")
        return
    if not private.get():
        messagebox.showerror("Error", "Private key is missing. Please generate a set of keys.")
        logging.error("etsave: private key is missing")
        return
    if not otherpublic.get():
        messagebox.showerror("Error", "Receiver public key is missing. Please provide a valid key.")
        logging.error("etsave: receiver public key is missing")
        return
    def thread_task():
        try:
            priv, pub = encdeckey(private.get(), otherpublic.get())
            outtext = encrypt(priv, pub, intext)
            logging.info("Text encryption in etsave successful")
            data = {"data": outtext, "savetime": time.time()}
            writejson(filepath, data)
            logging.info("File saved successfully in etsave")
            root.after(0, lambda: etsave_complete(filepath, outtext))
        except Exception as e:
            logging.error("etsave: failed: %s", e)
            root.after(0, lambda: messagebox.showerror("Error", f"Error while encrypting/saving text: {e}."))
    threading.Thread(target=thread_task).start()
def etsave_complete(filepath: str, outtext: str):
    ettextoutarea.delete(1.0, END)
    ettextoutarea.insert(END, outtext)
    messagebox.showinfo("Information", "The .ECCAESGCMTF file has been saved.")
def etload():
    logging.info("Entered etload")
    filepath = filedialog.askopenfilename(filetypes=[("ECC AES-GCM Encrypted Text File Format", "*.eccaesgcmtf")])
    if not filepath:
        messagebox.showerror("Error", "File path is empty. Please select a valid path.")
        logging.error("etload: no file path selected")
        return
    if not filepath.endswith(".eccaesgcmtf"):
        messagebox.showerror("Error", "The file extension is not .ECCAESGCMTF. Please provide a valid file path.")
        logging.error("etload: invalid file extension")
        return
    def thread_task():
        try:
            data = readjson(filepath)
            intext = data["data"]
            savetime = data["savetime"]
            if not private.get():
                raise Exception("Private key is missing. Please generate a set of keys.")
            if not otherpublic.get():
                raise Exception("Receiver public key is missing. Please provide a valid key.")
            priv, pub = encdeckey(private.get(), otherpublic.get())
            outtext = decrypt(priv, pub, intext)
            logging.info("Text decryption in etload successful")
            root.after(0, lambda: etload_complete(intext, outtext, savetime))
        except Exception as e:
            logging.error("etload: failed: %s", e)
            root.after(0, lambda: messagebox.showerror("Error", f"Error while loading/decrypting text: {e}."))
    threading.Thread(target=thread_task).start()
def etload_complete(intext: str, outtext: str, savetime: float):
    ettextinarea.delete(1.0, END)
    ettextinarea.insert(END, intext)
    ettextoutarea.delete(1.0, END)
    ettextoutarea.insert(END, outtext)
    messagebox.showinfo("Information", f".ECCAESGCMTF file is loaded. The file was created on {time.ctime(savetime)}")
def efsave():
    logging.info("Entered efsave")
    infilepath = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if not infilepath:
        messagebox.showerror("Error", "Input file path is empty. Please select a valid path.")
        logging.error("efsave: no input file path selected")
        return
    outfilepath = filedialog.asksaveasfilename(filetypes=[("ECC AES-GCM Encrypted Universal File Format", "*.eccaesgcmuf")])
    if not outfilepath:
        messagebox.showerror("Error", "Output file path is empty. Please select a valid path.")
        logging.error("efsave: no output file path selected")
        return
    if not outfilepath.endswith(".eccaesgcmuf"):
        outfilepath = outfilepath + ".eccaesgcmuf"
    def thread_task():
        try:
            indata = readbin64(infilepath)
            logging.info("File read successfully in efsave")
            priv, pub = encdeckey(private.get(), otherpublic.get())
            cipher_text = encrypt(priv, pub, indata)
            logging.info("File encryption in efsave successful")
            data = {"data": cipher_text, "savetime": time.time(), "extension": getextension(infilepath)}
            writejson(outfilepath, data)
            logging.info("File saved successfully in efsave")
            root.after(0, lambda: messagebox.showinfo("Information", "The .ECCAESGCMUF file has been saved."))
        except Exception as e:
            logging.error("efsave: failed: %s", e)
            root.after(0, lambda: messagebox.showerror("Error", f"Error while encrypting/saving file: {e}."))
    threading.Thread(target=thread_task).start()
def efload():
    logging.info("Entered efload")
    infilepath = filedialog.askopenfilename(filetypes=[("ECC AES-GCM Encrypted Universal File Format", "*.eccaesgcmuf")])
    if not infilepath:
        messagebox.showerror("Error", "Input file path is empty. Please select a valid path.")
        logging.error("efload: no input file path selected")
        return
    outfilepath = filedialog.asksaveasfilename(filetypes=[("All Files", "*.*")])
    if not outfilepath:
        messagebox.showerror("Error", "Output file path is empty. Please select a valid path.")
        logging.error("efload: no output file path selected")
        return
    def thread_task():
        try:
            indata = readjson(infilepath)
            logging.info("File read successfully in efload")
            final_outpath = outfilepath if outfilepath.endswith(indata["extension"]) else outfilepath + "." + indata["extension"]
            priv, pub = encdeckey(private.get(), otherpublic.get())
            outdata = decrypt(priv, pub, indata["data"])
            logging.info("File decryption in efload successful")
            writebin64(final_outpath, outdata)
            logging.info("Output file written successfully in efload")
            root.after(0, lambda: messagebox.showinfo("Information", f".ECCAESGCMUF file is loaded. The file was created on {time.ctime(indata['savetime'])}"))
        except Exception as e:
            logging.error("efload: failed: %s", e)
            root.after(0, lambda: messagebox.showerror("Error", f"Error while decrypting file: {e}."))
    threading.Thread(target=thread_task).start()
def foenc():
    logging.info("Entered foenc")
    folderpath = filedialog.askdirectory(title="Select Folder to Encrypt")
    if not folderpath:
        messagebox.showerror("Error", "No folder selected.")
        logging.error("foenc: no folder selected")
        return
    fologarea.delete(1.0, END)
    fologarea.insert(END, f"Selected folder: {folderpath}\n")
    if not private.get():
        messagebox.showerror("Error", "Private key is missing. Please generate or load your key pair.")
        logging.error("foenc: private key is missing")
        return
    if not otherpublic.get():
        messagebox.showerror("Error", "Receiver public key is missing. Please provide a valid key.")
        logging.error("foenc: receiver public key is missing")
        return
    try:
        priv, pub = encdeckey(private.get(), otherpublic.get())
    except Exception as e:
        messagebox.showerror("Error", f"Key loading failed: {e}")
        logging.error("foenc: key loading failed: %s", e)
        return
    tree = _gen_tree(folderpath)
    fologarea.insert(END, "Generating encryption tree...\n")
    def thread_task():
        _encrypt_tree(tree, folderpath, priv, pub)
        root.after(0, lambda: foenc_complete(tree, folderpath))
    threading.Thread(target=thread_task).start()
def foenc_complete(tree: dict, folderpath: str):
    outfilepath = filedialog.asksaveasfilename(title="Save Encrypted Folder File", filetypes=[("ECC AES-GCM Encrypted Folder Format", "*.eccaesgcmff")])
    if not outfilepath:
        messagebox.showerror("Error", "No output file selected.")
        logging.error("foenc: no output file selected")
        return
    if not outfilepath.endswith(".eccaesgcmff"):
        outfilepath += ".eccaesgcmff"
    data = {"tree": tree, "savetime": time.time()}
    try:
        writejson(outfilepath, data)
        fologarea.insert(END, f"Encrypted folder saved to {outfilepath}\n")
        logging.info("Folder encrypted and saved to %s", outfilepath)
        messagebox.showinfo("Information", f"Folder encrypted and saved as:\n{outfilepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Saving encrypted folder failed: {e}")
        logging.error("foenc: saving encrypted folder failed: %s", e)
def fodec():
    logging.info("Entered fodec")
    infile = filedialog.askopenfilename(title="Select Encrypted Folder File", filetypes=[("ECC AES-GCM Encrypted Folder Format", "*.eccaesgcmff")])
    if not infile:
        messagebox.showerror("Error", "No input file selected.")
        logging.error("fodec: no input file selected")
        return
    try:
        data = readjson(infile)
        tree = data["tree"]
    except Exception as e:
        messagebox.showerror("Error", f"Error reading encrypted folder file: {e}")
        logging.error("fodec: error reading encrypted folder file: %s", e)
        return
    fologarea.delete(1.0, END)
    fologarea.insert(END, f"Loaded encrypted folder file: {infile}\n")
    dest_folder = filedialog.askdirectory(title="Select Destination Folder for Decrypted Files")
    if not dest_folder:
        messagebox.showerror("Error", "No destination folder selected.")
        logging.error("fodec: no destination folder selected")
        return
    if not private.get():
        messagebox.showerror("Error", "Private key is missing.")
        logging.error("fodec: private key is missing")
        return
    if not otherpublic.get():
        messagebox.showerror("Error", "Receiver public key is missing.")
        logging.error("fodec: receiver public key is missing")
        return
    try:
        priv, pub = encdeckey(private.get(), otherpublic.get())
    except Exception as e:
        messagebox.showerror("Error", f"Key loading failed: {e}")
        logging.error("fodec: key loading failed: %s", e)
        return
    def thread_task():
        _decrypt_tree(tree, dest_folder, priv, pub)
        root.after(0, lambda: fodec_complete(dest_folder, data))
    threading.Thread(target=thread_task).start()
def fodec_complete(dest_folder: str, data: dict):
    fologarea.insert(END, f"Decrypted folder saved to {dest_folder}\n")
    messagebox.showinfo("Information", f"Folder decrypted and saved to {dest_folder} the encrypted .ECCAESGCMFF was created on {time.ctime(data['savetime'])}")
    logging.info("fodec completed successfully")
def _gen_tree(path: str) -> dict:
    logging.info("Entered _gen_tree for path: %s", path)
    tree = {}
    try:
        for entry in os.scandir(path):
            if entry.is_dir():
                tree[entry.name] = _gen_tree(entry.path)
            elif entry.is_file():
                tree[entry.name] = None
    except Exception as e:
        logging.error("Error generating tree for %s: %s", path, e)
    logging.info("_gen_tree completed for path: %s", path)
    return tree
def _encrypt_tree(tree: dict, path: str, priv, pub) -> None:
    logging.info("Entered _encrypt_tree for path: %s", path)
    for key, value in tree.items():
        fullpath = os.path.join(path, key)
        if isinstance(value, dict):
            _encrypt_tree(value, fullpath, priv, pub)
        else:
            try:
                indata = readbin64(fullpath)
                tree[key] = encrypt(priv, pub, indata)
                fologarea.insert(END, f"Encrypted: {fullpath}\n")
                fologarea.see(END)
                logging.info("Encrypted file: %s", fullpath)
            except Exception as e:
                messagebox.showerror("Error", f"Error encrypting {fullpath}: {e}")
                logging.error("Encryption error in file %s: %s", fullpath, e)
                return
    logging.info("_encrypt_tree completed for path: %s", path)
def _decrypt_tree(tree: dict, dest_path: str, priv, pub) -> None:
    logging.info("Entered _decrypt_tree for destination path: %s", dest_path)
    for key, value in tree.items():
        outpath = os.path.join(dest_path, key)
        if isinstance(value, dict):
            os.makedirs(outpath, exist_ok=True)
            _decrypt_tree(value, outpath, priv, pub)
        else:
            try:
                decrypted_data = decrypt(priv, pub, value)
                writebin64(outpath, decrypted_data)
                fologarea.insert(END, f"Decrypted: {outpath}\n")
                fologarea.see(END)
                logging.info("Decrypted file: %s", outpath)
            except Exception as e:
                messagebox.showerror("Error", f"Error decrypting file {outpath}: {e}")
                logging.error("Decryption error in file %s: %s", outpath, e)
                return
    logging.info("_decrypt_tree completed for destination path: %s", dest_path)
def updatefont():
    logging.info("Entered updatefont")
    newSize = simpledialog.askinteger("Font Size", "Enter font size (8-72):", minvalue=8, maxvalue=72)
    if newSize is None:
        logging.info("updatefont cancelled")
        return
    if newSize < 8 or newSize > 72:
        messagebox.showerror("Error", "Font size should be between 8 and 72.")
        logging.error("updatefont: font size out of range")
        return
    ettextinarea.configure(font=("Consolas", newSize))
    ettextoutarea.configure(font=("Consolas", newSize))
    global sizemenu, fontSize
    fontSize.set(str(newSize))
    sizemenu.entryconfig(0, label=f"Font Size: {newSize}")
    logging.info("updatefont completed with new size: %d", newSize)
def updatewidth():
    logging.info("Entered updatewidth")
    newwidth = simpledialog.askinteger("Width Size", "Enter width size (40-90):", minvalue=40, maxvalue=90)
    if newwidth is None:
        logging.info("updatewidth cancelled")
        return
    if newwidth < 40 or newwidth > 90:
        messagebox.showerror("Error", "Width should be between 40 and 90.")
        logging.error("updatewidth: width out of range")
        return
    ettextinarea.configure(width=newwidth)
    ettextoutarea.configure(width=newwidth)
    global sizemenu, width
    width.set(str(newwidth))
    sizemenu.entryconfig(1, label=f"Width: {newwidth}")
    logging.info("updatewidth completed with new width: %d", newwidth)
def updateheight():
    logging.info("Entered updateheight")
    newheight = simpledialog.askinteger("Height Size", "Enter height size (8-30):", minvalue=8, maxvalue=30)
    if newheight is None:
        logging.info("updateheight cancelled")
        return
    if newheight < 8 or newheight > 30:
        messagebox.showerror("Error", "Height should be between 8 and 30.")
        logging.error("updateheight: height out of range")
        return
    ettextinarea.configure(height=newheight)
    ettextoutarea.configure(height=newheight)
    global sizemenu, height
    height.set(str(newheight))
    sizemenu.entryconfig(2, label=f"Height: {newheight}")
    logging.info("updateheight completed with new height: %d", newheight)
def setlayout(mode):
    logging.info("Entered setlayout with mode: %s", mode)
    for widget in container.winfo_children():
        widget.grid_forget()
    if mode == "right":
        container.grid_columnconfigure(0, weight=1)
        container.grid_columnconfigure(1, weight=1)
        container.grid_rowconfigure(0, weight=1)
        mainframe.grid(row=0, column=0, sticky="nsew")
        encryptioncontainer.grid(row=0, column=1, sticky="nsew")
    elif mode == "bottom":
        container.grid_rowconfigure(0, weight=1)
        container.grid_rowconfigure(1, weight=1)
        container.grid_columnconfigure(0, weight=1)
        mainframe.grid(row=0, column=0, sticky="nsew")
        encryptioncontainer.grid(row=1, column=0, sticky="nsew")
    logging.info("setlayout completed with mode: %s", mode)
def showframe(frame):
    logging.info("Entered showframe")
    textframe.grid_forget()
    fileframe.grid_forget()
    folderframe.grid_forget()
    frame.grid(row=0, column=0, sticky="nsew")
    logging.info("showframe completed")
def toggleprivate():
    logging.info("Entered toggleprivate")
    if privatevisible.get():
        privatekeyarealabel.grid_forget()
        privatekeyarea.grid(row=1, column=0)
        logging.info("Private key shown")
    else:
        privatekeyarealabel.grid(row=1, column=0)
        privatekeyarea.grid_forget()
        logging.info("Private key hidden")
def updateallwidgets(widget, bg, fg):
    try:
        widget_type = widget.winfo_class()
        if widget_type == "Text":
            widget.configure(bg=bg, fg=fg, insertbackground=fg)
        elif widget_type == "Button":
            widget.configure(bg=bg, fg=fg, activebackground=bg)
        else:
            widget.configure(bg=bg, fg=fg)
    except Exception:
        try:
            widget.configure(bg=bg)
        except Exception:
            pass
    for child in widget.winfo_children():
        updateallwidgets(child, bg, fg)
def theme(mode):
    logging.info("Entered theme with mode: %s", mode)
    if mode == "black":
        bg = "black"
        fg = "white"
    elif mode == "white":
        bg = "#F0F0F0"
        fg = "black"
    else:
        logging.error("Invalid theme mode: %s", mode)
        return
    root.config(bg=bg)
    updateallwidgets(root, bg, fg)
    try:
        menubar.config(bg=bg)
    except Exception:
        pass
    if menubar.index("end") is not None:
        for i in range(menubar.index("end") + 1):
            try:
                menubar.entryconfig(i, background=bg)
            except Exception:
                pass
            try:
                menubar.entryconfig(i, activebackground=bg)
            except Exception:
                pass
    logging.info("Theme set to %s", mode)
class PasswordDialog(simpledialog.Dialog):
    def body(self, master):
        logging.info("PasswordDialog: body() called")
        Label(master, text="Password:").grid(row=0, column=0, padx=5, pady=5)
        self.password_var = StringVar()
        self.show_password_var = BooleanVar(value=False)
        self.password_entry = Entry(master, textvariable=self.password_var, width=48, show="*")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)
        self.generate_button = Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=1, column=0, columnspan=2, pady=5)
        self.show_checkbox = Checkbutton(master, text="Show Password", variable=self.show_password_var, command=self.toggle_show_password)
        self.show_checkbox.grid(row=2, column=0, columnspan=2, pady=5)
        logging.info("PasswordDialog: body() completed")
        return self.password_entry
    def toggle_show_password(self):
        logging.info("PasswordDialog: toggle_show_password() called")
        if self.show_password_var.get():
            self.password_entry.config(show="")
            logging.info("PasswordDialog: Password shown")
        else:
            self.password_entry.config(show="*")
            logging.info("PasswordDialog: Password hidden")
    def generate_password(self):
        logging.info("PasswordDialog: generate_password() called")
        password = generaterandompassword()
        self.password_var.set(password)
        logging.info("PasswordDialog: generated password")
    def apply(self):
        self.result = self.password_var.get()
        logging.info("PasswordDialog: apply() completed with result")
def generaterandompassword(length: int = 32) -> str:
    logging.info("Entered generaterandompassword with length: %d", length)
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    logging.info("generaterandompassword generated a password")
    return password
root = Tk()
root.title("ECC AES-GCM ENMFSR V: 3 B: 13/03/2025")
root.config(bg="#F0F0F0")
fontSize = StringVar(value="14")
width = StringVar(value="60")
height = StringVar(value="10")
public = StringVar()
otherpublic = StringVar()
private = StringVar()
menubar = Menu(root)
layoutmenu = Menu(menubar, tearoff=0)
layoutmenu.add_command(label="Right Layout", command=lambda: setlayout("right"))
layoutmenu.add_command(label="Bottom Layout", command=lambda: setlayout("bottom"))
menubar.add_cascade(label="Layout", menu=layoutmenu)
thememenu = Menu(menubar, tearoff=0)
thememenu.add_command(label="Dark Mode", command=lambda: theme("black"))
thememenu.add_command(label="Light Mode", command=lambda: theme("white"))
menubar.add_cascade(label="Theme", menu=thememenu)
sizemenu = Menu(menubar, tearoff=0)
sizemenu.add_command(label=f"Font Size: {fontSize.get()}", command=updatefont)
sizemenu.add_command(label=f"Width: {width.get()}", command=updatewidth)
sizemenu.add_command(label=f"Height: {height.get()}", command=updateheight)
menubar.add_cascade(label="Size", menu=sizemenu)
keymenu = Menu(menubar, tearoff=0)
keymenu.add_command(label="Save Keys", command=savekey)
keymenu.add_command(label="Load Keys", command=loadkey)
privatevisible = BooleanVar(value=False)
keymenu.add_checkbutton(label="Show Private Key", variable=privatevisible, command=toggleprivate)
menubar.add_cascade(label="Key", menu=keymenu)
root.config(menu=menubar)
container = Frame(root)
container.pack(fill="both", expand=True)
mainframe = Frame(container, padx=10, pady=10)
encryptioncontainer = Frame(container, padx=10, pady=10)
setlayout("right")
Label(mainframe, text="Elliptic Curve Cryptography (ECC)\nand Advanced Encryption Standard in Galois/Counter Mode (AES-GCM)\nfor Sending and Receiving Encrypted Messages and Files\nGraphical User Interface Version: 3\nBuilt: 13/03/2025").grid(row=0, column=0)
privatekeyarealabel = Label(mainframe, text="Private key is hidden.\nNEVER SHARE THIS, IT WOULD MAKE THE ENCRYPTION UNSAFE!")
privatekeyarealabel.grid(row=1, column=0)
privatekeyarea = scrolledtext.ScrolledText(mainframe, wrap=CHAR, width=30, state="disabled", height=7, font=("Consolas", 10))
privatekeyarea.grid(row=1, column=0)
privatekeyarea.grid_forget()
publickeyarea = scrolledtext.ScrolledText(mainframe, wrap=CHAR, width=28, state="disabled", height=7, font=("Consolas", 10))
publickeyarea.grid(row=1, column=1)
keygenbutton = Button(mainframe, text="GENERATE KEYS", command=generatekeys)
keygenbutton.grid(row=1, column=2)
Label(mainframe, text="PRIVATE KEY           PUBLIC KEY\n\n             RECEIVER PUBLIC KEY").grid(row=2, column=0)
otherpublickeyarea = scrolledtext.ScrolledText(mainframe, wrap=CHAR, width=28, height=7, font=("Consolas", 10))
otherpublickeyarea.grid(row=2, column=1)
otherpublickeybutton = Button(mainframe, text="SET RECEIVER", command=setotherpublic)
otherpublickeybutton.grid(row=2, column=2)
encbutton = Button(mainframe, text="TEXT ENCRYPTION", command=lambda: showframe(textframe))
encbutton.grid(row=3, column=0)
encfbutton = Button(mainframe, text="FILE ENCRYPTION", command=lambda: showframe(fileframe))
encfbutton.grid(row=3, column=1)
encfbutton2 = Button(mainframe, text="FOLDER ENCRYPTION", command=lambda: showframe(folderframe))
encfbutton2.grid(row=4, column=1)
textframe = Frame(encryptioncontainer, padx=10, pady=10)
fileframe = Frame(encryptioncontainer, padx=10, pady=10)
folderframe = Frame(encryptioncontainer, padx=10, pady=10)
Label(textframe, text="TEXT IN").grid(row=0, column=0)
Label(textframe, text="TEXT OUT").grid(row=0, column=1)
ettextinarea = scrolledtext.ScrolledText(textframe, wrap=WORD, width=int(width.get()), height=int(height.get()), font=("Consolas", int(fontSize.get())))
ettextinarea.grid(row=1, column=0)
ettextoutarea = scrolledtext.ScrolledText(textframe, wrap=WORD, width=int(width.get()), height=int(height.get()), font=("Consolas", int(fontSize.get())))
ettextoutarea.grid(row=1, column=1)
etbuttonenc = Button(textframe, text="ENCRYPT", command=etenc)
etbuttonenc.grid(row=2, column=0)
etbuttondec = Button(textframe, text="DECRYPT", command=etdec)
etbuttondec.grid(row=2, column=1)
etbuttonsave = Button(textframe, text="SAVE TO FILE", command=etsave)
etbuttonsave.grid(row=3, column=0)
etbuttonload = Button(textframe, text="LOAD FROM FILE", command=etload)
etbuttonload.grid(row=3, column=1)
Label(fileframe, text="ENCRYPT FILE").grid(row=0, column=0)
efbuttonenc = Button(fileframe, text="ENCRYPT FILE", command=efsave)
efbuttonenc.grid(row=3, column=0)
efbuttondec = Button(fileframe, text="DECRYPT FILE", command=efload)
efbuttondec.grid(row=3, column=1)
Label(folderframe, text="ENCRYPT FOLDER").grid(row=0, column=0)
fologarea = scrolledtext.ScrolledText(folderframe, wrap=WORD, width=int(width.get()), height=int(height.get()), font=("Consolas", int(fontSize.get())))
fologarea.grid(row=1, column=0)
fobuttonsave = Button(folderframe, text="ENCRYPT FOLDER", command=foenc)
fobuttonsave.grid(row=3, column=0)
fobuttonload = Button(folderframe, text="DECRYPT FOLDER", command=fodec)
fobuttonload.grid(row=4, column=0)
theme("white")
root.mainloop()
