# This is early version of the program.
# I will update it later. (it's buggy)

import os
import json
import time
import base64
import secrets
import string
import logging
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog, END
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

# Modern font adı
MODERN_FONT = "Segoe UI"

def encryptAESCBC(data: str, password: str) -> tuple:
    try:
        salt = get_random_bytes(SALT_LENGTH)
        iv = get_random_bytes(IV_LENGTH)
        key = PBKDF2(password, salt, dkLen=KEY_LENGTH, count=KDF_ITERATIONS)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad_length = AES.block_size - len(data) % AES.block_size
        padded_data = data + pad_length * chr(pad_length)
        ciphertext = cipher.encrypt(padded_data.encode())
        return (
            base64.b64encode(ciphertext).decode(),
            base64.b64encode(salt).decode(),
            base64.b64encode(iv).decode(),
        )
    except Exception as e:
        logging.error("Error in encryptAESCBC: %s", e)
        raise

def decryptAESCBC(ciphertext_b64: str, password: str, salt_b64: str, iv_b64: str) -> str:
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        salt = base64.b64decode(salt_b64)
        iv = base64.b64decode(iv_b64)
        key = PBKDF2(password, salt, dkLen=KEY_LENGTH, count=KDF_ITERATIONS)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext).decode()
        pad_length = ord(decrypted_data[-1])
        return decrypted_data[:-pad_length]
    except Exception as e:
        logging.error("Error in decryptAESCBC: %s", e)
        raise

def encdeckey(private_key_str: str, public_key_str: str) -> tuple:
    try:
        private_key_obj = serialization.load_pem_private_key(private_key_str.encode('utf-8'), password=None)
        public_key_obj = serialization.load_pem_public_key(public_key_str.encode('utf-8'))
        return private_key_obj, public_key_obj
    except Exception as e:
        logging.error("Error in encdeckey: %s", e)
        raise

def encrypt(private_key, public_key, message: str) -> str:
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
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        logging.error("Error in encrypt: %s", e)
        raise

def decrypt(private_key, public_key, encrypted_message: str) -> str:
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
        return plaintext.decode('utf-8')
    except Exception as e:
        logging.error("Error in decrypt: %s", e)
        raise

def writejson(filename: str, content: dict, mode='w', indent=4) -> None:
    try:
        with open(filename, mode) as file:
            json.dump(content, file, indent=indent)
    except Exception as e:
        logging.error("Error writing JSON to %s: %s", filename, e)
        raise

def readjson(filename: str) -> dict:
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
        return data
    except Exception as e:
        logging.error("Error reading JSON from %s: %s", filename, e)
        raise

def writebin64(filename: str, content: str) -> None:
    try:
        with open(filename, 'wb') as file:
            file.write(base64.b64decode(content))
    except Exception as e:
        logging.error("Error writing binary data to %s: %s", filename, e)
        raise

def readbin64(filename: str) -> str:
    try:
        with open(filename, 'rb') as file:
            data = base64.b64encode(file.read()).decode('utf-8')
        return data
    except Exception as e:
        logging.error("Error reading binary data from %s: %s", filename, e)
        raise

def getextension(file_path: str) -> str:
    ext = file_path.rsplit(".", 1)[-1] if "." in file_path else ""
    return ext

class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Enter Password"):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x250")
        self.resizable(False, False)
        self.result = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkFrame(self)
        frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text="Password:", font=ctk.CTkFont(family=MODERN_FONT, size=14)).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.password_var = ctk.StringVar()
        self.password_entry = ctk.CTkEntry(
            frame, 
            textvariable=self.password_var, 
            width=300,
            show="*",
            font=ctk.CTkFont(family=MODERN_FONT, size=14)
        )
        self.password_entry.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        self.show_password_var = ctk.BooleanVar(value=False)
        show_password_check = ctk.CTkCheckBox(
            frame, 
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_show_password,
            font=ctk.CTkFont(family=MODERN_FONT, size=13)
        )
        show_password_check.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        generate_btn = ctk.CTkButton(
            frame,
            text="Generate Secure Password",
            command=self.generate_password,
            font=ctk.CTkFont(family=MODERN_FONT, size=13)
        )
        generate_btn.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
        btn_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(
            btn_frame,
            text="Save",
            command=self.save_action,
            font=ctk.CTkFont(family=MODERN_FONT, size=13)
        ).grid(row=0, column=0, padx=5, sticky="ew")
        self.grab_set()
        self.transient(parent)
        self.wait_window()
    def toggle_show_password(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")
    def generate_password(self):
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) 
                        for _ in range(24))
        self.password_var.set(password)
    def save_action(self):
        self.result = self.password_var.get()
        self.destroy()

def generaterandompassword(length: int = 32) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ECC AES-GCM ENMFSR V: 3 BETA-1 • Built: 06/22/2025")
        self.geometry("1200x800")
        # Center the window on the screen
        self.update_idletasks()
        width = 1200
        height = 800
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        self.public = ctk.StringVar()
        self.otherpublic = ctk.StringVar()
        self.private = ctk.StringVar()
        self.private_visible = ctk.BooleanVar(value=False)
        self.font_size = ctk.IntVar(value=14)
        self.text_width = ctk.IntVar(value=60)
        self.text_height = ctk.IntVar(value=10)
        self.create_menu()
        self.create_main_ui()
        self.create_text_encryption_ui()
        self.create_file_encryption_ui()
        self.create_folder_encryption_ui()
        self.show_frame(self.main_frame)
    def create_menu(self):
        menu_bar = ctk.CTkFrame(self, height=60)
        menu_bar.pack(fill="x", padx=10, pady=5)
        theme_btn = ctk.CTkButton(menu_bar, text="Theme", width=80, height=40, command=self.show_theme_menu, font=ctk.CTkFont(family=MODERN_FONT, size=13))
        theme_btn.pack(side="left", padx=5)
        size_btn = ctk.CTkButton(menu_bar, text="Size", width=80, height=40, command=self.show_size_menu, font=ctk.CTkFont(family=MODERN_FONT, size=13))
        size_btn.pack(side="left", padx=5)
        key_btn = ctk.CTkButton(menu_bar, text="Key", width=80, height=40, command=self.show_key_menu, font=ctk.CTkFont(family=MODERN_FONT, size=13))
        key_btn.pack(side="left", padx=5)
        # Ortada yazarlar ve linkler
        center_frame = ctk.CTkFrame(menu_bar, fg_color="transparent")
        center_frame.pack(side="left", expand=True)
        def open_bruhmoment():
            import webbrowser
            webbrowser.open_new("https://github.com/bruh-moment-0")
        def open_omerdynasty():
            import webbrowser
            webbrowser.open_new("https://github.com/omerdynasty")
        accent_color = "#3498db"  # Tema uyumlu mavi
        hover_color = "#a3c9f7"   # Açık mavi hover
        label1 = ctk.CTkLabel(center_frame, text="by ", font=ctk.CTkFont(family=MODERN_FONT, size=13))
        label1.pack(side="left")
        link1 = ctk.CTkButton(center_frame, text="bruh-moment-0", fg_color="transparent", text_color=accent_color, hover_color=hover_color, font=ctk.CTkFont(family=MODERN_FONT, size=13, underline=True), command=open_bruhmoment)
        link1.pack(side="left")
        label2 = ctk.CTkLabel(center_frame, text=" and ", font=ctk.CTkFont(family=MODERN_FONT, size=13))
        label2.pack(side="left")
        link2 = ctk.CTkButton(center_frame, text="omerdynasty", fg_color="transparent", text_color=accent_color, hover_color=hover_color, font=ctk.CTkFont(family=MODERN_FONT, size=13, underline=True), command=open_omerdynasty)
        link2.pack(side="left")
        enc_types = ctk.CTkSegmentedButton(menu_bar, 
                                          values=["Main", "Text", "File", "Folder"],
                                          command=self.encryption_type_changed,
                                          font=ctk.CTkFont(family=MODERN_FONT, size=13),
                                          height=40)
        enc_types.pack(side="right", padx=5)
        enc_types.set("Main")
    def show_theme_menu(self):
        menu = ctk.CTkToplevel(self)
        menu.geometry("200x130")
        menu.title("Theme Options")
        menu.transient(self)
        menu.grab_set()
        ctk.CTkButton(menu, text="Blue Mode", command=lambda: self.set_theme_and_refresh("blue"), font=ctk.CTkFont(family=MODERN_FONT, size=13)).pack(pady=5, fill="x")
        ctk.CTkButton(menu, text="Green Mode", command=lambda: self.set_theme_and_refresh("green"), font=ctk.CTkFont(family=MODERN_FONT, size=13)).pack(pady=5, fill="x")
    def set_theme_and_refresh(self, theme_name):
        ctk.set_default_color_theme(theme_name)
        # Ana frame ve alt frame'leri yok et
        for widget in self.winfo_children():
            widget.destroy()
        # Yeniden oluştur
        self.create_menu()
        self.create_main_ui()
        self.create_text_encryption_ui()
        self.create_file_encryption_ui()
        self.create_folder_encryption_ui()
        self.show_frame(self.main_frame)
        self.update_idletasks()
        self.update()
    def show_size_menu(self):
        menu = ctk.CTkToplevel(self)
        menu.geometry("300x120")
        menu.title("Size Options")
        menu.transient(self)
        menu.grab_set()
        ctk.CTkLabel(menu, text="Font Size:").pack(pady=(5,0))
        font_slider = ctk.CTkSlider(menu, from_=8, to=24, variable=self.font_size)
        font_slider.pack(pady=5, padx=20, fill="x")
        ctk.CTkButton(menu, text="Apply", command=lambda: [self.apply_size_settings(), menu.destroy()], height=40, width=200).pack(pady=15)
    def show_key_menu(self):
        menu = ctk.CTkToplevel(self)
        menu.geometry("200x150")
        menu.title("Key Operations")
        menu.transient(self)
        menu.grab_set()
        ctk.CTkButton(menu, text="Save Keys", command=self.savekey).pack(pady=5, fill="x")
        ctk.CTkButton(menu, text="Load Keys", command=self.loadkey).pack(pady=5, fill="x")
        ctk.CTkCheckBox(menu, text="Show Private Key", variable=self.private_visible,
                        command=self.toggle_private).pack(pady=5)
    def encryption_type_changed(self, value):
        if value == "Main":
            self.show_frame(self.main_frame)
        elif value == "Text":
            self.show_frame(self.text_frame)
        elif value == "File":
            self.show_frame(self.file_frame)
        elif value == "Folder":
            self.show_frame(self.folder_frame)
    def create_main_ui(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        title = ctk.CTkLabel(
            self.main_frame,
            text="ECC AES-GCM Encryption Suite\nVersion BETA-1 • Built: 22/06/2025",
            font=ctk.CTkFont(family=MODERN_FONT, size=16, weight="bold")
        )
        title.pack(pady=20)
        key_frame = ctk.CTkFrame(self.main_frame)
        key_frame.pack(pady=20, padx=20)
        key_gen_btn = ctk.CTkButton(
            key_frame, 
            text="Generate New Keys", 
            command=self.generatekeys,
            height=40,
            font=ctk.CTkFont(family=MODERN_FONT, weight="bold", size=13)
        )
        key_gen_btn.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        private_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        private_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        ctk.CTkLabel(private_frame, text="Private Key:", font=ctk.CTkFont(family=MODERN_FONT, size=13)).pack(anchor="center")
        self.private_text = ctk.CTkTextbox(
            private_frame, 
            width=400, 
            height=100,
            state="disabled",
            font=ctk.CTkFont(family=MODERN_FONT, size=12)
        )
        self.private_text.pack(pady=5)
        public_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        public_frame.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        ctk.CTkLabel(public_frame, text="Public Key:", font=ctk.CTkFont(family=MODERN_FONT, size=13)).pack(anchor="center")
        self.public_text = ctk.CTkTextbox(
            public_frame, 
            width=400, 
            height=100,
            state="disabled",
            font=ctk.CTkFont(family=MODERN_FONT, size=12)
        )
        self.public_text.pack(pady=5)
        receiver_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        receiver_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        ctk.CTkLabel(receiver_frame, text="Receiver Public Key:", font=ctk.CTkFont(family=MODERN_FONT, size=13)).pack(anchor="center")
        self.receiver_text = ctk.CTkTextbox(
            receiver_frame, 
            width=400, 
            height=100,
            font=ctk.CTkFont(family=MODERN_FONT, size=12)
        )
        self.receiver_text.pack(pady=5)
        set_receiver_btn = ctk.CTkButton(
            receiver_frame, 
            text="Set Receiver Key",
            command=self.setotherpublic,
            font=ctk.CTkFont(family=MODERN_FONT, size=13)
        )
        set_receiver_btn.pack(pady=5)
    def create_text_encryption_ui(self):
        self.text_frame = ctk.CTkFrame(self, fg_color="transparent")
        text_container = ctk.CTkFrame(self.text_frame, fg_color="transparent")
        text_container.pack(fill="both", expand=True, padx=20, pady=20)
        text_container.grid_columnconfigure(0, weight=1)
        text_container.grid_columnconfigure(1, weight=1)
        text_container.grid_rowconfigure(0, weight=1)
        input_frame = ctk.CTkFrame(text_container)
        input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(input_frame, text="Input Text").pack(pady=5)
        self.input_text = ctk.CTkTextbox(
            input_frame,
            width=self.text_width.get(),
            height=self.text_height.get(),
            font=ctk.CTkFont(family=MODERN_FONT, size=self.font_size.get())
        )
        self.input_text.pack(fill="both", expand=True, padx=10, pady=5)
        output_frame = ctk.CTkFrame(text_container)
        output_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(output_frame, text="Output Text").pack(pady=5)
        self.output_text = ctk.CTkTextbox(
            output_frame,
            width=self.text_width.get(),
            height=self.text_height.get(),
            font=ctk.CTkFont(family=MODERN_FONT, size=self.font_size.get())
        )
        self.output_text.pack(fill="both", expand=True, padx=10, pady=5)
        btn_frame = ctk.CTkFrame(self.text_frame)
        btn_frame.pack(pady=10, padx=20, fill="x")
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)
        btn_frame.grid_columnconfigure(2, weight=1)
        btn_frame.grid_columnconfigure(3, weight=1)
        ctk.CTkButton(
            btn_frame, 
            text="Encrypt", 
            command=self.etenc
        ).grid(row=0, column=0, padx=5, sticky="ew")
        ctk.CTkButton(
            btn_frame, 
            text="Decrypt", 
            command=self.etdec
        ).grid(row=0, column=1, padx=5, sticky="ew")
        ctk.CTkButton(
            btn_frame, 
            text="Save to File", 
            command=self.etsave
        ).grid(row=0, column=2, padx=5, sticky="ew")
        ctk.CTkButton(
            btn_frame, 
            text="Load from File", 
            command=self.etload
        ).grid(row=0, column=3, padx=5, sticky="ew")
    def create_file_encryption_ui(self):
        self.file_frame = ctk.CTkFrame(self, fg_color="transparent")
        container = ctk.CTkFrame(self.file_frame)
        container.pack(fill="both", expand=True, padx=50, pady=50)
        ctk.CTkLabel(
            container, 
            text="File Encryption",
            font=ctk.CTkFont(family=MODERN_FONT, size=16, weight="bold")
        ).pack(pady=20)
        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(pady=20)
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(
            btn_frame,
            text="Encrypt File",
            command=self.efsave,
            height=40,
            width=200
        ).grid(row=0, column=0, padx=20, pady=10)
        ctk.CTkButton(
            btn_frame,
            text="Decrypt File",
            command=self.efload,
            height=40,
            width=200
        ).grid(row=0, column=1, padx=20, pady=10)
    def create_folder_encryption_ui(self):
        self.folder_frame = ctk.CTkFrame(self, fg_color="transparent")
        container = ctk.CTkFrame(self.folder_frame)
        container.pack(fill="both", expand=True, padx=50, pady=50)
        ctk.CTkLabel(
            container, 
            text="Folder Encryption",
            font=ctk.CTkFont(family=MODERN_FONT, size=16, weight="bold")
        ).pack(pady=20)
        ctk.CTkLabel(container, text="Operation Log:").pack(anchor="w", padx=20)
        self.folder_log = ctk.CTkTextbox(
            container,
            width=self.text_width.get(),
            height=20,
            font=ctk.CTkFont(family=MODERN_FONT, size=self.font_size.get())
        )
        self.folder_log.pack(fill="x", padx=20, pady=10)
        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(pady=20)
        ctk.CTkButton(
            btn_frame,
            text="Encrypt Folder",
            command=self.foenc,
            height=40,
            width=200
        ).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(
            btn_frame,
            text="Decrypt Folder",
            command=self.fodec,
            height=40,
            width=200
        ).pack(side="left", padx=20, pady=10)
    def show_frame(self, frame):
        for f in [self.main_frame, self.text_frame, self.file_frame, self.folder_frame]:
            f.pack_forget()
        frame.pack(fill="both", expand=True)
    def apply_size_settings(self):
        self.input_text.configure(
            width=self.text_width.get(),
            height=self.text_height.get(),
            font=ctk.CTkFont(family=MODERN_FONT, size=self.font_size.get())
        )
        self.output_text.configure(
            width=self.text_width.get(),
            height=self.text_height.get(),
            font=ctk.CTkFont(family=MODERN_FONT, size=self.font_size.get())
        )
        self.folder_log.configure(
            font=ctk.CTkFont(family=MODERN_FONT, size=self.font_size.get())
        )
    def set_layout(self, layout):
        messagebox.showinfo("Layout Changed", f"Layout set to {layout}")
    def toggle_private(self):
        if self.private_visible.get():
            self.private_text.configure(state="normal")
        else:
            self.private_text.configure(state="disabled")
    def savekey(self):
        logging.info("Entered savekey")
        dialog = PasswordDialog(self, title="Enter Password for Key Saving")
        keypass = dialog.result
        if not keypass:
            logging.info("No password provided for saving keys")
            return
        if not self.otherpublic.get():
            messagebox.showwarning("Warning", "Receiver public key is not provided.")
            logging.warning("Receiver public key is not provided")
        if not self.public.get() or not self.private.get():
            messagebox.showerror("Error", "Public and/or private key is missing. Please generate the keys first.")
            logging.error("Public and/or private key is missing")
            return
        data = {"key": {"public": self.public.get(), "public2": self.otherpublic.get()}}
        try:
            cipher_text, salt, iv = encryptAESCBC(self.private.get(), keypass)
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
    def loadkey(self):
        logging.info("Entered loadkey")
        filepath = filedialog.askopenfilename(filetypes=[("KEYS File", "*.keys")])
        if filepath:
            dialog = PasswordDialog(self, title="Enter Password for Key Loading")
            keypass = dialog.result
            if not keypass:
                logging.info("No password provided for loading keys")
                return
            try:
                data = readjson(filepath)
            except Exception as e:
                messagebox.showerror("Error", f"Loading file failed: {e}")
                logging.error("Loading file failed in loadkey: %s", e)
                return
            self.public.set(data["key"]["public"])
            self.otherpublic.set(data["key"]["public2"])
            cipher = data["key"]["private"]["cipher"]
            salt = data["key"]["private"]["salt"]
            iv = data["key"]["private"]["iv"]
            try:
                self.private.set(decryptAESCBC(cipher, keypass, salt, iv))
            except Exception as e:
                messagebox.showerror("Error", f"Error while loading the .KEYS file: {e}.")
                logging.error("Decryption failed in loadkey: %s", e)
                return
            savetime = data["meta"]["savetime"]
            if (time.time() - savetime) // (60 * 60 * 24) > 0:
                messagebox.showwarning("Warning", "The .KEYS file is older than one day. Please generate a new .KEYS file.")
                logging.warning("Loaded .KEYS file is older than one day")
            self.private_text.configure(state="normal")
            self.private_text.delete("1.0", "end")
            self.private_text.insert("1.0", self.private.get())
            self.private_text.configure(state="disabled")
            self.public_text.configure(state="normal")
            self.public_text.delete("1.0", "end")
            self.public_text.insert("1.0", self.public.get())
            self.public_text.configure(state="disabled")
            if self.otherpublic.get():
                self.receiver_text.delete("1.0", "end")
                self.receiver_text.insert("1.0", self.otherpublic.get())
            messagebox.showinfo("Information", ".KEYS file has been loaded.")
            logging.info("loadkey completed successfully")
        else:
            messagebox.showerror("Error", "File path is empty. Please select a valid path.")
            logging.error("No file path selected in loadkey")
            return
    def setotherpublic(self):
        public_key_text = self.receiver_text.get("1.0", "end").rstrip('\n')
        if public_key_text.startswith("-----BEGIN PUBLIC KEY-----") and public_key_text.endswith("-----END PUBLIC KEY-----"):
            self.otherpublic.set(public_key_text)
            messagebox.showinfo("Info", "The receiver's public key has been set.")
            self.receiver_text.delete("1.0", "end")
            self.receiver_text.insert("1.0", public_key_text)
        else:
            messagebox.showerror("Error", "Invalid public key format. Please enter a valid key.")
    def generatekeys(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.private.set(private_pem.decode('utf-8').rstrip('\n'))
        self.private_text.configure(state="normal")
        self.private_text.delete("1.0", "end")
        self.private_text.insert("1.0", self.private.get())
        self.private_text.configure(state="disabled")
        self.public.set(public_pem.decode('utf-8').rstrip('\n'))
        self.public_text.configure(state="normal")
        self.public_text.delete("1.0", "end")
        self.public_text.insert("1.0", self.public.get())
        self.public_text.configure(state="disabled")
    def etenc(self):
        intext = self.input_text.get("1.0", "end").strip()
        if not intext:
            messagebox.showerror("Error", "The input text area is empty. Please provide valid text.")
            return
        if not self.private.get():
            messagebox.showerror("Error", "Private key is missing. Please generate a set of keys.")
            return
        if not self.otherpublic.get():
            messagebox.showerror("Error", "Receiver public key is missing. Please provide a valid key.")
            return
        def thread_task():
            try:
                priv, pub = encdeckey(self.private.get(), self.otherpublic.get())
                outtext = encrypt(priv, pub, intext)
                self.output_text.delete("1.0", "end")
                self.output_text.insert("1.0", outtext)
            except Exception as e:
                messagebox.showerror("Error", f"Error while encrypting text: {e}.")
        threading.Thread(target=thread_task).start()
    def etdec(self):
        intext = self.input_text.get("1.0", "end").strip()
        if not intext:
            messagebox.showerror("Error", "The input text area is empty. Please provide valid text.")
            return
        if not self.private.get():
            messagebox.showerror("Error", "Private key is missing. Please generate a set of keys.")
            return
        if not self.otherpublic.get():
            messagebox.showerror("Error", "Receiver public key is missing. Please provide a valid key.")
            return
        def thread_task():
            try:
                priv, pub = encdeckey(self.private.get(), self.otherpublic.get())
                outtext = decrypt(priv, pub, intext)
                self.output_text.delete("1.0", "end")
                self.output_text.insert("1.0", outtext)
            except Exception as e:
                messagebox.showerror("Error", f"Error while decrypting text: {e}.")
        threading.Thread(target=thread_task).start()
    def etsave(self):
        filepath = filedialog.asksaveasfilename(filetypes=[("ECC AES-GCM Encrypted Text File Format", "*.eccaesgcmtf")])
        if not filepath:
            messagebox.showerror("Error", "File path is empty. Please select a valid path.")
            return
        if not filepath.endswith(".eccaesgcmtf"):
            filepath = filepath + ".eccaesgcmtf"
        intext = self.input_text.get("1.0", "end").strip()
        if not intext:
            messagebox.showerror("Error", "The input text area is empty. Please provide valid text.")
            return
        if not self.private.get():
            messagebox.showerror("Error", "Private key is missing. Please generate a set of keys.")
            return
        if not self.otherpublic.get():
            messagebox.showerror("Error", "Receiver public key is missing. Please provide a valid key.")
            return
        def thread_task():
            try:
                priv, pub = encdeckey(self.private.get(), self.otherpublic.get())
                outtext = encrypt(priv, pub, intext)
                data = {"data": outtext, "savetime": time.time()}
                writejson(filepath, data)
                self.output_text.delete("1.0", "end")
                self.output_text.insert("1.0", outtext)
                messagebox.showinfo("Information", "The .ECCAESGCMTF file has been saved.")
            except Exception as e:
                messagebox.showerror("Error", f"Error while encrypting/saving text: {e}.")
        threading.Thread(target=thread_task).start()
    def etload(self):
        filepath = filedialog.askopenfilename(filetypes=[("ECC AES-GCM Encrypted Text File Format", "*.eccaesgcmtf")])
        if not filepath:
            messagebox.showerror("Error", "File path is empty. Please select a valid path.")
            return
        if not filepath.endswith(".eccaesgcmtf"):
            messagebox.showerror("Error", "The file extension is not .ECCAESGCMTF. Please provide a valid file path.")
            return
        def thread_task():
            try:
                data = readjson(filepath)
                intext = data["data"]
                savetime = data["savetime"]
                if not self.private.get():
                    raise Exception("Private key is missing. Please generate a set of keys.")
                if not self.otherpublic.get():
                    raise Exception("Receiver public key is missing. Please provide a valid key.")
                priv, pub = encdeckey(self.private.get(), self.otherpublic.get())
                outtext = decrypt(priv, pub, intext)
                self.input_text.delete("1.0", "end")
                self.input_text.insert("1.0", intext)
                self.output_text.delete("1.0", "end")
                self.output_text.insert("1.0", outtext)
                messagebox.showinfo("Information", f".ECCAESGCMTF file is loaded. The file was created on {time.ctime(savetime)}")
            except Exception as e:
                messagebox.showerror("Error", f"Error while loading/decrypting text: {e}.")
        threading.Thread(target=thread_task).start()
    def efsave(self):
        infilepath = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if not infilepath:
            messagebox.showerror("Error", "Input file path is empty. Please select a valid path.")
            return
        outfilepath = filedialog.asksaveasfilename(filetypes=[("ECC AES-GCM Encrypted Universal File Format", "*.eccaesgcmuf")])
        if not outfilepath:
            messagebox.showerror("Error", "Output file path is empty. Please select a valid path.")
            return
        if not outfilepath.endswith(".eccaesgcmuf"):
            outfilepath = outfilepath + ".eccaesgcmuf"
        def thread_task():
            try:
                indata = readbin64(infilepath)
                priv, pub = encdeckey(self.private.get(), self.otherpublic.get())
                cipher_text = encrypt(priv, pub, indata)
                data = {"data": cipher_text, "savetime": time.time(), "extension": getextension(infilepath)}
                writejson(outfilepath, data)
                messagebox.showinfo("Information", "The .ECCAESGCMUF file has been saved.")
            except Exception as e:
                messagebox.showerror("Error", f"Error while encrypting/saving file: {e}.")
        threading.Thread(target=thread_task).start()
    def efload(self):
        infilepath = filedialog.askopenfilename(filetypes=[("ECC AES-GCM Encrypted Universal File Format", "*.eccaesgcmuf")])
        if not infilepath:
            messagebox.showerror("Error", "Input file path is empty. Please select a valid path.")
            return
        outfilepath = filedialog.asksaveasfilename(filetypes=[("All Files", "*.*")])
        if not outfilepath:
            messagebox.showerror("Error", "Output file path is empty. Please select a valid path.")
            return
        def thread_task():
            try:
                indata = readjson(infilepath)
                final_outpath = outfilepath if outfilepath.endswith(indata["extension"]) else outfilepath + "." + indata["extension"]
                priv, pub = encdeckey(self.private.get(), self.otherpublic.get())
                outdata = decrypt(priv, pub, indata["data"])
                writebin64(final_outpath, outdata)
                messagebox.showinfo("Information", f".ECCAESGCMUF file is loaded. The file was created on {time.ctime(indata['savetime'])}")
            except Exception as e:
                messagebox.showerror("Error", f"Error while decrypting file: {e}.")
        threading.Thread(target=thread_task).start()
    def foenc(self):
        folderpath = filedialog.askdirectory(title="Select Folder to Encrypt")
        if not folderpath:
            messagebox.showerror("Error", "No folder selected.")
            return
        self.folder_log.delete("1.0", "end")
        self.folder_log.insert("1.0", f"Selected folder: {folderpath}\n")
        if not self.private.get():
            messagebox.showerror("Error", "Private key is missing. Please generate or load your key pair.")
            return
        if not self.otherpublic.get():
            messagebox.showerror("Error", "Receiver public key is missing. Please provide a valid key.")
            return
        try:
            priv, pub = encdeckey(self.private.get(), self.otherpublic.get())
        except Exception as e:
            messagebox.showerror("Error", f"Key loading failed: {e}")
            return
        tree = self._gen_tree(folderpath)
        self.folder_log.insert("end", "Generating encryption tree...\n")
        def thread_task():
            self._encrypt_tree(tree, folderpath, priv, pub)
            self.foenc_complete(tree, folderpath)
        threading.Thread(target=thread_task).start()
    def foenc_complete(self, tree: dict, folderpath: str):
        outfilepath = filedialog.asksaveasfilename(title="Save Encrypted Folder File", filetypes=[("ECC AES-GCM Encrypted Folder Format", "*.eccaesgcmff")])
        if not outfilepath:
            messagebox.showerror("Error", "No output file selected.")
            return
        if not outfilepath.endswith(".eccaesgcmff"):
            outfilepath += ".eccaesgcmff"
        data = {"tree": tree, "savetime": time.time()}
        try:
            writejson(outfilepath, data)
            self.folder_log.insert("end", f"Encrypted folder saved to {outfilepath}\n")
            messagebox.showinfo("Information", f"Folder encrypted and saved as:\n{outfilepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Saving encrypted folder failed: {e}")
    def fodec(self):
        infile = filedialog.askopenfilename(title="Select Encrypted Folder File", filetypes=[("ECC AES-GCM Encrypted Folder Format", "*.eccaesgcmff")])
        if not infile:
            messagebox.showerror("Error", "No input file selected.")
            return
        try:
            data = readjson(infile)
            tree = data["tree"]
        except Exception as e:
            messagebox.showerror("Error", f"Error reading encrypted folder file: {e}")
            return
        self.folder_log.delete("1.0", "end")
        self.folder_log.insert("1.0", f"Loaded encrypted folder file: {infile}\n")
        dest_folder = filedialog.askdirectory(title="Select Destination Folder for Decrypted Files")
        if not dest_folder:
            messagebox.showerror("Error", "No destination folder selected.")
            return
        if not self.private.get():
            messagebox.showerror("Error", "Private key is missing.")
            return
        if not self.otherpublic.get():
            messagebox.showerror("Error", "Receiver public key is missing.")
            return
        try:
            priv, pub = encdeckey(self.private.get(), self.otherpublic.get())
        except Exception as e:
            messagebox.showerror("Error", f"Key loading failed: {e}")
            return
        def thread_task():
            self._decrypt_tree(tree, dest_folder, priv, pub)
            self.fodec_complete(dest_folder, data)
        threading.Thread(target=thread_task).start()
    def fodec_complete(self, dest_folder: str, data: dict):
        self.folder_log.insert("end", f"Decrypted folder saved to {dest_folder}\n")
        messagebox.showinfo("Information", f"Folder decrypted and saved to {dest_folder} the encrypted .ECCAESGCMFF was created on {time.ctime(data['savetime'])}")
    def _gen_tree(self, path: str) -> dict:
        tree = {}
        try:
            for entry in os.scandir(path):
                if entry.is_dir():
                    tree[entry.name] = self._gen_tree(entry.path)
                elif entry.is_file():
                    tree[entry.name] = None
        except Exception as e:
            logging.error("Error generating tree for %s: %s", path, e)
        return tree
    def _encrypt_tree(self, tree: dict, path: str, priv, pub) -> None:
        for key, value in tree.items():
            fullpath = os.path.join(path, key)
            if isinstance(value, dict):
                self._encrypt_tree(value, fullpath, priv, pub)
            else:
                try:
                    indata = readbin64(fullpath)
                    tree[key] = encrypt(priv, pub, indata)
                    self.folder_log.insert("end", f"Encrypted: {fullpath}\n")
                    self.folder_log.see("end")
                except Exception as e:
                    messagebox.showerror("Error", f"Error encrypting {fullpath}: {e}")
                    return
    def _decrypt_tree(self, tree: dict, dest_path: str, priv, pub) -> None:
        for key, value in tree.items():
            outpath = os.path.join(dest_path, key)
            if isinstance(value, dict):
                os.makedirs(outpath, exist_ok=True)
                self._decrypt_tree(value, outpath, priv, pub)
            else:
                try:
                    decrypted_data = decrypt(priv, pub, value)
                    writebin64(outpath, decrypted_data)
                    self.folder_log.insert("end", f"Decrypted: {outpath}\n")
                    self.folder_log.see("end")
                except Exception as e:
                    messagebox.showerror("Error", f"Error decrypting file {outpath}: {e}")
                    return
    def refresh_ui(self):
        if self.main_frame.winfo_ismapped():
            self.show_frame(self.main_frame)
        elif self.text_frame.winfo_ismapped():
            self.show_frame(self.text_frame)
        elif self.file_frame.winfo_ismapped():
            self.show_frame(self.file_frame)
        elif self.folder_frame.winfo_ismapped():
            self.show_frame(self.folder_frame)

if __name__ == "__main__":
    app = App()
    app.mainloop()
