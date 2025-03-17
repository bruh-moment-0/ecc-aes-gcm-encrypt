# ecc-aes-gcm encrypt  
elliptic curve cryptography (ecc) and advanced encryption standard in galois/counter mode (aes-gcm) for secure message and file encryption, featuring a graphical user interface.  

## features  
- highly secure – if you protect your private key, not even the cia, fbi, nsa, or any other entity can decrypt your data (at least until quantum computing breaks current encryption standards).  
- user-friendly – simple tkinter-based gui.  
- logging enabled – useful for debugging.  
- fast performance – uses the threading module for improved speed.  
- customizable ui – many gui elements can be modified.  
- flexible encryption – encrypts messages, files, or entire folders.  
- peer-to-peer encryption – set a recipient's public key for secure communication.  
- dark mode support  
- secure key storage – saves private, public, and recipient's public keys using aes-cbc encryption.  
- privacy-focused – no hidden info-stealers or shady backdoors.  

## how to run it  
1. install python (minimum requirement: python 3.6) from [python.org](https://www.python.org/downloads/).  
2. run `installer.py` to install the required dependencies.  
3. launch `main.py` to start the application.  

## how to use it  
1. complete the initial setup.  
2. click "generate keys" to create your encryption keys.  
3. share your public key with the recipient.  
4. obtain the recipient’s public key, enter it in the designated field, and press "set receiver."  
5. select your encryption mode.  
6. encrypt or decrypt messages/files as needed.  

pro tip: if you're encrypting files for personal use, you can set yourself as the recipient by copying and pasting your own public key.
