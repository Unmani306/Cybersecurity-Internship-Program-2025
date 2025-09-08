import tkinter as tk
from tkinter import filedialog, messagebox
from ciphers import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt
from aes_handler import aes_encrypt_file, aes_decrypt_file

def encrypt_text():
    text = entry_text.get()
    method = method_var.get()
    if method == "Caesar":
        shift = int(entry_shift.get())
        output_text.set(caesar_encrypt(text, shift))
    else:
        key = entry_key.get()
        output_text.set(vigenere_encrypt(text, key))

def decrypt_text():
    text = entry_text.get()
    method = method_var.get()
    if method == "Caesar":
        shift = int(entry_shift.get())
        output_text.set(caesar_decrypt(text, shift))
    else:
        key = entry_key.get()
        output_text.set(vigenere_decrypt(text, key))

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        new_file = aes_encrypt_file(file_path)
        messagebox.showinfo("AES Encryption", f"Encrypted file saved as:\n{new_file}")

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        new_file = aes_decrypt_file(file_path)
        messagebox.showinfo("AES Decryption", f"Decrypted file saved as:\n{new_file}")

# GUI
window = tk.Tk()
window.title("Multi-Cipher Tool")

tk.Label(window, text="Enter Text:").pack()
entry_text = tk.Entry(window, width=50)
entry_text.pack()

method_var = tk.StringVar(value="Caesar")
tk.OptionMenu(window, method_var, "Caesar", "Vigenère").pack()

tk.Label(window, text="Shift (Caesar) or Key (Vigenère):").pack()
entry_shift = tk.Entry(window, width=10)
entry_shift.pack()
entry_key = tk.Entry(window, width=20)
entry_key.pack()

tk.Button(window, text="Encrypt Text", command=encrypt_text).pack(pady=5)
tk.Button(window, text="Decrypt Text", command=decrypt_text).pack(pady=5)
tk.Button(window, text="Encrypt File (AES)", command=encrypt_file).pack(pady=5)
tk.Button(window, text="Decrypt File (AES)", command=decrypt_file).pack(pady=5)

tk.Label(window, text="Output:").pack()
output_text = tk.StringVar()
tk.Entry(window, textvariable=output_text, width=50, state='readonly').pack()

window.mainloop()
