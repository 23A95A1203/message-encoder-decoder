from tkinter import *
from tkinter import filedialog, messagebox, Toplevel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64, qrcode
from PIL import Image, ImageTk

# Initialize window
root = Tk()
root.title("🔐 Secure Message Encoder/Decoder (RSA + QR)")
root.geometry("600x480")
root.resizable(False, False)
root.configure(bg="#f0f0f0")

# Define variables
Text = StringVar()
Result = StringVar()
mode = StringVar(value="encode")
pub_key_path = StringVar()
priv_key_path = StringVar()
public_key_cache = None  # store generated public key bytes for QR

# --- RSA Key Helpers ---
def generate_keys():
    global public_key_cache
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    public_key_cache = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as f:
        f.write(public_key_cache)

    messagebox.showinfo("Keys Generated", "public_key.pem and private_key.pem saved!")

def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# --- Encode / Decode ---
def Encode(pub_path, message):
    try:
        pub = load_public_key(pub_path)
        ciphertext = pub.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        return base64.b64encode(ciphertext).decode()
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")
        return ""

def Decode(priv_path, token):
    try:
        priv = load_private_key(priv_path)
        ciphertext = base64.b64decode(token)
        plaintext = priv.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        return plaintext.decode()
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")
        return ""

# --- Main Process ---
def Process():
    message = Text.get()
    if mode.get() == "encode":
        if not pub_key_path.get():
            messagebox.showwarning("Missing Info", "Please select a public key file.")
            return
        Result.set(Encode(pub_key_path.get(), message))
    elif mode.get() == "decode":
        if not priv_key_path.get():
            messagebox.showwarning("Missing Info", "Please select a private key file.")
            return
        Result.set(Decode(priv_key_path.get(), message))

def Reset():
    Text.set("")
    Result.set("")
    pub_key_path.set("")
    priv_key_path.set("")

def CopyResult():
    root.clipboard_clear()
    root.clipboard_append(Result.get())
    messagebox.showinfo("Copied", "Result copied to clipboard!")

# --- File dialogs ---
def select_public_key():
    path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    if path: pub_key_path.set(path)

def select_private_key():
    path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    if path: priv_key_path.set(path)

# --- QR Code for Public Key ---
def show_qr_code():
    global public_key_cache
    if not public_key_cache:
        try:
            with open("public_key.pem", "rb") as f:
                public_key_cache = f.read()
        except:
            messagebox.showwarning("No Key", "Generate or load a public key first!")
            return

    # Create QR code
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
    qr.add_data(public_key_cache.decode())
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    # Show in new window
    qr_window = Toplevel(root)
    qr_window.title("Public Key QR Code")
    qr_window.geometry("400x400")
    qr_window.resizable(False, False)

    img = img.resize((350, 350))
    tk_img = ImageTk.PhotoImage(img)
    lbl = Label(qr_window, image=tk_img)
    lbl.image = tk_img
    lbl.pack(pady=20)

# --- UI Layout ---
Label(root, text="RSA Secure Messenger (with QR)", font=("Arial", 20, "bold"), bg="#f0f0f0").pack(pady=10)

# Message
Label(root, text="Message:", font=("Arial", 12), bg="#f0f0f0").pack()
Entry(root, textvariable=Text, width=60, font=("Arial", 10)).pack(pady=5)

# Mode
Label(root, text="Mode:", font=("Arial", 12), bg="#f0f0f0").pack()
Radiobutton(root, text="Encode (use recipient public key)", variable=mode, value="encode", font=("Arial", 10), bg="#f0f0f0").pack()
Radiobutton(root, text="Decode (use your private key)", variable=mode, value="decode", font=("Arial", 10), bg="#f0f0f0").pack()

# Key selection
Button(root, text="Select Public Key", command=select_public_key, bg="#2196F3", fg="white").pack(pady=5)
Label(root, textvariable=pub_key_path, font=("Arial", 8), bg="#f0f0f0").pack()

Button(root, text="Select Private Key", command=select_private_key, bg="#9C27B0", fg="white").pack(pady=5)
Label(root, textvariable=priv_key_path, font=("Arial", 8), bg="#f0f0f0").pack()

# Result
Label(root, text="Result:", font=("Arial", 12), bg="#f0f0f0").pack()
Entry(root, textvariable=Result, width=60, font=("Arial", 10), state="readonly").pack(pady=5)

# Buttons
Button(root, text="Generate Keys", command=generate_keys, bg="#FF9800", fg="white", font=("Arial", 10, "bold")).pack(pady=5)
Button(root, text="Show Public Key QR", command=show_qr_code, bg="#673AB7", fg="white", font=("Arial", 10, "bold")).pack(pady=5)
Button(root, text="Process", command=Process, bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(pady=5)
Button(root, text="Copy", command=CopyResult, bg="#00BCD4", fg="white", font=("Arial", 10, "bold")).pack(pady=5)
Button(root, text="Reset", command=Reset, bg="#FFC107", font=("Arial", 10, "bold")).pack(pady=5)
Button(root, text="Exit", command=root.quit, bg="#F44336", fg="white", font=("Arial", 10, "bold")).pack(pady=5)

root.mainloop()
