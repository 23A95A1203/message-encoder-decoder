from tkinter import *
import base64
from tkinter import messagebox

# Initialize window
root = Tk()
root.title("🔐 Secure Message Encoder/Decoder")
root.geometry("550x350")
root.resizable(False, False)
root.configure(bg="#f0f0f0")

# Define variables
Text = StringVar()
private_key = StringVar()
mode = StringVar(value="encode")  # default to encode
Result = StringVar()

# Function to encode
def Encode(key, message):
    enc = []
    for i in range(len(message)):
        key_c = key[i % len(key)]
        enc.append(chr((ord(message[i]) + ord(key_c)) % 256))
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

# Function to decode
def Decode(key, message):
    dec = []
    try:
        message = base64.urlsafe_b64decode(message).decode()
    except Exception as e:
        messagebox.showerror("Error", "Invalid encoded message!")
        return ""
    for i in range(len(message)):
        key_c = key[i % len(key)]
        dec.append(chr((256 + ord(message[i]) - ord(key_c)) % 256))
    return "".join(dec)

# Main function
def Process():
    message = Text.get()
    key = private_key.get()
    if not message or not key:
        messagebox.showwarning("Missing Info", "Please enter both message and key.")
        return
    if mode.get() == "encode":
        Result.set(Encode(key, message))
    elif mode.get() == "decode":
        Result.set(Decode(key, message))

# Reset function
def Reset():
    Text.set("")
    private_key.set("")
    Result.set("")
def CopyResult():
    root.clipboard_clear()
    root.clipboard_append(Result.get())
    messagebox.showinfo("Copied", "Result copied to clipboard!")
# Exit function
def Exit():
    root.quit()

# --- UI Layout ---
Label(root, text="Message Encoder & Decoder", font=("Arial", 20, "bold"), bg="#f0f0f0").grid(row=0, column=0, columnspan=3, pady=10)

# Message
Label(root, text="Message:", font=("Arial", 12), bg="#f0f0f0").grid(row=1, column=0, sticky=W, padx=20, pady=5)
Entry(root, textvariable=Text, width=50, font=("Arial", 10)).grid(row=1, column=1, columnspan=2, pady=5)

# Key
Label(root, text="Key:", font=("Arial", 12), bg="#f0f0f0").grid(row=2, column=0, sticky=W, padx=20, pady=5)
Entry(root, textvariable=private_key, width=50, font=("Arial", 10), show="*").grid(row=2, column=1, columnspan=2, pady=5)

# Mode selection
Label(root, text="Mode:", font=("Arial", 12), bg="#f0f0f0").grid(row=3, column=0, sticky=W, padx=20, pady=5)
Radiobutton(root, text="Encode", variable=mode, value="encode", font=("Arial", 10), bg="#f0f0f0").grid(row=3, column=1, sticky=W)
Radiobutton(root, text="Decode", variable=mode, value="decode", font=("Arial", 10), bg="#f0f0f0").grid(row=3, column=2, sticky=W)

# Result label
Label(root, text="Result:", font=("Arial", 12), bg="#f0f0f0").grid(row=4, column=0, sticky=W, padx=20, pady=5)
Entry(root, textvariable=Result, width=50, font=("Arial", 10), state="readonly").grid(row=4, column=1, columnspan=2, pady=5)

# Buttons
Button(root, text="Process", width=10, command=Process, bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).grid(row=5, column=0, pady=20, padx=10)
Button(root, text="Reset", width=10, command=Reset, bg="#FFC107", font=("Arial", 10, "bold")).grid(row=5, column=1, pady=20)
Button(root, text="Exit", width=10, command=Exit, bg="#F44336", fg="white", font=("Arial", 10, "bold")).grid(row=5, column=2, pady=20)
Button(root, text="Copy", width=10, command=CopyResult, bg="#2196F3", fg="white", font=("Arial", 10, "bold")).grid(row=6, column=1, pady=10)  # NEW




root.mainloop()
