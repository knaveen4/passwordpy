import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random
import string
import pyperclip

class PasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")

        self.length_label = ttk.Label(root, text="Password Length:")
        self.length_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")

        self.length_var = tk.IntVar()
        self.length_entry = ttk.Entry(root, textvariable=self.length_var)
        self.length_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.complexity_label = ttk.Label(root, text="Complexity:")
        self.complexity_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")

        self.uppercase_var = tk.IntVar()
        self.uppercase_check = ttk.Checkbutton(root, text="Uppercase", variable=self.uppercase_var)
        self.uppercase_check.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        self.lowercase_var = tk.IntVar()
        self.lowercase_check = ttk.Checkbutton(root, text="Lowercase", variable=self.lowercase_var)
        self.lowercase_check.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        self.lowercase_check.invoke()  # Initially checked

        self.digits_var = tk.IntVar()
        self.digits_check = ttk.Checkbutton(root, text="Digits", variable=self.digits_var)
        self.digits_check.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        self.symbols_var = tk.IntVar()
        self.symbols_check = ttk.Checkbutton(root, text="Symbols", variable=self.symbols_var)
        self.symbols_check.grid(row=4, column=1, padx=10, pady=5, sticky="w")

        self.generate_button = ttk.Button(root, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=5, column=0, columnspan=2, pady=10)

    def generate_password(self):
        length = self.length_var.get()

        if length <= 0:
            messagebox.showerror("Error", "Password length must be greater than 0.")
            return

        complexity_options = {
            'uppercase': string.ascii_uppercase if self.uppercase_var.get() else '',
            'lowercase': string.ascii_lowercase if self.lowercase_var.get() else '',
            'digits': string.digits if self.digits_var.get() else '',
            'symbols': string.punctuation if self.symbols_var.get() else ''
        }

        if all(len(option) == 0 for option in complexity_options.values()):
            messagebox.showerror("Error", "Select at least one complexity option.")
            return

        password_characters = ''.join(complexity_options.values())
        generated_password = ''.join(random.choice(password_characters) for _ in range(length))

        if not self.check_security_rules(generated_password):
            messagebox.showwarning("Warning", "Generated password does not adhere to common security rules.")

        pyperclip.copy(generated_password)

        messagebox.showinfo("Password Generated", "Password copied to clipboard:\n" + generated_password)

    @staticmethod
    def check_security_rules(password):
        # Add your security rules here (e.g., minimum length, presence of uppercase, lowercase, digits, etc.)
        return len(password) >= 8 and any(c.isupper() for c in password) and any(c.isdigit() for c in password)


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()
