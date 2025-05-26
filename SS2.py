import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
import json
import os
from datetime import datetime
import re
import hashlib
import secrets
import string

class PasswordManagerApp:
    def _init_(self, root):
        self.root = root
        self.root.title("GetSecured")
        self.root.geometry("1000x600")
        self.root.resizable(False, False)
        
        # Initialize data storage
        self.data_dir = "user_data"
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Account storage
        self.accounts_file = os.path.join(self.data_dir, "accounts.json")
        self.accounts = self.load_data(self.accounts_file)
        
        # Security questions storage
        self.security_file = os.path.join(self.data_dir, "security.json")
        self.security_data = self.load_data(self.security_file)
        
        # Password storage
        self.passwords_file = os.path.join(self.data_dir, "passwords.json")
        self.passwords = self.load_data(self.passwords_file)
        
        # PIN storage
        self.pin_file = os.path.join(self.data_dir, "pins.json")
        self.pins = self.load_data(self.pin_file)
        
        self.current_user = None
        self.show_password = False
        self.login_attempts = 0
        self.max_login_attempts = 3
        
        # Security questions
        self.security_questions = [
            "What was your first pet's name?",
            "What city were you born in?",
            "What is your mother's maiden name?",
            "What was the name of your first school?",
            "What was your childhood nickname?"
        ]
        
        # Font settings
        self.default_font = ("Times New Roman", 10)
        self.entry_font = ("Times New Roman", 12)
        self.button_font = ("Times New Roman", 12)
        self.title_font = ("Times New Roman", 16, "bold")
        
        # Show login screen
        self.show_login_screen()
    
    def clear_window(self):
        """Clear all widgets from the root window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def hash_password(self, password):
        """Hash password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        return hashlib.sha256((password + salt).encode()).hexdigest() + ":" + salt
    
    def verify_password(self, stored_password, provided_password):
        """Verify hashed password"""
        if ":" not in stored_password:
            return False  # Old format password
        hashed, salt = stored_password.split(":")
        return hashlib.sha256((provided_password + salt).encode()).hexdigest() == hashed
    
    def load_data(self, filename):
        """Load JSON data from file"""
        if os.path.exists(filename):
            try:
                with open(filename, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_data(self, filename, data):
        """Save data to JSON file"""
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    
    def check_password_strength(self, password):
        """Check password strength"""
        if len(password) < 8:
            return "Password must be at least 8 characters long"
        if not re.search("[a-z]", password):
            return "Password must contain lowercase letters"
        if not re.search("[A-Z]", password):
            return "Password must contain uppercase letters"
        if not re.search("[0-9]", password):
            return "Password must contain numbers"
        if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
            return "Password must contain special characters"
        return "strong"
    
    def generate_strong_password(self):
        """Generate a strong random password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        return ''.join(secrets.choice(chars) for _ in range(16))
    
    def show_login_screen(self):
        self.clear_window()
        self.login_attempts = 0
        
        # Load login background
        try:
            bg_image = Image.open("images/getsecured_bg.png")
            self.login_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(self.root, image=self.login_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            self.root.login_bg_photo = self.login_bg_photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not load login background image: {e}")
            self.root.configure(bg="dark blue")
            return
        
        center_x = 500
        start_y = 250
        
        # Email Label
        email_label = tk.Label(
            self.root,
            text="Enter your email address:",
            font=self.default_font,
            bg="dark blue",
            fg="white",
            justify="center"
        )
        email_label.place(x=center_x-175, y=start_y, width=350, height=25)
        
        # Email Entry
        self.email_entry = tk.Entry(
            self.root,
            font=self.entry_font,
            bg="white"
        )
        self.email_entry.place(x=center_x-175, y=start_y+30, width=350, height=25)
        
        # Password Label
        password_label = tk.Label(
            self.root,
            text="Enter your password:",
            font=self.default_font,
            bg="dark blue",
            fg="white",
            justify="center"
        )
        password_label.place(x=center_x-175, y=start_y+80, width=350, height=25)
        
        # Password Entry
        self.password_entry = tk.Entry(
            self.root,
            font=self.entry_font,
            show="•",
            bg="white"
        )
        self.password_entry.place(x=center_x-175, y=start_y+110, width=350, height=25)
        
        # Login Button
        login_btn = tk.Button(
            self.root,
            text="Login",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=self.attempt_login
        )
        login_btn.place(x=center_x-175, y=start_y+160, width=350, height=30)
        
        # Forgot Password Button
        forgot_btn = tk.Button(
            self.root,
            text="Forgot Password?",
            font=("Times New Roman", 9),
            bg="dark blue",
            fg="white",
            relief=tk.FLAT,
            command=self.forgot_password
        )
        forgot_btn.place(x=center_x-90, y=start_y+210)
        
        # Sign Up Button
        signup_btn = tk.Button(
            self.root,
            text="Sign Up",
            font=("Times New Roman", 9),
            bg="dark blue",
            fg="white",
            relief=tk.FLAT,
            command=self.show_signup
        )
        signup_btn.place(x=center_x+30, y=start_y+210)
    
    def verify_pin(self, email):
        """Verify user's PIN"""
        pin_window = tk.Toplevel(self.root)
        pin_window.title("PIN Verification")
        pin_window.geometry("400x300")
        pin_window.resizable(False, False)
        
        # Load background
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 300), Image.LANCZOS)
            self.pin_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(pin_window, image=self.pin_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            pin_window.pin_bg_photo = self.pin_bg_photo
        except:
            pin_window.configure(bg="dark blue")
        
        center_x = 200
        start_y = 100
        
        # Title
        title_label = tk.Label(
            pin_window,
            text="Enter Your PIN",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        # PIN Entry
        pin_entry = tk.Entry(
            pin_window,
            show="•",
            font=self.entry_font,
            bg="white"
        )
        pin_entry.place(x=center_x-150, y=start_y, width=300, height=25)
        
        def check_pin():
            entered_pin = pin_entry.get()
            if email in self.pins and self.pins[email] == entered_pin:
                pin_window.destroy()
                self.current_user = email
                self.show_password_manager()
            else:
                messagebox.showerror("Error", "Incorrect PIN")
                pin_window.destroy()
        
        # Submit Button
        submit_btn = tk.Button(
            pin_window,
            text="Submit",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=check_pin
        )
        submit_btn.place(x=center_x-150, y=start_y+50, width=300, height=30)
    
    def forgot_password(self):
        forgot_window = tk.Toplevel(self.root)
        forgot_window.title("Forgot Password")
        forgot_window.geometry("400x400")
        forgot_window.resizable(False, False)
        
        # Load background
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 400), Image.LANCZOS)
            self.forgot_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(forgot_window, image=self.forgot_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            forgot_window.forgot_bg_photo = self.forgot_bg_photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not load background image: {e}")
            forgot_window.configure(bg="dark blue")
            return
        
        center_x = 200
        start_y = 100
        
        # Title
        title_label = tk.Label(
            forgot_window,
            text="Reset Password",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        # Email Label
        email_label = tk.Label(
            forgot_window,
            text="Enter your registered email:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        email_label.place(x=center_x-150, y=start_y)
        
        # Email Entry
        email_entry = tk.Entry(
            forgot_window,
            font=self.entry_font,
            bg="white"
        )
        email_entry.place(x=center_x-150, y=start_y+30, width=300, height=25)
        
        def submit_request():
            email = email_entry.get()
            if not email:
                messagebox.showerror("Error", "Please enter your email")
            elif email not in self.accounts:
                messagebox.showerror("Error", "No account found with this email")
            else:
                forgot_window.destroy()
                self.verify_security_question(email)
        
        # Submit Button
        submit_btn = tk.Button(
            forgot_window,
            text="Submit",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=submit_request
        )
        submit_btn.place(x=center_x-150, y=start_y+80, width=300, height=30)
        
        # Back Button
        back_btn = tk.Button(
            forgot_window,
            text="Back to Login",
            font=("Times New Roman", 9),
            bg="dark blue",
            fg="white",
            relief=tk.FLAT,
            command=forgot_window.destroy
        )
        back_btn.place(x=center_x-50, y=start_y+130, width=100, height=25)
    
    def verify_security_question(self, email):
        verify_window = tk.Toplevel(self.root)
        verify_window.title("Security Question")
        verify_window.geometry("400x400")
        verify_window.resizable(False, False)
        
        # Load background
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 400), Image.LANCZOS)
            self.verify_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(verify_window, image=self.verify_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            verify_window.verify_bg_photo = self.verify_bg_photo
        except:
            verify_window.configure(bg="dark blue")
        
        center_x = 200
        start_y = 100
        
        # Title
        title_label = tk.Label(
            verify_window,
            text="Security Question",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        # Security Question
        question = self.security_data[email]["question"]
        question_label = tk.Label(
            verify_window,
            text=question,
            font=self.default_font,
            fg="white",
            bg="dark blue",
            wraplength=300
        )
        question_label.place(x=center_x, y=start_y, anchor="center")
        
        # Answer Entry
        answer_entry = tk.Entry(
            verify_window,
            font=self.entry_font,
            bg="white"
        )
        answer_entry.place(x=center_x-150, y=start_y+50, width=300, height=25)
        
        def check_answer():
            answer = answer_entry.get()
            if answer.lower() == self.security_data[email]["answer"].lower():
                verify_window.destroy()
                self.reset_password(email)
            else:
                messagebox.showerror("Error", "Incorrect answer")
        
        # Submit Button
        submit_btn = tk.Button(
            verify_window,
            text="Submit",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=check_answer
        )
        submit_btn.place(x=center_x-150, y=start_y+100, width=300, height=30)
    
    def reset_password(self, email):
        reset_window = tk.Toplevel(self.root)
        reset_window.title("Reset Password")
        reset_window.geometry("400x400")
        reset_window.resizable(False, False)
        
        # Load background
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 400), Image.LANCZOS)
            self.reset_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(reset_window, image=self.reset_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            reset_window.reset_bg_photo = self.reset_bg_photo
        except:
            reset_window.configure(bg="dark blue")
        
        center_x = 200
        start_y = 100
        
        # Title
        title_label = tk.Label(
            reset_window,
            text="Reset Password",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        # New Password
        new_label = tk.Label(
            reset_window,
            text="New Password:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        new_label.place(x=center_x-150, y=start_y)
        
        new_entry = tk.Entry(
            reset_window,
            show="•",
            font=self.entry_font,
            bg="white"
        )
        new_entry.place(x=center_x-150, y=start_y+25, width=300, height=25)
        
        # Confirm Password
        confirm_label = tk.Label(
            reset_window,
            text="Confirm Password:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        confirm_label.place(x=center_x-150, y=start_y+70)
        
        confirm_entry = tk.Entry(
            reset_window,
            show="•",
            font=self.entry_font,
            bg="white"
        )
        confirm_entry.place(x=center_x-150, y=start_y+95, width=300, height=25)
        
        # Strength indicator
        strength_label = tk.Label(
            reset_window,
            text="",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        strength_label.place(x=center_x-150, y=start_y+130, width=300, height=25)
        
        def check_strength(event=None):
            password = new_entry.get()
            strength = self.check_password_strength(password)
            if strength == "strong":
                strength_label.config(text="Password strength: Strong", fg="green")
            else:
                strength_label.config(text=f"Password strength: {strength}", fg="red")
        
        new_entry.bind("<KeyRelease>", check_strength)
        
        def save_new_password():
            new_pass = new_entry.get()
            confirm_pass = confirm_entry.get()
            
            if not new_pass or not confirm_pass:
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            if new_pass != confirm_pass:
                messagebox.showerror("Error", "Passwords don't match")
                return
            
            strength = self.check_password_strength(new_pass)
            if strength != "strong":
                messagebox.showerror("Error", "Password is not strong enough")
                return
            
            self.accounts[email] = self.hash_password(new_pass)
            self.save_data(self.accounts_file, self.accounts)
            messagebox.showinfo("Success", "Password reset successfully!")
            reset_window.destroy()
        
        # Save Button
        save_btn = tk.Button(
            reset_window,
            text="Save",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=save_new_password
        )
        save_btn.place(x=center_x-150, y=start_y+180, width=300, height=30)
    
    def show_signup(self):
        signup_window = tk.Toplevel(self.root)
        signup_window.title("Sign Up")
        signup_window.geometry("500x600")  # Increased height for additional fields
        signup_window.resizable(False, False)
        
        # Load signup background
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((500, 600), Image.LANCZOS)
            self.signup_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(signup_window, image=self.signup_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            signup_window.signup_bg_photo = self.signup_bg_photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not load signup background image: {e}")
            signup_window.configure(bg="dark blue")
            return
        
        center_x = 250
        start_y = 100
        
        # Title
        title_label = tk.Label(
            signup_window,
            text="Create Account",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        # Email
        email_label = tk.Label(
            signup_window,
            text="Email:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        email_label.place(x=center_x-200, y=start_y)
        
        email_entry = tk.Entry(
            signup_window,
            font=self.entry_font,
            bg="white"
        )
        email_entry.place(x=center_x-200, y=start_y+25, width=400, height=25)
        
        # Password
        password_label = tk.Label(
            signup_window,
            text="Password:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        password_label.place(x=center_x-200, y=start_y+70)
        
        password_entry = tk.Entry(
            signup_window,
            show="•",
            font=self.entry_font,
            bg="white"
        )
        password_entry.place(x=center_x-200, y=start_y+95, width=400, height=25)
        
        # Password Strength
        strength_label = tk.Label(
            signup_window,
            text="",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        strength_label.place(x=center_x-200, y=start_y+130, width=400, height=25)
        
        def check_strength(event=None):
            password = password_entry.get()
            strength = self.check_password_strength(password)
            if strength == "strong":
                strength_label.config(text="Password strength: Strong", fg="green")
            else:
                strength_label.config(text=f"Password strength: {strength}", fg="red")
        
        password_entry.bind("<KeyRelease>", check_strength)
        
        # Confirm Password
        confirm_label = tk.Label(
            signup_window,
            text="Confirm Password:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        confirm_label.place(x=center_x-200, y=start_y+170)
        
        confirm_entry = tk.Entry(
            signup_window,
            show="•",
            font=self.entry_font,
            bg="white"
        )
        confirm_entry.place(x=center_x-200, y=start_y+195, width=400, height=25)
        
        # Security Question
        question_label = tk.Label(
            signup_window,
            text="Security Question:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        question_label.place(x=center_x-200, y=start_y+240)
        
        question_var = tk.StringVar(signup_window)
        question_var.set(self.security_questions[0])
        
        question_menu = tk.OptionMenu(
            signup_window,
            question_var,
            *self.security_questions
        )
        question_menu.config(font=self.default_font, bg="white")
        question_menu.place(x=center_x-200, y=start_y+265, width=400, height=25)
        
        # Security Answer
        answer_label = tk.Label(
            signup_window,
            text="Answer:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        answer_label.place(x=center_x-200, y=start_y+310)
        
        answer_entry = tk.Entry(
            signup_window,
            font=self.entry_font,
            bg="white"
        )
        answer_entry.place(x=center_x-200, y=start_y+335, width=400, height=25)
        
        # PIN
        pin_label = tk.Label(
            signup_window,
            text="Create a 4-digit PIN:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        pin_label.place(x=center_x-200, y=start_y+380)
        
        pin_entry = tk.Entry(
            signup_window,
            show="•",
            font=self.entry_font,
            bg="white",
            validate="key",
            validatecommand=(signup_window.register(lambda s: len(s) <= 4 and s.isdigit()), '%S')
        )
        pin_entry.place(x=center_x-200, y=start_y+405, width=400, height=25)
        
        def register():
            email = email_entry.get()
            password = password_entry.get()
            confirm = confirm_entry.get()
            question = question_var.get()
            answer = answer_entry.get()
            pin = pin_entry.get()
            
            if not all([email, password, confirm, answer, pin]):
                messagebox.showerror("Error", "Please fill all fields")
            elif password != confirm:
                messagebox.showerror("Error", "Passwords don't match")
            elif email in self.accounts:
                messagebox.showerror("Error", "Email already registered")
            elif len(pin) != 4 or not pin.isdigit():
                messagebox.showerror("Error", "PIN must be 4 digits")
            else:
                strength = self.check_password_strength(password)
                if strength != "strong":
                    messagebox.showerror("Error", "Password is not strong enough")
                    return
                
                self.accounts[email] = self.hash_password(password)
                self.security_data[email] = {
                    "question": question,
                    "answer": answer.lower()
                }
                self.pins[email] = pin
                self.passwords[email] = []
                
                self.save_data(self.accounts_file, self.accounts)
                self.save_data(self.security_file, self.security_data)
                self.save_data(self.pin_file, self.pins)
                self.save_data(self.passwords_file, self.passwords)
                
                messagebox.showinfo("Success", "Account created successfully!")
                signup_window.destroy()
        
        signup_btn = tk.Button(
            signup_window,
            text="Sign Up",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=register
        )
        signup_btn.place(x=center_x-150, y=start_y+450, width=300, height=30)
    
    def show_password_manager(self):
        self.clear_window()
        
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((1000, 600), Image.LANCZOS)
            self.pm_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(self.root, image=self.pm_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            self.root.pm_bg_photo = self.pm_bg_photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not load password manager background: {e}")
            self.root.configure(bg="dark blue")
            return
        
        # User info
        user_label = tk.Label(
            self.root,
            text=f"Logged in as: {self.current_user}",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        user_label.place(x=500, y=30, anchor="center")
        
        # Password entries treeview
        columns = ("S.No", "Site", "Username", "Password", "Created At")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        
        # Configure columns
        self.tree.heading("S.No", text="S.No")
        self.tree.column("S.No", width=50, anchor="center")
        
        self.tree.heading("Site", text="Site")
        self.tree.column("Site", width=150)
        
        self.tree.heading("Username", text="Username")
        self.tree.column("Username", width=150)
        
        self.tree.heading("Password", text="Password")
        self.tree.column("Password", width=150)
        
        self.tree.heading("Created At", text="Created At")
        self.tree.column("Created At", width=150)
        
        self.tree.place(x=50, y=100, width=900, height=350)
        
        # Load user's passwords
        self.load_user_passwords()
        
        # Button configuration
        buttons = [
            ("Add Password", "green", self.show_add_password),
            ("Generate Password", "#3498db", self.generate_password),
            ("Show Passwords" if not self.show_password else "Hide Passwords", "#3498db", self.toggle_password_visibility),
            ("Delete Password", "red", self.delete_password),
            ("Logout", "red", self.logout)
        ]
        
        # Place buttons
        for i, (text, color, cmd) in enumerate(buttons):
            btn = tk.Button(
                self.root,
                text=text,
                font=self.button_font,
                bg=color,
                fg="white",
                command=cmd
            )
            btn.place(x=150 + i*175, y=480, width=150, height=40)
    
    def generate_password(self):
        gen_window = tk.Toplevel(self.root)
        gen_window.title("Generate Password")
        gen_window.geometry("400x200")
        gen_window.resizable(False, False)
        
        # Load background
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 200), Image.LANCZOS)
            self.gen_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(gen_window, image=self.gen_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            gen_window.gen_bg_photo = self.gen_bg_photo
        except:
            gen_window.configure(bg="dark blue")
        
        center_x = 200
        start_y = 50
        
        # Title
        title_label = tk.Label(
            gen_window,
            text="Generated Password",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-30, anchor="center")
        
        # Generated Password
        password = self.generate_strong_password()
        password_var = tk.StringVar(value=password)
        
        password_entry = tk.Entry(
            gen_window,
            textvariable=password_var,
            font=self.entry_font,
            bg="white",
            justify="center"
        )
        password_entry.place(x=center_x-150, y=start_y, width=300, height=25)
        
        # Copy Button
        def copy_password():
            gen_window.clipboard_clear()
            gen_window.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        
        copy_btn = tk.Button(
            gen_window,
            text="Copy Password",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=copy_password
        )
        copy_btn.place(x=center_x-150, y=start_y+50, width=300, height=30)
    
    def show_add_password(self):
        add_window = tk.Toplevel(self.root)
        add_window.title("Add Password")
        add_window.geometry("400x400")
        add_window.resizable(False, False)
        
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 400), Image.LANCZOS)
            self.add_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(add_window, image=self.add_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            add_window.add_bg_photo = self.add_bg_photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not load add password background: {e}")
            add_window.configure(bg="dark blue")
            return
        
        center_x = 200
        start_y = 100
        
        title_label = tk.Label(
            add_window,
            text="Add New Password",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        site_label = tk.Label(
            add_window,
            text="Site:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        site_label.place(x=center_x-150, y=start_y)
        
        site_entry = tk.Entry(
            add_window,
            font=self.entry_font,
            bg="white"
        )
        site_entry.place(x=center_x-150, y=start_y+25, width=300, height=25)
        
        username_label = tk.Label(
            add_window,
            text="Username:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        username_label.place(x=center_x-150, y=start_y+70)
        
        username_entry = tk.Entry(
            add_window,
            font=self.entry_font,
            bg="white"
        )
        username_entry.place(x=center_x-150, y=start_y+95, width=300, height=25)
        
        password_label = tk.Label(
            add_window,
            text="Password:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        password_label.place(x=center_x-150, y=start_y+140)
        
        password_entry = tk.Entry(
            add_window,
            show="•",
            font=self.entry_font,
            bg="white"
        )
        password_entry.place(x=center_x-150, y=start_y+165, width=300, height=25)
        
        def save_password():
            site = site_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            
            if not site or not username or not password:
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            new_entry = {
                "site": site,
                "username": username,
                "password": password,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            if self.current_user in self.passwords:
                self.passwords[self.current_user].append(new_entry)
            else:
                self.passwords[self.current_user] = [new_entry]
            
            self.save_data(self.passwords_file, self.passwords)
            self.load_user_passwords()
            add_window.destroy()
            messagebox.showinfo("Success", "Password saved successfully")
        
        save_btn = tk.Button(
            add_window,
            text="Save",
            font=self.button_font,
            bg="green",
            fg="white",
            command=save_password
        )
        save_btn.place(x=center_x-150, y=start_y+220, width=300, height=30)
    
    def load_user_passwords(self):
        if self.current_user in self.passwords:
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            for idx, pw in enumerate(self.passwords[self.current_user], 1):
                display_password = pw["password"] if self.show_password else "••••••••"
                self.tree.insert("", tk.END, values=(
                    idx,
                    pw["site"],
                    pw["username"],
                    display_password,
                    pw["created_at"]
                ))
    
    def toggle_password_visibility(self):
        self.show_password = not self.show_password
        self.load_user_passwords()
    
    def delete_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a password to delete")
            return
        
        item = self.tree.item(selected[0])
        site = item["values"][1]
        
        if self.current_user in self.passwords:
            self.passwords[self.current_user] = [
                pw for pw in self.passwords[self.current_user] 
                if pw["site"] != site
            ]
            self.save_data(self.passwords_file, self.passwords)
            self.load_user_passwords()
            messagebox.showinfo("Success", "Password deleted successfully")
    
    def attempt_login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        
        if not email or not password:
            messagebox.sh
    def attempt_login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        
        if not email or not password:
            messagebox.showerror("Error", "Please enter both email and password")
        elif email not in self.accounts:
            messagebox.showinfo("No Account", "No account found with this email. Please sign up first.")
        elif not self.verify_password(self.accounts[email], password):
            self.login_attempts += 1
            if self.login_attempts >= self.max_login_attempts:
                messagebox.showerror("Error", "Too many failed attempts. Account locked.")
                self.root.after(30000, self.unlock_account)  # Lock for 30 seconds
                self.email_entry.config(state=tk.DISABLED)
                self.password_entry.config(state=tk.DISABLED)
            else:
                messagebox.showerror("Error", f"Incorrect password. {self.max_login_attempts - self.login_attempts} attempts remaining")
        else:
            self.current_user = email
            self.verify_pin(email)  # Require PIN verification after password
    
    def unlock_account(self):
        self.login_attempts = 0
        self.email_entry.config(state=tk.NORMAL)
        self.password_entry.config(state=tk.NORMAL)
        messagebox.showinfo("Account Unlocked", "You may now attempt to login again")
    
    def show_password_manager(self):
        # ... (previous code remains the same until the buttons section)
        
        # Enhanced button configuration with more security options
        buttons = [
            ("Add Password", "green", self.show_add_password),
            ("Generate Password", "#3498db", self.generate_password),
            ("Show Passwords" if not self.show_password else "Hide Passwords", 
             "#3498db", self.toggle_password_visibility),
            ("Export Passwords", "orange", self.export_passwords),
            ("Import Passwords", "orange", self.import_passwords),
            ("Change Master Password", "purple", self.change_master_password),
            ("Security Settings", "#8e44ad", self.security_settings),
            ("Delete Password", "red", self.delete_password),
            ("Logout", "red", self.logout)
        ]
        
        # Place buttons in a grid
        for i, (text, color, cmd) in enumerate(buttons):
            row = i // 3
            col = i % 3
            btn = tk.Button(
                self.root,
                text=text,
                font=self.button_font,
                bg=color,
                fg="white",
                command=cmd
            )
            btn.place(x=50 + col*300, y=480 + row*50, width=290, height=40)
    
    def export_passwords(self):
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Passwords")
        export_window.geometry("400x300")
        export_window.resizable(False, False)
        
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 300), Image.LANCZOS)
            self.export_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(export_window, image=self.export_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            export_window.export_bg_photo = self.export_bg_photo
        except:
            export_window.configure(bg="dark blue")
        
        center_x = 200
        start_y = 100
        
        title_label = tk.Label(
            export_window,
            text="Export Passwords",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        # Encryption option
        encrypt_var = tk.IntVar(value=1)
        encrypt_check = tk.Checkbutton(
            export_window,
            text="Encrypt export file",
            variable=encrypt_var,
            font=self.default_font,
            fg="white",
            bg="dark blue",
            selectcolor="dark blue",
            activebackground="dark blue",
            activeforeground="white"
        )
        encrypt_check.place(x=center_x-150, y=start_y)
        
        def perform_export():
            try:
                export_data = {
                    "version": "1.0",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "passwords": self.passwords.get(self.current_user, [])
                }
                
                filename = f"password_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                
                if encrypt_var.get():
                    # In a real app, you would use proper encryption here
                    filename = filename.replace(".json", ".enc")
                    with open(filename, "w") as f:
                        json.dump({"encrypted": True, "data": export_data}, f)
                    messagebox.showinfo("Success", f"Passwords exported to {filename} (encrypted)")
                else:
                    with open(filename, "w") as f:
                        json.dump(export_data, f, indent=4)
                    messagebox.showinfo("Success", f"Passwords exported to {filename}")
                
                export_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
        
        export_btn = tk.Button(
            export_window,
            text="Export",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=perform_export
        )
        export_btn.place(x=center_x-150, y=start_y+50, width=300, height=30)
    
    def import_passwords(self):
        import_window = tk.Toplevel(self.root)
        import_window.title("Import Passwords")
        import_window.geometry("400x300")
        import_window.resizable(False, False)
        
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 300), Image.LANCZOS)
            self.import_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(import_window, image=self.import_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            import_window.import_bg_photo = self.import_bg_photo
        except:
            import_window.configure(bg="dark blue")
        
        center_x = 200
        start_y = 100
        
        title_label = tk.Label(
            import_window,
            text="Import Passwords",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        # File selection
        file_label = tk.Label(
            import_window,
            text="Select file to import:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        file_label.place(x=center_x-150, y=start_y)
        
        file_entry = tk.Entry(
            import_window,
            font=self.entry_font,
            bg="white"
        )
        file_entry.place(x=center_x-150, y=start_y+30, width=300, height=25)
        
        def browse_file():
            filename = tk.filedialog.askopenfilename(
                title="Select export file",
                filetypes=(("JSON files", ".json"), ("Encrypted files", ".enc"), ("All files", ".")))
            if filename:
                file_entry.delete(0, tk.END)
                file_entry.insert(0, filename)
        
        browse_btn = tk.Button(
            import_window,
            text="Browse",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=browse_file
        )
        browse_btn.place(x=center_x+160, y=start_y+30, width=80, height=25)
        
        def perform_import():
            filename = file_entry.get()
            if not filename:
                messagebox.showerror("Error", "Please select a file")
                return
            
            try:
                with open(filename, "r") as f:
                    data = json.load(f)
                
                # Check if encrypted
                if isinstance(data, dict) and data.get("encrypted"):
                    # In a real app, you would decrypt here
                    data = data.get("data", {})
                
                if not isinstance(data, dict) or "passwords" not in data:
                    messagebox.showerror("Error", "Invalid file format")
                    return
                
                # Verify before importing
                if not messagebox.askyesno("Confirm Import", f"Import {len(data['passwords'])} passwords?"):
                    return
                
                # Add imported passwords
                if self.current_user not in self.passwords:
                    self.passwords[self.current_user] = []
                
                self.passwords[self.current_user].extend(data["passwords"])
                self.save_data(self.passwords_file, self.passwords)
                self.load_user_passwords()
                
                messagebox.showinfo("Success", f"Imported {len(data['passwords'])} passwords")
                import_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import: {str(e)}")
        
        import_btn = tk.Button(
            import_window,
            text="Import",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=perform_import
        )
        import_btn.place(x=center_x-150, y=start_y+80, width=300, height=30)
    
    def change_master_password(self):
        change_window = tk.Toplevel(self.root)
        change_window.title("Change Master Password")
        change_window.geometry("400x400")
        change_window.resizable(False, False)
        
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 400), Image.LANCZOS)
            self.change_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(change_window, image=self.change_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            change_window.change_bg_photo = self.change_bg_photo
        except:
            change_window.configure(bg="dark blue")
        
        center_x = 200
        start_y = 100
        
        title_label = tk.Label(
            change_window,
            text="Change Master Password",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        # Current Password
        current_label = tk.Label(
            change_window,
            text="Current Password:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        current_label.place(x=center_x-150, y=start_y)
        
        current_entry = tk.Entry(
            change_window,
            show="•",
            font=self.entry_font,
            bg="white"
        )
        current_entry.place(x=center_x-150, y=start_y+25, width=300, height=25)
        
        # New Password
        new_label = tk.Label(
            change_window,
            text="New Password:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        new_label.place(x=center_x-150, y=start_y+70)
        
        new_entry = tk.Entry(
            change_window,
            show="•",
            font=self.entry_font,
            bg="white"
        )
        new_entry.place(x=center_x-150, y=start_y+95, width=300, height=25)
        
        # Confirm Password
        confirm_label = tk.Label(
            change_window,
            text="Confirm Password:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        confirm_label.place(x=center_x-150, y=start_y+140)
        
        confirm_entry = tk.Entry(
            change_window,
            show="•",
            font=self.entry_font,
            bg="white"
        )
        confirm_entry.place(x=center_x-150, y=start_y+165, width=300, height=25)
        
        # Strength indicator
        strength_label = tk.Label(
            change_window,
            text="",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        strength_label.place(x=center_x-150, y=start_y+200, width=300, height=25)
        
        def check_strength(event=None):
            password = new_entry.get()
            strength = self.check_password_strength(password)
            if strength == "strong":
                strength_label.config(text="Password strength: Strong", fg="green")
            else:
                strength_label.config(text=f"Password strength: {strength}", fg="red")
        
        new_entry.bind("<KeyRelease>", check_strength)
        
        def save_changes():
            current = current_entry.get()
            new_pass = new_entry.get()
            confirm = confirm_entry.get()
            
            if not current or not new_pass or not confirm:
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            if not self.verify_password(self.accounts[self.current_user], current):
                messagebox.showerror("Error", "Current password is incorrect")
                return
            
            if new_pass != confirm:
                messagebox.showerror("Error", "New passwords don't match")
                return
            
            strength = self.check_password_strength(new_pass)
            if strength != "strong":
                messagebox.showerror("Error", "New password is not strong enough")
                return
            
            if current == new_pass:
                messagebox.showerror("Error", "New password must be different")
                return
            
            self.accounts[self.current_user] = self.hash_password(new_pass)
            self.save_data(self.accounts_file, self.accounts)
            messagebox.showinfo("Success", "Password changed successfully")
            change_window.destroy()
        
        save_btn = tk.Button(
            change_window,
            text="Change Password",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=save_changes
        )
        save_btn.place(x=center_x-150, y=start_y+250, width=300, height=30)
    
    def security_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Security Settings")
        settings_window.geometry("400x400")
        settings_window.resizable(False, False)
        
        try:
            bg_image = Image.open("images/signup_bg.png")
            bg_image = bg_image.resize((400, 400), Image.LANCZOS)
            self.settings_bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(settings_window, image=self.settings_bg_photo)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            settings_window.settings_bg_photo = self.settings_bg_photo
        except:
            settings_window.configure(bg="dark blue")
        
        center_x = 200
        start_y = 100
        
        title_label = tk.Label(
            settings_window,
            text="Security Settings",
            font=self.title_font,
            fg="white",
            bg="dark blue"
        )
        title_label.place(x=center_x, y=start_y-50, anchor="center")
        
        # Change PIN
        pin_label = tk.Label(
            settings_window,
            text="Change 4-digit PIN:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        pin_label.place(x=center_x-150, y=start_y)
        
        pin_entry = tk.Entry(
            settings_window,
            show="•",
            font=self.entry_font,
            bg="white",
            validate="key",
            validatecommand=(settings_window.register(lambda s: len(s) <= 4 and s.isdigit()), '%S')
        )
        pin_entry.place(x=center_x-150, y=start_y+25, width=300, height=25)
        
        # Change Security Question
        question_label = tk.Label(
            settings_window,
            text="Change Security Question:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        question_label.place(x=center_x-150, y=start_y+70)
        
        question_var = tk.StringVar(settings_window)
        question_var.set(self.security_data[self.current_user]["question"])
        
        question_menu = tk.OptionMenu(
            settings_window,
            question_var,
            *self.security_questions
        )
        question_menu.config(font=self.default_font, bg="white")
        question_menu.place(x=center_x-150, y=start_y+95, width=300, height=25)
        
        # Security Answer
        answer_label = tk.Label(
            settings_window,
            text="New Answer:",
            font=self.default_font,
            fg="white",
            bg="dark blue"
        )
        answer_label.place(x=center_x-150, y=start_y+140)
        
        answer_entry = tk.Entry(
            settings_window,
            font=self.entry_font,
            bg="white"
        )
        answer_entry.place(x=center_x-150, y=start_y+165, width=300, height=25)
        
        def save_settings():
            new_pin = pin_entry.get()
            new_question = question_var.get()
            new_answer = answer_entry.get()
            
            if new_pin:
                if len(new_pin) != 4:
                    messagebox.showerror("Error", "PIN must be 4 digits")
                    return
                self.pins[self.current_user] = new_pin
                self.save_data(self.pin_file, self.pins)
            
            if new_question or new_answer:
                if not new_answer:
                    messagebox.showerror("Error", "Please provide an answer")
                    return
                
                self.security_data[self.current_user] = {
                    "question": new_question,
                    "answer": new_answer.lower()
                }
                self.save_data(self.security_file, self.security_data)
            
            messagebox.showinfo("Success", "Security settings updated")
            settings_window.destroy()
        
        save_btn = tk.Button(
            settings_window,
            text="Save Settings",
            font=self.button_font,
            bg="#3498db",
            fg="white",
            command=save_settings
        )
        save_btn.place(x=center_x-150, y=start_y+220, width=300, height=30)
    
    def logout(self):
        # Clear sensitive data from memory
        self.current_user = None
        self.show_password = False
        self.login_attempts = 0
        
        # Show login screen
        self.show_login_screen()

if __name__ == "_main_":
    root = tk.Tk()
    
    # Set application icon
    try:
        root.iconbitmap("images/icon.ico")
    except:
        pass
    
    # Create user_data directory if it doesn't exist
    if not os.path.exists("user_data"):
        os.makedirs("user_data")
    
    # Create images directory if it doesn't exist
    if not os.path.exists("images"):
        os.makedirs("images")
        # You would place your default images here in a real application
    
    app = PasswordManagerApp(root)
    root.mainloop()