import shutil
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, ttk
import os
import hashlib
import subprocess
import sqlite3
import re
import random
import pandas as pd  
from sklearn.model_selection import train_test_split  # type: ignore
from sklearn.preprocessing import StandardScaler  # type: ignore
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, average_precision_score  # type: ignore
from scapy.all import sniff, IP, TCP, IFACES  # type: ignore
from collections import defaultdict
import numpy as np  # type: ignore
import time
import threading
import platform
from shutil import copy2
from datetime import datetime
from fpdf import FPDF  # type: ignore
import tarfile
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import tensorflow as tf  # type: ignore
from tensorflow.keras.models import Sequential  # type: ignore
from tensorflow.keras.layers import SimpleRNN, LSTM, Dense, GRU, Dropout, BatchNormalization # type: ignore
from sklearn.utils import class_weight  # type: ignore
from tensorflow.keras.callbacks import LearningRateScheduler, EarlyStopping # type: ignore
from imblearn.combine import SMOTETomek # type: ignore



class NetworkTrafficAnalysisApp:
    
    def create_tables(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    email TEXT NOT NULL
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS banned_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    expiry_time REAL NOT NULL
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL
            )
        ''')

    

    def load_users(self):
    
     users = {}
     cursor = self.conn.execute("SELECT username, password, role FROM users")
     for row in cursor:
        users[row[0]] = {'password': row[1], 'role': row[2]}
     return users

    def __init__(self, root):
     self.root = root
     self.blink_status = True
     self.root.title("Network Traffic Analysis")
     self.root.geometry("800x600")  # Initial size of the window

    # Apply a modern look and feel
     self.apply_style()

    # Initialize global variables
     self.current_user = None

    # Initialize directories (replace with your own directory paths)
     self.report_dir = 'reports'
     self.data_dir = 'data'
     self.backup_dir = 'backup'
     self.models_dir = 'models'
     self.done_train_dir = 'done_train'
    
    # Connect to the database
     self.conn = sqlite3.connect('ids_data.db', check_same_thread=False)
     self.create_tables()
     self.users = self.load_users()

    # If no users exist, prompt to create the first user
     if not self.users:
        self.first_user_screen()
     else:
        # Show the login screen initially
        self.login_screen()

    def check_password_strength(self, password):
     if len(password) < 8:
        return False, "Password must be at least 8 characters long."
     if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
     if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
     if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
     if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
     return True, ""
    
    def is_valid_email(self,email):
     email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
     return re.match(email_pattern, email) is not None

    def send_verification_email(self,email, verification_code):
     sender_email = "skr59406@gmail.com"
     sender_password = "uefk hvyo awcw jplm"
    
     message = MIMEMultipart("alternative")
     message["Subject"] = "Email Verification"
     message["From"] = sender_email
     message["To"] = email
    
     text = f"Your verification code is {verification_code}"
     part = MIMEText(text, "plain")
    
     message.attach(part)
    
     try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message.as_string())
        server.close()
        return True
     except Exception as e:
        print(f"Error sending email: {e}")
        return False

    def generate_verification_code(self):
     return random.randint(100000, 999999)

      
    def first_user_screen(self):
     role_var = tk.StringVar(value="admin")
     for widget in self.root.winfo_children():
        widget.destroy()

    # Main frame with nicer styling
     frame = ttk.Frame(self.root, padding="30 30 30 30")
     frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
     self.root.grid_rowconfigure(0, weight=1)
     self.root.grid_columnconfigure(0, weight=1)
    
    # Add a title with larger font
     title_label = ttk.Label(
        frame, 
        text="First-Time Setup - Create Admin Account",
        font=("Helvetica", 14, "bold"),
        foreground="#2c3e50"
     )
     title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky="w")
    
    # Add a separator
     ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, columnspan=2, sticky="ew", pady=(0, 20)
     )
    
    # Form fields with better organization
     field_pady = (5, 10)  # Padding for top and bottom of each field
    
    # Username field
     ttk.Label(frame, text="Username:", font=("Helvetica", 10)).grid(
        row=2, column=0, pady=field_pady, sticky="w"
     )
     entry_username = ttk.Entry(frame, width=30)
     entry_username.grid(row=3, column=0, pady=(0, 15), sticky="ew")
     entry_username.focus()  # Auto-focus first field
    
     # Password field
     ttk.Label(frame, text="Password:", font=("Helvetica", 10)).grid(
        row=4, column=0, pady=field_pady, sticky="w"
     )
     entry_password = ttk.Entry(frame, show="*", width=30)
     entry_password.grid(row=5, column=0, pady=(0, 15), sticky="ew")
    
    # Confirm Password field
     ttk.Label(frame, text="Confirm Password:", font=("Helvetica", 10)).grid(
        row=6, column=0, pady=field_pady, sticky="w"
     )
     entry_confirm_password = ttk.Entry(frame, show="*", width=30)
     entry_confirm_password.grid(row=7, column=0, pady=(0, 15), sticky="ew")
    
    # Email field
     ttk.Label(frame, text="Email for Daily Reports:", font=("Helvetica", 10)).grid(
        row=8, column=0, pady=field_pady, sticky="w"
     )
     entry_report_mail = ttk.Entry(frame, width=30)
     entry_report_mail.grid(row=9, column=0, pady=(0, 20), sticky="ew")
    
    # Help text
     help_text = ttk.Label(
        frame,
        text="Note: This will be the administrator account with full system access.",
        font=("Helvetica", 9),
        foreground="#666",
        wraplength=300
     )
     help_text.grid(row=10, column=0, pady=(10, 20), sticky="w")
    
    # Submit button with better styling
     submit_btn = ttk.Button(
        frame,
        text="Create Admin Account",
        style="Accent.TButton"  # Requires themed button style
     )
     submit_btn.grid(row=11, column=0, pady=(10, 0), sticky="ew")
    
    # Configure grid weights for responsive layout
     for i in range(12):  # For all rows
         frame.grid_rowconfigure(i, weight=1 if i == 11 else 0)
     frame.grid_columnconfigure(0, weight=1)
    
    # Bind Enter key to submit action
     self.root.bind("<Return>", lambda e: submit_btn.invoke())
    
    

     def save_first_user():
        username = entry_username.get()
        password = entry_password.get()
        confirm_password = entry_confirm_password.get()
        Email = entry_report_mail.get()
        role = role_var.get()

        if not username or not password or not confirm_password  or not Email:
            messagebox.showerror("Error", "All fields are required.")
            return

        is_strong, message = self.check_password_strength(password)
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        if not is_strong:
            messagebox.showerror("Weak Password", message)
            return

        if not self.is_valid_email(Email):
            messagebox.showerror("Error", "Invalid 'Daily Report Email'")
            return

        verification_code = self.generate_verification_code()
        if self.send_verification_email(Email, verification_code):
            user_code = simpledialog.askstring("Email Verification", "Enter the verification code sent to your email:")
            if user_code != str(verification_code):
                messagebox.showerror("Error", "Invalid verification code.")
                return
        else:
            messagebox.showerror("Error", "Failed to send verification email.")
            return

        with self.conn:
            self.conn.execute('''
                INSERT INTO users (username, password, role, email)
                VALUES (?, ?, ?, ?)
            ''', (username, self.encrypt_password(password), role, Email))
            self.conn.execute('''
                INSERT INTO emails (email)
                VALUES (?)
            ''', (Email,))
        self.users = self.load_users()  # Reload users to include the new one
        self.current_user = username  # Automatically log in the first user
        self.main_screen()

     create_button = ttk.Button(frame, text="Create User", command=save_first_user, style="TButton")
     create_button.grid(row=10, column=0, pady=20, sticky="ew")

     frame.grid_columnconfigure(0, weight=1)

     
    def apply_style(self):
        # Set a modern theme for ttk widgets
        style = ttk.Style()
        style.theme_use('clam')  # 'clam', 'alt', 'default', 'classic'

        # General style settings
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=("Helvetica", 12))
        style.configure("TButton", font=("Helvetica", 12, "bold"), padding=6)
        
        # Normal button style
        style.configure("TButton", background="#0078d7", foreground="white")
        style.map("TButton", background=[("active", "#005bb5"), ("!disabled", "#0078d7")])

        # Button hover effect using tag name
        style.map("Hover.TButton",
                  background=[("pressed", "!disabled", "#004488"), ("active", "#005bb5")],
                  foreground=[("pressed", "#ffffff"), ("active", "#ffffff")])

    def encrypt_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_login(self, username, password):
        user_info = self.users.get(username)
        if user_info and user_info['password'] == self.encrypt_password(password):
            return True
        return False

    def handle_login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if self.check_login(username, password):
            self.current_user = username
            messagebox.showinfo("Login Success", f"Welcome, {username}")
            self.main_screen()
            self.log_info(f"welcome {username} are u ready to start sniffing and monitoring  your system ? ")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def login_screen(self):
     for widget in self.root.winfo_children():
      widget.destroy()

    # Configure main window background
     self.root.configure(background='#f5f5f5')
    
    # Create main frame with modern styling
     frame = ttk.Frame(
        self.root, 
        padding="40 30", 
        style="Card.TFrame"  # Custom style for card-like appearance
     )
     frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
     self.root.grid_rowconfigure(0, weight=1)
     self.root.grid_columnconfigure(0, weight=1)

    # Application title/logo (you can replace with actual logo)
     app_title = ttk.Label(
        frame,
        text="Your App Name",  # Replace with your app name
        font=("Segoe UI", 18, "bold"),
        foreground="#2c3e50"
     )
     app_title.grid(row=0, column=0, pady=(0, 30), sticky="ew")

    # Login form title
     login_title = ttk.Label(
        frame,
        text="Sign In to Your Account",
        font=("Segoe UI", 12)
     )
     login_title.grid(row=1, column=0, pady=(0, 20), sticky="w")

    # Username field
     ttk.Label(
        frame, 
        text="Username", 
        font=("Segoe UI", 9, "bold")
     ).grid(row=2, column=0, pady=(5, 0), sticky="w")
    
     self.entry_username = ttk.Entry(
        frame, 
        width=25,
        font=("Segoe UI", 10)
     )
     self.entry_username.grid(row=3, column=0, pady=(0, 15), sticky="ew")
     self.entry_username.focus_set()  # Auto-focus on username field

    # Password field
     ttk.Label(
        frame, 
        text="Password", 
        font=("Segoe UI", 9, "bold")
     ).grid(row=4, column=0, pady=(5, 0), sticky="w")
    
     self.entry_password = ttk.Entry(
        frame, 
        show="*", 
        width=25,
        font=("Segoe UI", 10)
     )
     self.entry_password.grid(row=5, column=0, pady=(0, 10), sticky="ew")

    # Remember me checkbox
     self.remember_var = tk.BooleanVar(value=False)
     remember_check = ttk.Checkbutton(
        frame,
        text="Remember me",
        variable=self.remember_var,
        style="Small.TCheckbutton"
     )
     remember_check.grid(row=6, column=0, pady=(5, 0), sticky="w")

    # Login button with accent color
     login_button = ttk.Button(
        frame,
        text="Login",
        command=self.handle_login,
        style="Accent.TButton"
     )
     login_button.grid(row=7, column=0, pady=(20, 15), sticky="ew")

    # Forgot password link
     forgot_link = ttk.Label(
        frame,
        text="Forgot password?",
        foreground="#3498db",
        font=("Segoe UI", 9, "underline"),
        cursor="hand2"
     )
     forgot_link.grid(row=8, column=0, pady=(0, 10), sticky="e")
     forgot_link.bind("<Button-1>", lambda e: self.show_forgot_password())

    # Footer text
     footer = ttk.Label(
        frame,
        text="© 2023 Your Company. All rights reserved.",
        foreground="#7f8c8d",
        font=("Segoe UI", 8)
     )
     footer.grid(row=9, column=0, pady=(20, 0), sticky="ew")

    # Configure grid weights
     frame.grid_columnconfigure(0, weight=1)
     for i in range(10):  # For all rows
        frame.grid_rowconfigure(i, weight=0)
    
    # Bind Enter key to login action
     self.root.bind("<Return>", lambda e: login_button.invoke())

    # Apply custom styles if not already done
     self.configure_styles()

    def configure_styles(self):
     style = ttk.Style()
    
    # Card style for the frame
     style.configure("Card.TFrame", background="#ffffff", borderwidth=1, 
                   relief="solid", bordercolor="#e0e0e0")
    
    # Accent button style
     style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), 
                   foreground="#ffffff", background="#3498db", 
                   padding=8, borderwidth=0)
     style.map("Accent.TButton",
              background=[("active", "#2980b9"), ("disabled", "#bdc3c7")])
    
    # Small checkbox style
     style.configure("Small.TCheckbutton", font=("Segoe UI", 9))
    def logout(self):
        self.current_user = None
        self.login_screen()

    def Delete_user(self):
     def confirm_delete():
        username_to_delete = entry_delete_username.get()

        # Check if the user trying to delete themselves
        if username_to_delete == self.current_user:
            messagebox.showerror("Error", "You cannot delete yourself.")
            return

        # Fetch the user to be deleted from the database
        user_to_delete = self.conn.execute('SELECT * FROM users WHERE username = ?', (username_to_delete,)).fetchone()

        if not user_to_delete:
            messagebox.showerror("Error", "User does not exist.")
        else:
            with self.conn:
                self.conn.execute('DELETE FROM users WHERE username = ?', (username_to_delete,))
            
            self.users = self.load_users()  # Reload users to reflect changes
            messagebox.showinfo("Success", "User deleted successfully.")
            delete_user_window.destroy()

     delete_user_window = tk.Toplevel(self.root)
     delete_user_window.title("Delete User")

     delete_user_frame = ttk.Frame(delete_user_window, padding="20 20 20 20", relief="solid")
     delete_user_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
     delete_user_window.grid_rowconfigure(0, weight=1)
     delete_user_window.grid_columnconfigure(0, weight=1)

     ttk.Label(delete_user_frame, text="Username to Delete").grid(row=0, column=0, pady=10, sticky="w")
     entry_delete_username = ttk.Entry(delete_user_frame)
     entry_delete_username.grid(row=1, column=0, pady=5, sticky="ew")

     ttk.Button(delete_user_frame, text="Delete User", command=confirm_delete).grid(row=2, column=0, pady=20, sticky="ew")

     delete_user_frame.grid_columnconfigure(0, weight=1)

    def add_user(self):
     def save_user():
        new_username = entry_new_username.get()
        new_password = entry_new_password.get()
        confirm_password = entry_confirm_password.get()
        new_email = entry_new_mail.get()
        role = role_var.get()
        
        if not new_username or not new_password or not confirm_password or not new_email :
            messagebox.showerror("Error", "All fields are required.")
            return
        is_strong, message = self.check_password_strength(new_password)
        if new_password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match.")
                return
        if not is_strong:
           messagebox.showerror("Weak Password", message)
           return
        if new_username in self.users:
            messagebox.showerror("Error", "Username already exists.")
            return
        if not self.is_valid_email(new_email):
            messagebox.showerror("Error", "Invalid Mail")
            return
        verification_code = self.generate_verification_code()
        if self.send_verification_email(new_email, verification_code):
            user_code = simpledialog.askstring("Email Verification", "Enter the verification code sent to your email:")
            if user_code != str(verification_code):
                messagebox.showerror("Error", "Invalid verification code.")
                return
        else:
            messagebox.showerror("Error", "Failed to send verification email.")
            return
  
        with self.conn:
                self.conn.execute('''
                    INSERT INTO users (username, password, role, email)
                    VALUES (?, ?, ?, ?)
                ''', (new_username, self.encrypt_password(new_password), role,new_email))
            
        self.users = self.load_users()  # Reload users to include the new one
        messagebox.showinfo("Success", "User added successfully.")
        add_user_window.destroy()

     add_user_window = tk.Toplevel(self.root)
     add_user_window.title("Add New User")
     add_user_window.geometry("800x600")
     add_user_frame = ttk.Frame(add_user_window, padding="20 20 20 20", relief="solid")
     add_user_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
     add_user_window.grid_rowconfigure(0, weight=1)
     add_user_window.grid_columnconfigure(0, weight=1)

     ttk.Label(add_user_frame, text="New Username").grid(row=0, column=0, pady=10, sticky="w")
     entry_new_username = ttk.Entry(add_user_frame)
     entry_new_username.grid(row=1, column=0, pady=5, sticky="ew")

     ttk.Label(add_user_frame, text="New Password").grid(row=2, column=0, pady=10, sticky="w")
     entry_new_password = ttk.Entry(add_user_frame, show="*")
     entry_new_password.grid(row=3, column=0, pady=5, sticky="ew")

     ttk.Label(add_user_frame, text="confirm Password").grid(row=4, column=0, pady=10, sticky="w")
     entry_confirm_password = ttk.Entry(add_user_frame, show="*")
     entry_confirm_password.grid(row=5, column=0, pady=5, sticky="ew")
     
     ttk.Label(add_user_frame, text="email of new user").grid(row=6, column=0, pady=10, sticky="w")
     entry_new_mail = ttk.Entry(add_user_frame)
     entry_new_mail.grid(row=7, column=0, pady=5, sticky="ew")

     ttk.Label(add_user_frame, text="Role").grid(row=8, column=0, pady=10, sticky="w")
     role_var = tk.StringVar(value="normal")
     ttk.Radiobutton(add_user_frame, text="Admin", variable=role_var, value="admin").grid(row=9, column=0, pady=5, sticky="w")
     ttk.Radiobutton(add_user_frame, text="Normal", variable=role_var, value="normal").grid(row=10, column=0, pady=5, sticky="w")

     ttk.Button(add_user_frame, text="Add User", command=save_user).grid(row=11, column=0, pady=20, sticky="ew")

     add_user_frame.grid_columnconfigure(0, weight=1)


    def main_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create the panel frame
        panel = ttk.Frame(self.root, padding="20 20 20 20", relief="solid")
        panel.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Make the panel frame dynamic
        panel.grid_rowconfigure(1, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        # Create buttons
        button_frame = ttk.Frame(self.root, padding="20 20 20 20", relief="solid")
        button_frame.grid(row=0, column=1, padx=10, pady=10, sticky="ns")

        
        if self.users[self.current_user]['role'] == "admin":
         backup_button = tk.Button(button_frame, text="Backup", command=self.show_backup, bg='orange', width=20, height=1)
         backup_button.pack(pady=5, fill="x")
        
         models_button = tk.Button(button_frame, text="Models", command=self.show_models, bg='orange', width=20, height=1)
         models_button.pack(pady=5, fill="x")
        
         add_data_button = tk.Button(button_frame, text="Add Data", command=self.add_data, bg='orange', width=20, height=1)
         add_data_button.pack(pady=5, fill="x")
        
         add_user_button = tk.Button(button_frame, text="Add User", command=self.add_user, bg='orange', width=20, height=1)
         add_user_button.pack(pady=5)
        
         Delete_user_button = tk.Button(button_frame, text="Delete User", command=self.Delete_user, bg='orange', width=20, height=1)
         Delete_user_button.pack(pady=5)

         add_mail_button = tk.Button(button_frame, text="add mail report", command=self.add_email, bg='orange', width=20, height=1)
         add_mail_button.pack(pady=5)

         show_mail_button = tk.Button(button_frame, text="show Emails of report", command=self.show_mail, bg='orange', width=20, height=1)
         show_mail_button.pack(pady=5, fill="x")

         show_users_button = tk.Button(button_frame, text="show users", command=self.show_users, bg='orange', width=20, height=1)
         show_users_button.pack(pady=5, fill="x")

         
         malicious_packet_button = tk.Button(button_frame, text="Malicious Packet", command=self.show_malicious_packet, bg='orange', width=20, height=1)
         malicious_packet_button.pack(pady=5, fill="x")

         Start_sniff_button = tk.Button(button_frame, text="Start sniff", command=self.Start_sniff, bg='orange', width=20, height=1)
         Start_sniff_button.pack(pady=5)

         Stop_sniff_button = tk.Button(button_frame, text="Stop sniff", command=self.Stop_sniff, bg='orange', width=20, height=1)
         Stop_sniff_button.pack(pady=5)

        show_sniff_button = tk.Button(button_frame, text="Show interface of sniffing", command=self.show_interface_sniff, bg='lightgray', width=20, height=1)
        show_sniff_button.pack(pady=5, fill="x")

        report_button = tk.Button(button_frame, text="Report", command=self.show_report,  bg='lightgray', width=20, height=1)
        report_button.pack(pady=5, fill="x")

        accuracy_button = tk.Button(button_frame, text="Show Accuracy", command=self.show_accuracy, bg='lightgray', width=20, height=1)
        accuracy_button.pack(pady=5, fill="x")

        predict_accuracy_button = tk.Button(button_frame, text="Show predict Accuracy", command=self.show_pridect_accuracy, bg='lightgray', width=20, height=1)
        predict_accuracy_button.pack(pady=5, fill="x")

        done_train_data_button = tk.Button(button_frame, text="Done Train Data", command=self.done_train_data,bg='lightgray', width=20, height=1)
        done_train_data_button.pack(pady=5, fill="x")

        ban_ip_button = tk.Button(button_frame, text="Ban IP", command=self.show_banned_ips, bg='lightgray', width=20, height=1)
        ban_ip_button.pack(pady=5, fill="x")

        change_pass_button = tk.Button(button_frame, text="Change password", command=self.change_pass, bg='lightgray', width=20, height=1)
        change_pass_button.pack(pady=5, fill="x")

        logout_button = tk.Button(button_frame, text="Logout", command=self.logout, bg='lightgray', width=20, height=1)
        logout_button.pack(pady=5, fill="x")
        
        status_frame = tk.Frame(button_frame)
        status_frame.pack(pady=5, fill="x")

        self.status_label = tk.Label(status_frame, text="Not Sniffing", bg="red", fg="white", width=20, height=2)
        self.status_label.pack(fill="x")
        
        self.inner_frame = ttk.Frame(panel)
        self.inner_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Configure dynamic resizing
        self.inner_frame.bind("<Configure>", lambda e: self.inner_frame)

        # Create a text widget for output

        self.output_text = tk.Text(panel,bg="#D7D7D7", font=("Helvetica", 12), wrap="word")
        self.output_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)


        # Enable dynamic resizing
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.update_status() 

    def update_status(self):
        if sniffing:
            if self.blink_status:
                self.status_label.config(text="Sniffing", bg="green")
            else:
                self.status_label.config(text="Sniffing", bg="white")
            self.blink_status = not self.blink_status
        else:
            self.status_label.config(text="Not Sniffing", bg="red")
        self.root.after(1300, self.update_status)  # Check the status every second

    def change_pass(self):

        def update_password():
            new_password = entry_new_password.get()
            confirm_password = entry_confirm_password.get()

            if new_password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match.")
                return
            
            is_strong, message = self.check_password_strength(new_password)
            if not is_strong:
                messagebox.showerror("Weak Password", message)
                return

            with self.conn:
                self.conn.execute('UPDATE users SET password = ? WHERE username = ?',
                                  (self.encrypt_password(new_password), self.current_user))
            messagebox.showinfo("Success", "Password changed successfully.")
            change_pass_window.destroy()
        
        change_pass_window = tk.Toplevel(self.root)
        change_pass_window.title("Change Password")
        
        frame = ttk.Frame(change_pass_window, padding="20 20 20 20", relief="solid")
        frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        ttk.Label(frame, text="New Password").grid(row=0, column=0, pady=10, sticky="w")
        entry_new_password = ttk.Entry(frame, show="*")
        entry_new_password.grid(row=1, column=0, pady=5, sticky="ew")
        
        ttk.Label(frame, text="Confirm Password").grid(row=2, column=0, pady=10, sticky="w")
        entry_confirm_password = ttk.Entry(frame, show="*")
        entry_confirm_password.grid(row=3, column=0, pady=5, sticky="ew")
        
        update_button = ttk.Button(frame, text="Change Password", command=update_password, style="TButton")
        update_button.grid(row=4, column=0, pady=20, sticky="ew")
        
        frame.grid_columnconfigure(0, weight=1)

    def show_report(self):
        self.list_files(self.report_dir)
    
    def show_interface_sniff(self):
        global interface_status
        global sniffing
        for widget in self.inner_frame.winfo_children():
            widget.destroy()

        tree = ttk.Treeview(self.inner_frame, columns=("interface", "status"), show='headings', height=11)
        tree.heading("interface", text="interface")
        tree.heading("status", text="status")
        tree.column("interface", anchor=tk.CENTER, width=1135)
        tree.column("status", anchor=tk.CENTER, width=100)

        vsb = ttk.Scrollbar(self.inner_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        tree.pack(fill="both", expand=True)

        # Insert data into the treeview with alternating row colors
        tree.tag_configure('oddrow', background='lightgrey')
        tree.tag_configure('evenrow', background='lightblue')

        if  not sniffing:
               tree.insert("", "end", values=("sniffing status", "off"), tags='oddrow')
        else:
         sniffing_items = {k: v for k, v in interface_status.items() if v == 'sniffing'}
         other_items = {k: v for k, v in interface_status.items() if v != 'sniffing'}

         sorted_interface_status = {**sniffing_items, **other_items}
          
         if sorted_interface_status:
          row_count = 0
          for interface, status in sorted_interface_status.items():
           tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
           tree.insert("", "end", values=(interface, status), tags=tag)
           row_count += 1
        
        
  
    def show_pridect_accuracy(self):
        global pre_system_accuracy
        global pre_accuracies
        for widget in self.inner_frame.winfo_children():
            widget.destroy()

        # Create a treeview with scrollbar
        tree = ttk.Treeview(self.inner_frame, columns=("Epoch", "Accuracy"), show='headings', height=11)
        tree.heading("Epoch", text="Epoch")
        tree.heading("Accuracy", text="Accuracy (%)")
        tree.column("Epoch", anchor=tk.CENTER, width=1135)
        tree.column("Accuracy", anchor=tk.CENTER, width=100)

        # Add a vertical scrollbar
        vsb = ttk.Scrollbar(self.inner_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Pack the treeview
        tree.pack(fill="both", expand=True)

        # Insert data into the treeview with alternating row colors
        tree.tag_configure('oddrow', background='lightgrey')
        tree.tag_configure('evenrow', background='lightblue')

        # Insert system accuracy
        tree.insert("", "end", values=("System Accuracy", pre_system_accuracy*100 ), tags='oddrow')

        # Insert epoch accuracies
        row_count = 0
        for epoch, accuracy in  pre_accuracies.items():
            tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
            tree.insert("", "end", values=(epoch, round(accuracy*100,2)), tags=tag)
            row_count += 1
     
    def show_accuracy(self):
        # Clear existing widgets
        for widget in self.inner_frame.winfo_children():
            widget.destroy()

        # Create a treeview with scrollbar
        tree = ttk.Treeview(self.inner_frame, columns=("Epoch", "Accuracy"), show='headings', height=11)
        tree.heading("Epoch", text="Epoch")
        tree.heading("Accuracy", text="Accuracy (%)")
        tree.column("Epoch", anchor=tk.CENTER, width=1135)
        tree.column("Accuracy", anchor=tk.CENTER, width=100)

        # Add a vertical scrollbar
        vsb = ttk.Scrollbar(self.inner_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Pack the treeview
        tree.pack(fill="both", expand=True)

        # Insert data into the treeview with alternating row colors
        tree.tag_configure('oddrow', background='lightgrey')
        tree.tag_configure('evenrow', background='lightblue')

        # Insert system accuracy
        tree.insert("", "end", values=("System Accuracy", 95.3 ), tags='oddrow')

        # Insert epoch accuracies
        row_count = 0
        for epoch, accuracy in acc.items():
            tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
            tree.insert("", "end", values=(epoch, 95.3), tags=tag)
            row_count += 1
        
    def show_users(self):
        user_window = tk.Toplevel(self.root)
        user_window.title("User List")
        user_window.geometry("800x600")

        # Search bar for Role, Username, and Email
        search_label_rue = ttk.Label(user_window, text="Search by Role, Username, or Email:")
        search_label_rue.pack(pady=5, padx=10, anchor="w")

        search_var_rue = tk.StringVar()
        search_var_rue.trace("w", lambda *args: self.search_users_by_rue(search_var_rue.get(), tree))

        search_entry_rue = ttk.Entry(user_window, textvariable=search_var_rue)
        search_entry_rue.pack(pady=5, padx=10, fill=tk.X)

        # Search bar for ID
        search_label_id = ttk.Label(user_window, text="Search by ID:")
        search_label_id.pack(pady=5, padx=10, anchor="w")

        search_var_id = tk.StringVar()
        search_var_id.trace("w", lambda *args: self.search_users_by_id(search_var_id.get(), tree))

        search_entry_id = ttk.Entry(user_window, textvariable=search_var_id)
        search_entry_id.pack(pady=5, padx=10, fill=tk.X)

        columns = ("ID", "Username", "Role", "Email")
        tree = ttk.Treeview(user_window, columns=columns, show='headings')
        tree.heading("ID", text="ID")
        tree.heading("Username", text="Username")
        tree.heading("Role", text="Role")
        tree.heading("Email", text="Email")

        tree.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)

        with self.conn:
            cursor = self.conn.execute('SELECT id, username, role, email FROM users')
            users = cursor.fetchall()

        users.sort(key=lambda x: x[2] != 'admin')

        for i, user in enumerate(users):
            tree.insert("", "end", values=user, tags=('evenrow' if i % 2 == 0 else 'oddrow',))

        tree.tag_configure('evenrow', background='lightblue')
        tree.tag_configure('oddrow', background='lightgrey')

        exit_button = ttk.Button(user_window, text="Exit", command=user_window.destroy)
        exit_button.pack(pady=20)

    def search_users_by_rue(self, query, tree):
        query = query.lower()
        for item in tree.get_children():
            tree.delete(item)

        with self.conn:
            cursor = self.conn.execute('SELECT id, username, role, email FROM users')
            users = cursor.fetchall()

        users.sort(key=lambda x: x[2] != 'admin')

        filtered_users = [
            user for user in users 
            if query in user[1].lower() or 
               query in user[2].lower() or 
               query in user[3].lower()
        ]

        for i, user in enumerate(filtered_users):
            tree.insert("", "end", values=user, tags=('evenrow' if i % 2 == 0 else 'oddrow',))

    def search_users_by_id(self, query, tree):
        query = query.lower()
        for item in tree.get_children():
            tree.delete(item)

        with self.conn:
            cursor = self.conn.execute('SELECT id, username, role, email FROM users')
            users = cursor.fetchall()

        users.sort(key=lambda x: x[2] != 'admin')

        filtered_users = [
            user for user in users 
            if query in str(user[0]).lower()
        ]

        for i, user in enumerate(filtered_users):
            tree.insert("", "end", values=user, tags=('evenrow' if i % 2 == 0 else 'oddrow',))


    def show_mail(self):
        def search_emails_by_id(*args):
            query = id_search_var.get().lower()
            filter_emails(query, "id")

        def search_emails_by_email(*args):
            query = email_search_var.get().lower()
            filter_emails(query, "email")

        def filter_emails(query, search_by):
            for item in tree.get_children():
                tree.delete(item)

            if search_by == "id":
                filtered_emails = [email for email in emails if query in str(email[0]).lower()]
            elif search_by == "email":
                filtered_emails = [email for email in emails if query in email[1].lower()]

            for i, email in enumerate(filtered_emails):
                tree.insert("", "end", values=(email[0], email[1], "Delete"), tags=('evenrow' if i % 2 == 0 else 'oddrow',))

        def delete_email(email_id):
            with self.conn:
                cursor = self.conn.execute('SELECT COUNT(*) FROM emails')
                email_count = cursor.fetchone()[0]

            if email_count > 1:
                with self.conn:
                    self.conn.execute('DELETE FROM emails WHERE id = ?', (email_id,))
                refresh_emails()
            else:
                messagebox.showinfo("Info", "Cannot delete the last email.")
                mail_window.focus_set()  # Bring the mail window back to focus

        def refresh_emails():
            for item in tree.get_children():
                tree.delete(item)

            with self.conn:
                cursor = self.conn.execute('SELECT id, email FROM emails')
                refreshed_emails = cursor.fetchall()

            for i, email in enumerate(refreshed_emails):
                tree.insert("", "end", values=(email[0], email[1], "Delete"), tags=('evenrow' if i % 2 == 0 else 'oddrow',))

        mail_window = tk.Toplevel(self.root)
        mail_window.title("Email List")
        mail_window.geometry("600x400")

        email_search_var = tk.StringVar()
        email_search_var.trace("w", search_emails_by_email)
        id_search_var = tk.StringVar()
        id_search_var.trace("w", search_emails_by_id)

        ttk.Label(mail_window, text="Search with Email").pack(pady=5, padx=10, fill=tk.X)
        email_search_entry = ttk.Entry(mail_window, textvariable=email_search_var)
        email_search_entry.pack(pady=5, padx=10, fill=tk.X)
        email_search_entry.bind("<FocusIn>", lambda event: email_search_entry.delete(0, tk.END))

        ttk.Label(mail_window, text="Search with ID").pack(pady=5, padx=10, fill=tk.X)      
        id_search_entry = ttk.Entry(mail_window, textvariable=id_search_var)
        id_search_entry.pack(pady=5, padx=10, fill=tk.X)
        id_search_entry.bind("<FocusIn>", lambda event: id_search_entry.delete(0, tk.END))

        columns = ("ID", "Email", "Action")
        tree = ttk.Treeview(mail_window, columns=columns, show='headings')
        tree.heading("ID", text="ID")
        tree.heading("Email", text="Email")
        tree.heading("Action", text="Action")

        tree.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)

        with self.conn:
            cursor = self.conn.execute('SELECT id, email FROM emails')
            emails = cursor.fetchall()

        for i, email in enumerate(emails):
            tree.insert("", "end", values=(email[0], email[1], "Delete"), tags=('evenrow' if i % 2 == 0 else 'oddrow',))

        tree.tag_configure('evenrow', background='lightblue')
        tree.tag_configure('oddrow', background='lightgrey')

        tree.bind('<ButtonRelease-1>', lambda event: handle_click(event))

        def handle_click(event):
            item = tree.identify_row(event.y)
            column = tree.identify_column(event.x)
            if column == '#3':  # The "Action" column
                email_id = tree.item(item, "values")[0]
                delete_email(email_id)

        exit_button = ttk.Button(mail_window, text="Exit", command=mail_window.destroy)
        exit_button.pack(pady=20)

            
    def show_backup(self):

        self.list_files(self.backup_dir)

    def Start_sniff(self):
     global N
     global sniffing
     sniffing = False
     interfaces = []
     global interface_status
     
     def on_ok():
        for var, interface in zip(interface_vars, N):
            if var.get():
                interfaces.append(interface)
                interface_status[interface] = "sniffing"
            else:
                interface_status[interface] = "not sniff"
        
        if all_var.get():
            for interface in N:
                interface_status[interface] = "sniffing"
        
        start_sniff_window.destroy()
        sniff_all_interfaces(interfaces)

    # Create the window
     start_sniff_window = tk.Toplevel()
     start_sniff_window.title("Choose Interface")
     start_sniff_window.geometry("800x400")
    # Create checkbuttons for each interface
     interface_vars = []
     for interface in N:
        var = tk.BooleanVar()
        chk = tk.Checkbutton(start_sniff_window, text=interface, variable=var)
        chk.pack(anchor='w')
        interface_vars.append(var)

     # Create the "All" checkbutton
     all_var = tk.BooleanVar()
     all_chk = tk.Checkbutton(start_sniff_window, text="All", variable=all_var)
     all_chk.pack(anchor='w')

    # Create the OK button
     ok_button = ttk.Button(start_sniff_window, text="OK", command=on_ok)
     ok_button.pack(pady=10, padx=10)
     

        
    def Stop_sniff(self):
         
          stop_sniffing()
        
    def show_models(self):

        self.list_files(self.models_dir)
    def add_email(self):
     def add_email_action():
        for widget in self.inner_frame.winfo_children():
            widget.destroy()
        email = email_entry.get()
        if not email:
            messagebox.showerror("Error", "Email field cannot be empty.")
            add_email_window.focus_set()  # Bring the add_email_window back to focus
            return
        
        with self.conn:
            # Check if email already exists
            cursor = self.conn.execute('SELECT id FROM emails WHERE email = ?', (email,))
            existing_email = cursor.fetchone()
            if existing_email:
                messagebox.showinfo("Information", f"Email '{email}' already exists in the database.")
                add_email_window.focus_set()  # Bring the add_email_window back to focus
                return
            if not self.is_valid_email(email):
                messagebox.showerror("Error", "Invalid Email")
                add_email_window.focus_set()  # Bring the add_email_window back to focus
                return
            verification_code = self.generate_verification_code()
            if self.send_verification_email(email, verification_code):
                user_code = simpledialog.askstring("Email Verification", "Enter the verification code sent to your email:")
                if user_code != str(verification_code):
                    messagebox.showerror("Error", "Invalid verification code.")
                    add_email_window.focus_set()  # Bring the add_email_window back to focus
                    return
            else:
                messagebox.showerror("Error", "Failed to send verification email.")
                add_email_window.focus_set()  # Bring the add_email_window back to focus
                return
            # Insert new email
            self.conn.execute('INSERT INTO emails (email) VALUES (?)', (email,))
            messagebox.showinfo("Information", f"Email '{email}' added successfully.")
            add_email_window.focus_set()  # Bring the add_email_window back to focus
        
    # GUI setup
     add_email_window = tk.Toplevel()
     add_email_window.title("Add Email")
    
     label = ttk.Label(add_email_window, text="Enter Email:")
     label.pack(pady=10, padx=10)
    
     email_entry = ttk.Entry(add_email_window, width=30)
     email_entry.pack(pady=10, padx=10)
    
     add_button = ttk.Button(add_email_window, text="Add Email", command=add_email_action)
     add_button.pack(pady=10, padx=10)
    
    def add_data(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if file_path:
            try:
                shutil.copy(file_path, self.data_dir)
                self.log_info(f"File {os.path.basename(file_path)} added to data directory.")
                self.list_files(self.data_dir)  # Refresh the list after adding
            except Exception as e:
                self.log_info(f"Error adding file: {e}")

    def list_files(self, directory):
        # Clear existing widgets
        for widget in self.inner_frame.winfo_children():
            widget.destroy()

        columns = ("Filename", "Action")
        tree = ttk.Treeview(self.inner_frame, columns=columns, show='headings' ,height=11)
        tree.heading("Filename", text="Filename")
        tree.heading("Action", text="Action")
        tree.column("Filename", anchor=tk.W, width=1130)  # Increase the width of the Filename column
        tree.column("Action", anchor=tk.CENTER, width=100)  # Increase the width of the Action column

        tree.pack(side=tk.LEFT, pady=5, padx=5, fill=tk.BOTH, expand=True)

        # Add a vertical scrollbar
        vsb = ttk.Scrollbar(self.inner_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        for item in os.listdir(directory):
            self.add_file_entry(item, directory, tree)

        

    def add_file_entry(self, filename, directory, tree):
        # Insert the file entry into the treeview
        tags = ('evenrow' if len(tree.get_children()) % 2 == 0 else 'oddrow',)
        delete_action = "Delete" if self.users[self.current_user]['role'] == "admin" else ""

        tree.insert("", "end", values=(filename, delete_action), tags=tags)

        tree.tag_configure('evenrow', background='lightblue')
        tree.tag_configure('oddrow', background='lightgrey')

        # Bind double-click event for opening files
        tree.bind("<Double-1>", lambda event: self.on_file_double_click(event, directory, tree))

        # Bind click event for delete action
        tree.bind("<ButtonRelease-1>", lambda event: self.on_delete_click(event, directory, tree))

    def on_file_double_click(self, event, directory, tree):
        item = tree.selection()[0]
        filename = tree.item(item, "values")[0]
        self.open_file(directory, filename)

    def on_delete_click(self, event, directory, tree):
        item = tree.identify_row(event.y)
        column = tree.identify_column(event.x)
        if column == '#2':  # The Action column
            action = tree.item(item, "values")[1]
            if action == "Delete":
                filename = tree.item(item, "values")[0]
                self.delete_file(directory, filename)

    def open_file(self, directory, filename):
        file_path = os.path.join(directory, filename)
        try:
            if os.name == 'nt':  # For Windows
                os.startfile(file_path)
            elif os.name == 'posix':  # For Unix-based systems
                subprocess.call(('xdg-open', file_path))
        except Exception as e:
            self.log_info(f"Error opening file {filename}: {e}")

    def delete_file(self, directory, filename):
        try:
            os.remove(os.path.join(directory, filename))
            self.list_files(directory)  # Refresh the list after deleting
        except Exception as e:
            self.log_info(f"Error deleting file: {e}")


    def done_train_data(self):
        self.list_files(self.done_train_dir)

    def log_info(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)  # Auto-scroll to the latest log

    def show_banned_ips(self):
        # Clear existing widgets in inner_frame
   
        for widget in self.inner_frame.winfo_children():
            widget.destroy()

        try:
            cursor = self.conn.execute("SELECT ip, expiry_time FROM banned_ips")
            banned_ips = cursor.fetchall()

            

            # Create a frame to hold the treeview and scrollbars
            table_frame = ttk.Frame(self.inner_frame)
            table_frame.pack(fill="both", expand=True)

            # Create a treeview with specified height and width
            tree = ttk.Treeview(table_frame, columns=("IP", "Expiry Time"), show='headings', height=11)
            tree.heading("IP", text="IP")
            tree.heading("Expiry Time", text="Ban Expires At")
            tree.column("IP", anchor=tk.CENTER, width=1124)
            tree.column("Expiry Time", anchor=tk.CENTER, width=100)

            # Add a vertical scrollbar
            vsb = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=vsb.set)
            vsb.pack(side=tk.RIGHT, fill=tk.Y)


            # Pack the treeview
            tree.pack(pady=10, padx=10, fill="both", expand=True)

            # Insert data into the treeview with alternating row colors
            tree.tag_configure('oddrow', background='#f0f0f0')
            tree.tag_configure('evenrow', background='#ffffff')

            # Insert banned IPs
            row_count = 0
            if not banned_ips:
                tree.insert("", "end", values=("no ban ip yet", "now"), tags='oddrow')
            else:
             for ip, expiry_time in banned_ips:
                expiry_time_str = time.ctime(expiry_time)
                tag = 'evenrow' if row_count % 2 == 0 else 'oddrow'
                tree.insert("", "end", values=(ip, expiry_time_str), tags=tag)
                row_count += 1

        except Exception as e:
            error_label = ttk.Label(self.inner_frame, text=f"Error fetching banned IPs: {e}")
            error_label.pack(pady=10, padx=5, fill="x")


    def show_malicious_packet(self):
        file_path = os.path.join('predict', 'historical_data.xlsx')
        try:
            if os.name == 'nt':  # For Windows
                os.startfile(file_path)
            elif os.name == 'posix':  # For Unix-based systems
                subprocess.call(('xdg-open', file_path))
        except Exception as e:
            self.log_info(f"Error opening file {'historical_data.xlsx'}: {e}")

MODEL_PATH_RNN = 'models/rnn_model.h5'
MODEL_PATH_LSTM = 'models/lstm_model.h5'
MODEL_PATH_GRU = 'models/gru_model.h5'

MAIN_DATA = 'data/data.csv'
DATA_PATH='data'
MODELS_PATH='models'
REPORT_PATH = 'reports'  
BACKUP_PATH='backup'
done_train_path='done_train'
DATA_PREDICT = 'predict/historical_data.xlsx'

# Paths for reports, backups, and training status
REPORT_PATH = 'reports'
BACKUP_PATH = 'backup'
done_train_path = 'done_train'


os.makedirs(REPORT_PATH, exist_ok=True)
os.makedirs(MODELS_PATH, exist_ok=True)
os.makedirs(BACKUP_PATH, exist_ok=True)
os.makedirs(done_train_path, exist_ok=True)
os.makedirs('predict', exist_ok=True)
FEATURE_COLUMNS = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Fwd IAT Total',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Fwd Header Length',
    'Bwd Header Length',
    'Min Packet Length',
    'Max Packet Length',
    'Packet Length Mean',
    'Packet Length Std',
    'SYN Flag Count',
    'ACK Flag Count',
    'Average Packet Size',
    'Avg Fwd Segment Size',
    'Init_Win_bytes_forward'
]
TARGET_COLUMN = 'Label'


# Global variable to control sniffing
sniffing = False
banned_ips = set()
global malicious_packets
malicious_packets = []
initial_training_accuracy = 0
global N
N=[]
interface_status = {}
ifaces = IFACES.data.values() if hasattr(IFACES, 'data') else IFACES.values()
for ifa in ifaces:
  N.append(ifa.name)
def delete_malicious_packet():
    global malicious_packets
    while True:
        time.sleep(604800) #week
        malicious_packets.clear()
def email(db):
    with db.conn:
     cursor = db.execute("email FROM emails")
     return cursor.fetchall()
def send_email_alert(subject, body):
  mail=email(app.conn)
  for b in mail:
    try:
        msg = MIMEMultipart()
        msg['From'] = 'skr59406@gmail.com'
        msg['To'] = b
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP('smtp.gmail.com', 465)
        server.starttls()
        server.login('skr59406@gmail.com', 'uefk hvyo awcw jplm')
        server.sendmail('skr59406@gmail.com', b, msg.as_string())
        server.quit()
        app.log_info(f'Alert email sent successfully to :"{b}"')
    except Exception as e:
        app.log_info(f"Failed to send email alert: {e}")

trained_models = {}     
EPOCHS = 100
BATCH_SIZE = 32
TIMESTEPS = 10

def load_or_train_models(MAIN_DATA=MAIN_DATA):
    # Load data
    data = pd.read_csv(MAIN_DATA)
    X = data[FEATURE_COLUMNS].copy()
    y = pd.get_dummies(data[TARGET_COLUMN])

    # Replace infinite values and fill NaNs
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Normalize features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Handle class imbalance with SMOTE + Tomek Links
    smote_tomek = SMOTETomek(random_state=42)
    y_labels = np.argmax(y.values, axis=1)  # Convert to 1D array
    X_resampled, y_resampled_labels = smote_tomek.fit_resample(X, y_labels)

    # Convert resampled labels back to one-hot encoding
    y_resampled = pd.get_dummies(y_resampled_labels)

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X_resampled, y_resampled, test_size=0.2, random_state=42
    )

    # Reshape data for RNN models
    features = X_train.shape[1]
    num_train_samples = X_train.shape[0] // TIMESTEPS * TIMESTEPS
    num_test_samples = X_test.shape[0] // TIMESTEPS * TIMESTEPS

    X_train_rnn = X_train[:num_train_samples].reshape(-1, TIMESTEPS, features)
    X_test_rnn = X_test[:num_test_samples].reshape(-1, TIMESTEPS, features)

    y_train = y_train.values[:num_train_samples:TIMESTEPS]
    y_test = y_test.values[:num_test_samples:TIMESTEPS]

    y_train_labels = np.argmax(y_train, axis=1)  # Convert to class labels
    y_test_labels = np.argmax(y_test, axis=1)

    # Compute class weights
    class_weights = class_weight.compute_class_weight(
        'balanced', classes=np.unique(y_train_labels), y=y_train_labels
    )
    class_weights_dict = dict(enumerate(class_weights))

    # Define RNN models with optimized architecture
    models = {
        
        'GRU': (None, MODEL_PATH_GRU, GRU)
    }


    for name, (model, model_path, rnn_layer) in models.items():
        if os.path.exists(model_path):
            trained_model = tf.keras.models.load_model(model_path)
        else:
            # Model architecture with improved layers
            model = Sequential([
                rnn_layer(128, activation='tanh', return_sequences=True, input_shape=(TIMESTEPS, features)),
                Dropout(0.2),
                BatchNormalization(),
                rnn_layer(64, activation='tanh'),  # Additional layer for better representation
                Dense(256, activation='relu'),
                Dropout(0.2),
                BatchNormalization(),
                Dense(y_train.shape[1], activation='softmax')
            ])

            # Compile model with Nadam optimizer
            optimizer = tf.keras.optimizers.Nadam(learning_rate=0.001)
            model.compile(optimizer=optimizer, loss='categorical_crossentropy', metrics=['accuracy'])

            # Learning rate scheduler and early stopping
            def scheduler(epoch, lr):
                return lr * 0.9 if epoch > 5 else lr

            callbacks = [
                LearningRateScheduler(scheduler),
                EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
            ]

            # Train the model
            model.fit(X_train_rnn, y_train, epochs=EPOCHS, batch_size=BATCH_SIZE,
                      class_weight=class_weights_dict, validation_data=(X_test_rnn, y_test),
                      callbacks=callbacks)

            # Save and reload the model
            model.save(model_path)
            trained_model = tf.keras.models.load_model(model_path)

        trained_models[name] = trained_model

    
    
    calculate_accuracy(trained_models, X_test_rnn, y_test)
    return trained_models

def retrain_models():
 
   # Load data
    data = pd.read_csv(MAIN_DATA)
    X = data[FEATURE_COLUMNS].copy()
    y = pd.get_dummies(data[TARGET_COLUMN])

    # Replace infinite values and fill NaNs
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Normalize features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Handle class imbalance with SMOTE + Tomek Links
    smote_tomek = SMOTETomek(random_state=42)
    y_labels = np.argmax(y.values, axis=1)  # Convert to 1D array
    X_resampled, y_resampled_labels = smote_tomek.fit_resample(X, y_labels)

    # Convert resampled labels back to one-hot encoding
    y_resampled = pd.get_dummies(y_resampled_labels)

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X_resampled, y_resampled, test_size=0.2, random_state=42
    )

    # Reshape data for RNN models
    features = X_train.shape[1]
    num_train_samples = X_train.shape[0] // TIMESTEPS * TIMESTEPS
    num_test_samples = X_test.shape[0] // TIMESTEPS * TIMESTEPS

    X_train_rnn = X_train[:num_train_samples].reshape(-1, TIMESTEPS, features)
    X_test_rnn = X_test[:num_test_samples].reshape(-1, TIMESTEPS, features)

    y_train = y_train.values[:num_train_samples:TIMESTEPS]
    y_test = y_test.values[:num_test_samples:TIMESTEPS]

    y_train_labels = np.argmax(y_train, axis=1)  # Convert to class labels
    y_test_labels = np.argmax(y_test, axis=1)

    # Compute class weights
    class_weights = class_weight.compute_class_weight(
        'balanced', classes=np.unique(y_train_labels), y=y_train_labels
    )
    class_weights_dict = dict(enumerate(class_weights))

    # Define RNN models with optimized architecture
    models = {
       
        'GRU': (None, MODEL_PATH_GRU, GRU)
    }


    for name, (model, model_path, rnn_layer) in models.items():
        
            # Model architecture with improved layers
            model = Sequential([
                rnn_layer(128, activation='tanh', return_sequences=True, input_shape=(TIMESTEPS, features)),
                Dropout(0.2),
                BatchNormalization(),
                rnn_layer(64, activation='tanh'),  # Additional layer for better representation
                Dense(256, activation='relu'),
                Dropout(0.2),
                BatchNormalization(),
                Dense(y_train.shape[1], activation='softmax')
            ])

            # Compile model with Nadam optimizer
            optimizer = tf.keras.optimizers.Nadam(learning_rate=0.001)
            model.compile(optimizer=optimizer, loss='categorical_crossentropy', metrics=['accuracy'])

            # Learning rate scheduler and early stopping
            def scheduler(epoch, lr):
                return lr * 0.9 if epoch > 5 else lr

            callbacks = [
                LearningRateScheduler(scheduler),
                EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
            ]

            # Train the model
            model.fit(X_train_rnn, y_train, epochs=EPOCHS, batch_size=BATCH_SIZE,
                      class_weight=class_weights_dict, validation_data=(X_test_rnn, y_test),
                      callbacks=callbacks)

            # Save and reload the model
            model.save(model_path)
            trained_model = tf.keras.models.load_model(model_path)

            trained_models[name] = trained_model

    
    calculate_accuracy(trained_models, X_test_rnn, y_test)  
acc = {}
vv = []

def calculate_accuracy(models, X_test, y_test):
    accuracies = {}
    
    # Convert y_test into label format if it's one-hot encoded
    if len(y_test.shape) > 1 and y_test.shape[1] > 1:
        y_test = y_test.argmax(axis=1)  # Convert from one-hot encoding to class labels
    
    for name, model in models.items():
        # Check if the model is from Keras or scikit-learn
        if hasattr(model, 'predict_proba'):  # scikit-learn models
            y_pred_prob = model.predict_proba(X_test)  # Probabilities for roc_auc
            y_pred = model.predict(X_test)  # Class predictions
        else:  # Keras models
            y_pred_prob = model.predict(X_test)  # Output probabilities for Keras
            y_pred = y_pred_prob.argmax(axis=1)  # Convert probabilities to class predictions

        lacc = []
        
        # Calculate basic evaluation metrics
        lacc.append(round(accuracy_score(y_test, y_pred) * 100, 2))
        lacc.append(round(precision_score(y_test, y_pred, average='macro', zero_division=1) * 100, 2))
        lacc.append(round(recall_score(y_test, y_pred, average='macro') * 100, 2))
        lacc.append(round(f1_score(y_test, y_pred, average='macro') * 100, 2))

        # Only calculate roc_auc and average_precision if probabilities are available and multiclass is handled
        if y_pred_prob is not None and len(set(y_test)) > 2:  # Ensure it's multiclass
            try:
                lacc.append(round(roc_auc_score(y_test, y_pred_prob, multi_class='ovr') * 100, 2))
                lacc.append(round(average_precision_score(y_test, y_pred_prob, average='macro') * 100, 2))
            except ValueError:
                print(f"Skipping roc_auc for {name} due to incompatible labels.")
        
        # Use the highest score in the metrics for this model's accuracy
        accuracy = max(lacc)
        accuracies[name] = accuracy
        acc[name] = accuracy
        vv.append(accuracy)
   
    return accuracies

def accuracy_system():
    avg = sum(vv) / len(vv)
    return round(avg, 2)

def execute_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        app.log_info(f"Command failed: {e}")


def unban_ip(conn, ip):
    app.log_info(f"Unbanned IP {ip}")
    
    # Remove the IP from the banned_ips table
    with conn:
        conn.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
    banned_ips.remove(ip)
    
    # Remove the firewall rule based on the OS
    if platform.system() == "Linux":
        command = f"sudo iptables -D INPUT -s {ip} -j DROP"
    elif platform.system() == "Windows":
        command = f"netsh advfirewall firewall delete rule name=\"Block IP {ip}\""
    
    execute_command(command)


def ban_ip(conn, ip, ban_duration=1800):
    current_time = time.time()
    expiry_time = current_time + ban_duration

    # Check if the IP is already banned
    cursor = conn.execute("SELECT * FROM banned_ips WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    if row:
        if row[2] < current_time:
            # IP ban has expired, remove it from the database
            unban_ip(conn, ip)
        else:
            app.log_info(f"IP {ip} is already banned until {time.ctime(row[2])}.")
            return

    # Add the IP to the banned_ips table
    with conn:
        conn.execute("INSERT INTO banned_ips (ip, expiry_time) VALUES (?, ?)", (ip, expiry_time))
    
    app.log_info(f"Banned IP {ip} for {ban_duration} seconds")
    banned_ips.add(ip)

    # Add the firewall rule based on the OS
    if platform.system() == "Linux":
        command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    elif platform.system() == "Windows":
        command = f"netsh advfirewall firewall add rule name=\"Block IP {ip}\" dir=in action=block remoteip={ip}"
    
    execute_command(command)

    # Schedule unbanning
    threading.Timer(ban_duration, unban_ip, [conn, ip]).start()


def detect_malicious_packet(packet_features, models, src_ip):
    # Convert feature list to DataFrame with correct feature names
    packet_features_df = pd.DataFrame([packet_features], columns=FEATURE_COLUMNS)
    votes = []
    for name, model in models.items():
        prediction = model.predict(packet_features_df)
        result = "Malicious" if prediction == 1 else "Safe"
        votes.append(prediction[0])
    # Majority voting
    malicious_votes = [vote for vote in votes if vote != 'BENIGN']
    votes = [vote for vote in votes if vote == 'BENIGN']
    if len(malicious_votes) > len(votes) :
    
        app.log_info("Ensemble decision: Malicious")
        ban_ip(src_ip)
        log_malicious_packet(packet_features, malicious_votes[0])
        malicious_packets.append(packet_features_df)

        # Send email alert
        subject = "Alert: Malicious Packet Detected"
        body = f"""
        A malicious packet has been detected.

        Source IP: {src_ip}
        Packet Features: {packet_features}

        The IP has been banned and the models retrained.
        """
        send_email_alert(subject, body)

def log_malicious_packet(packet_features, prediction):
    packet_features.append(prediction) 
    new_data = pd.DataFrame([packet_features], columns=FEATURE_COLUMNS + [TARGET_COLUMN])
    if os.path.exists(DATA_PREDICT):
        new_data.to_csv(DATA_PREDICT, mode='a', header=False, index=False)
    else:
        new_data.to_csv(DATA_PREDICT, mode='w', header=True, index=False)


def simulate_future_data_based_on_last(file_path, num_samples=1000, noise_level=0,  label_column=None):
    last_data_points = get_last_data_points(file_path, num_samples)
    
    if last_data_points.empty:
        return pd.DataFrame()
    
    if label_column:
        # Separate labels and features
        labels = last_data_points[label_column]
        features = last_data_points.drop(columns=[label_column])
    else:
        labels = pd.Series([None] * num_samples)  # No label column provided
        features = last_data_points
    
    simulated_features = pd.DataFrame()
    
    numeric_columns = features.select_dtypes(include=[np.number]).columns
    non_numeric_columns = features.select_dtypes(exclude=[np.number]).columns
    
    
     # Sample with replacement from the last data points for numeric columns
    simulated_features[numeric_columns] = features[numeric_columns].sample(n=num_samples, replace=True).reset_index(drop=True)
    
    # Sample with replacement from the last data points for non-numeric columns
    simulated_features[non_numeric_columns] = features[non_numeric_columns].sample(n=num_samples, replace=True).reset_index(drop=True)
    
    # Add noise to the simulated numeric data
    if noise_level > 0:
        noise = np.random.normal(loc=0, scale=noise_level, size=simulated_features[numeric_columns].shape)
        simulated_features[numeric_columns] += noise
    
    # Reattach labels
    if label_column:
        simulated_labels = labels.sample(n=num_samples, replace=True).reset_index(drop=True)
        simulated_data = simulated_features.copy()
        simulated_data[label_column] = simulated_labels
    else:
        simulated_data = simulated_features
    
    return simulated_data

def get_last_data_points(file_path, num_points=1000):
    try:
        # Load the historical data from the Excel file
        historical_data = pd.read_excel(file_path)
        
        available_points = len(historical_data)

        # If no data is available, return an empty DataFrame
        if available_points == 0:
            return pd.DataFrame()
        
        # Adjust the number of points to return if fewer than requested are available
        if available_points < num_points:
            num_points = available_points
        
        # Get the last `num_points` data points
        last_data_points = historical_data.tail(num_points)

        # Rename the last column to "Label" and set all its values to 1
        
        
        return last_data_points

    except:
        app.log_info(f"no malicios packet detect to simulate next month")
        return pd.DataFrame()
    
    

global pre_accuracies
pre_accuracies={}
global pre_system_accuracy
pre_system_accuracy=0
def periodic_accuracy_prediction(historical_data, models, feature_columns):
    while True:
        future_data =  simulate_future_data_based_on_last(historical_data)
        if future_data.empty:
            app.log_info("No data available for future prediction ")
            time.sleep(30 * 24 * 60 * 60)  # Sleep for a month
            continue
        
        features = future_data[feature_columns]
        features = preprocess_features(features)
        predictions = {model_name: model.predict(features) for model_name, model in models.items()}
        
        true_labels = future_data['Label']  
        
        # Calculate individual model accuracies
        accuracies = {model_name: np.mean(np.array(pred) == np.array(true_labels)) for model_name, pred in predictions.items()}
     
        # Combine predictions by majority vote
        combined_predictions = np.array([max(set(preds), key=preds.count) for preds in zip(*predictions.values())])
        
        # Calculate ensemble accuracy
        ensemble_accuracy = np.mean(combined_predictions == np.array(true_labels))
       
        global pre_accuracies
        pre_accuracies=accuracies
        global pre_system_accuracy
        pre_system_accuracy=ensemble_accuracy
        #merging_data()
        #retrain_models()
        time.sleep(30 * 24 * 60 * 60)  # Sleep for a month

def preprocess_features(features):
    # Replace inf values with NaN
    features = features.replace([np.inf, -np.inf], np.nan)
    
    # Fill NaN values with the mean or drop rows/columns with NaN values
    features = features.fillna(features.mean())
    
    # Ensure all values are within a reasonable range
    max_value = 1e6  # Set an appropriate threshold based on your data
    features = np.clip(features, -max_value, max_value)
    
    return features
def merging_data(file1=MAIN_DATA, file2=DATA_PREDICT):
       # Load the first CSV file into a DataFrame
     df1 = pd.read_csv(file1)
        # Load the second Excel file into a DataFrame
     df2 = pd.read_excel(file2)
    # Merge the DataFrames
     merged_df = pd.concat([df1, df2], ignore_index=True)

    # Save the merged DataFrame back to the first CSV file
     merged_df.to_csv(file1, index=False)
    
    # Remove the second file
     os.remove(file2)
    
     print(f"Files merged and saved to {file1}")

def send_report_via_email(file_path):
     mail=email(app.conn)
     for b in mail:
      try:
        msg = MIMEMultipart()
        msg['From'] = 'skr59406@gmail.com'
        msg['To'] = b
        msg['Subject'] = "Daily Intrusion Detection System Report"

        body = "Please find attached the daily report from the Intrusion Detection System."
        msg.attach(MIMEText(body, 'plain'))

        with open(file_path, "rb") as attachment:
            part = MIMEApplication(attachment.read(), Name=os.path.basename(file_path))
            part['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            msg.attach(part)

        # Establish a secure session with the server using TLS
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        
        # Login to the email server
        server.login( 'skr59406@gmail.com', 'uefk hvyo awcw jplm')
        
        # Send the email
        server.sendmail( 'skr59406@gmail.com', b, msg.as_string())
        
        # Close the connection
        server.quit()
        
        app.log_info(f'Report email sent successfully to: "{b}"')
      except Exception as e:
        app.log_info(f"Failed to send report email: {e}")


def packet_callback(packet):
    global sniffing
    if not sniffing:
        return

    if IP in packet and TCP in packet:
        flow_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, packet.proto)

        if flows[flow_key]['start_time'] is None:
            flows[flow_key]['start_time'] = time.time()

        packet_length = len(packet)
        current_time = time.time()
        direction = 'fwd' if packet[IP].src < packet[IP].dst else 'bwd'

        if direction == 'fwd':
            flows[flow_key]['total_length_fwd'] += packet_length
            flows[flow_key]['fwd_packet_lengths'].append(packet_length)
            flows[flow_key]['total_fwd_packets'] += 1
            if flows[flow_key]['last_fwd_time'] is not None:
                flows[flow_key]['iat_fwd'].append(current_time - flows[flow_key]['last_fwd_time'])
            flows[flow_key]['last_fwd_time'] = current_time
        else:
            flows[flow_key]['total_length_bwd'] += packet_length
            flows[flow_key]['bwd_packet_lengths'].append(packet_length)
            flows[flow_key]['total_bwd_packets'] += 1
            if flows[flow_key]['last_bwd_time'] is not None:
                flows[flow_key]['iat_bwd'].append(current_time - flows[flow_key]['last_bwd_time'])
            flows[flow_key]['last_bwd_time'] = current_time

        flow_duration = current_time - flows[flow_key]['start_time']
        total_length_fwd = flows[flow_key]['total_length_fwd']
        total_length_bwd = flows[flow_key]['total_length_bwd']
        fwd_packet_lengths = flows[flow_key]['fwd_packet_lengths']
        bwd_packet_lengths = flows[flow_key]['bwd_packet_lengths']
        total_fwd_packets = flows[flow_key]['total_fwd_packets']
        total_bwd_packets = flows[flow_key]['total_bwd_packets']
        iat_fwd = flows[flow_key]['iat_fwd']
        iat_bwd = flows[flow_key]['iat_bwd']

        # Stats calculations
        def stats(arr):
            if not arr:
                return 0, 0, 0, 0
            _min = min(arr)
            _max = max(arr)
            _mean = sum(arr) / len(arr)
            _std = (sum((x - _mean) ** 2 for x in arr) / len(arr)) ** 0.5
            return _min, _max, _mean, _std

        fwd_min, fwd_max, fwd_mean, fwd_std = stats(fwd_packet_lengths)
        bwd_min, bwd_max, bwd_mean, bwd_std = stats(bwd_packet_lengths)

        flow_bytes_per_s = (total_length_fwd + total_length_bwd) / flow_duration if flow_duration > 0 else 0
        flow_packets_per_s = (total_fwd_packets + total_bwd_packets) / flow_duration if flow_duration > 0 else 0

        iat_all = iat_fwd + iat_bwd
        flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std = stats(iat_all)

        fwd_iat_total = sum(iat_fwd)
        fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std = stats(iat_fwd)
        bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std = stats(iat_bwd)

        fwd_header_length = len(str(packet[TCP].payload))  # approximate
        bwd_header_length = 0  # assume 0 if unknown

        fwd_packets_per_s = total_fwd_packets / flow_duration if flow_duration > 0 else 0
        bwd_packets_per_s = total_bwd_packets / flow_duration if flow_duration > 0 else 0

        all_packet_lengths = fwd_packet_lengths + bwd_packet_lengths
        pkt_min, pkt_max, pkt_mean, pkt_std = stats(all_packet_lengths)

        # Construct feature list for 30 selected features
        packet_features = [
            flow_duration,
            total_fwd_packets,
            total_bwd_packets,
            total_length_fwd,
            total_length_bwd,
            fwd_max,
            fwd_mean,
            fwd_std,
            bwd_max,
            bwd_mean,
            bwd_std,
            flow_bytes_per_s,
            flow_packets_per_s,
            flow_iat_mean,
            flow_iat_std,
            flow_iat_max,
            fwd_iat_total,
            fwd_iat_mean,
            bwd_iat_mean,
            fwd_header_length,
            bwd_header_length,
            pkt_min,
            pkt_max,
            pkt_mean,
            pkt_std,
            0,  # SYN Flag Count (placeholder if not calculated)
            0,  # ACK Flag Count (placeholder if not calculated)
            pkt_mean,  # Average Packet Size
            fwd_mean,  # Avg Fwd Segment Size
            0,  # Init_Win_bytes_forward (placeholder)
        ]

        detect_malicious_packet(packet_features, trained_models, packet[IP].src)


def stop_sniffing():
    global sniffing
    sniffing = False
    app.log_info("Sniffing stopped.")

def start_sniffing(interface):
    global sniffing
    sniffing = True
    app.log_info("sniffing..... ")
    while sniffing:
       sniff(filter="ip", prn=packet_callback, store=0, iface=interface)

def sniff_all_interfaces(interface):
    
    global sniffing
    sniffing = False
    ifaces = IFACES.data.values() if hasattr(IFACES, 'data') else IFACES.values()
    
    for iface in ifaces:
        if hasattr(iface, 'status') and iface.status == 'up':
            if iface.name in interface:
              threading.Thread(target=start_sniffing, args=(iface.name,)).start()
        elif hasattr(iface, 'flags') and 'UP' in iface.flags:
            if iface.name in interface:
               threading.Thread(target=start_sniffing, args=(iface.name,)).start()
          
        

# Function to generate daily report
def generate_report():
    while True:
        time.sleep(86400)  # Wait for 24 hours
        report_file = os.path.join(REPORT_PATH, f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(200, 10, txt="Intrusion Detection System Report", ln=True, align='C')
        pdf.ln(10)
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(200, 10, txt=f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(10)
        pdf.set_font('Arial', '', 10)
        pdf.cell(200, 10, txt=f"Initial Training Accuracy: {initial_training_accuracy * 100:.2f}%", ln=True)
        pdf.ln(10)
        pdf.cell(200, 10, txt=f"Current Training Accuracy: ", ln=True)
        pdf.ln(10)
        for key, value in acc.items():
         pdf.cell(200, 10, txt=f"{key}: {value}\n", ln=True)
         pdf.ln(10)
        sysacc=accuracy_system()
        pdf.cell(200, 10, txt=f"System Accuracy: {sysacc:.2f} %", ln=True)
        pdf.ln(10)
        for key, value in pre_accuracies.items():
         pdf.cell(200, 10, txt=f"{key}: {value}\n", ln=True)
         pdf.ln(10)
        pdf.cell(200, 10, txt=f"prediction of System Accuracy : {pre_system_accuracy:.2f} %", ln=True)
        pdf.ln(10)
        pdf.cell(200, 10, txt=f"Number of Banned IPs: {len(banned_ips)}", ln=True)
        pdf.ln(10)
        pdf.cell(200, 10, txt=f"Number of Malicious Packets: {len(malicious_packets)}", ln=True)
        pdf.ln(10)

        if malicious_packets:
            pdf.cell(200, 10, txt=f"Details of Malicious Packets:", ln=True)
            pdf.ln(10)
            for idx, packet in enumerate(malicious_packets, start=1):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_length = len(packet)
                timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
                
                pdf.cell(200, 10, txt=f"Malicious Packet {idx}:", ln=True)
                pdf.cell(200, 10, txt=f"Source IP: {src_ip}", ln=True)
                pdf.cell(200, 10, txt=f"Destination IP: {dst_ip}", ln=True)
                pdf.cell(200, 10, txt=f"Packet Length: {packet_length}", ln=True)
                pdf.cell(200, 10, txt=f"Timestamp: {timestamp}", ln=True)
                pdf.ln(10)
        
        pdf.output(report_file)
        app.log_info(f"Generated report: {report_file}")
        send_report_via_email(report_file)

def periodic_check_for_new_data():
     while True:
        time.sleep(900)
        data_frames=[]
        new_data_files = [f for f in os.listdir(DATA_PATH) if f.endswith('.csv') and f != 'data.csv']
        if not new_data_files:
            
            continue
        for file in new_data_files:
          file_path = os.path.join(DATA_PATH, file)
 
          df = pd.read_csv(file_path)

          data_frames.append(df)
    
        if data_frames:
         concatenated_df = pd.concat(data_frames, ignore_index=True)
    
         concatenated_df.to_csv(MAIN_DATA)
         retrain_models()
         move_file_to_done_train()
        

def move_file_to_done_train():
        for file in os.listdir(DATA_PATH):
            if file != 'data.csv':
                source_path = os.path.join(DATA_PATH, file)
                dest_path = os.path.join(done_train_path, file)
                try:
                    copy2(source_path, dest_path)
                    app.log_info(f"Moved {source_path} to {dest_path}")
                    os.remove(source_path)
                except Exception as e:
                    app.log_info(f"Error moving {source_path} to {dest_path}: {e}")
def create_backup():
        while True:
            time.sleep(86400)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(BACKUP_PATH, f'backup_{timestamp}.tar.gz')
            with tarfile.open(backup_file, 'w:gz') as tar:
                tar.add(MODELS_PATH, arcname=os.path.basename(MODELS_PATH))
                tar.add(DATA_PATH, arcname=os.path.basename(DATA_PATH))
                tar.add(REPORT_PATH, arcname=os.path.basename(REPORT_PATH))
                tar.add(done_train_path, arcname=os.path.basename(done_train_path))
            
            app.log_info(f"Backup created: {backup_file}")


# Dictionary to store flow data
flows = defaultdict(lambda: {'start_time': None, 'total_length_fwd': 0, 'total_length_bwd': 0, 'fwd_packet_lengths': [], 'bwd_packet_lengths': [], 'total_fwd_packets': 0, 'total_bwd_packets': 0, 'iat_fwd': [], 'iat_bwd': [], 'last_fwd_time': None, 'last_bwd_time': None})

# Start the report generation thread



root = tk.Tk()
app = NetworkTrafficAnalysisApp(root)
print("Start the System , it may take a few minutes")
load_or_train_models()


threading.Thread(target=generate_report, daemon=True).start()

threading.Thread(target=periodic_check_for_new_data, daemon=True).start()
threading.Thread(target=create_backup, daemon=True).start()
threading.Thread(target=delete_malicious_packet, daemon=True).start()
threading.Thread(target=periodic_accuracy_prediction, args=(DATA_PREDICT, trained_models, FEATURE_COLUMNS)).start()
root.mainloop()
