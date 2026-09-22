import sys
import os
import sqlite3
import hashlib
import re
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import shutil
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QTextEdit, QTreeWidget, QTreeWidgetItem, 
    QMessageBox, QDialog, QFileDialog, QScrollArea, QCheckBox, 
    QRadioButton, QButtonGroup, QInputDialog, QFrame, QSizePolicy,
    QTabWidget, QComboBox, QProgressBar, QSplitter, QToolBar, QStatusBar,
    QSystemTrayIcon, QMenu, QAction, QGraphicsDropShadowEffect
)
from PyQt5.QtCore import Qt, QTimer, QSize, QPoint
from PyQt5.QtGui import (
    QFont, QColor, QPalette, QIcon, QPixmap, QLinearGradient, 
    QBrush, QPainter, QFontDatabase
)

class ModernTrafficAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.setup_database()
        self.setup_styles()
        self.check_first_run()
        
        # System tray icon
        self.setup_system_tray()
        
        # Demo data - replace with your actual data
        self.demo_interfaces = ["eth0", "wlan0", "lo", "eth1"]
        self.demo_models = ["Random Forest", "SVM", "Neural Network", "Decision Tree"]
        self.demo_reports = ["daily_report_2023.csv", "weekly_summary.pdf", "threat_analysis.xlsx"]
        
        # Start with login screen
        self.show_login()

    def setup_ui(self):
        """Initialize the main window UI"""
        self.setWindowTitle("NeuralGuard - Network Traffic Analyzer")
        self.resize(1200, 800)
        self.setMinimumSize(1000, 700)
        
        # Central widget with main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create sidebar (initially hidden)
        self.sidebar = QWidget()
        self.sidebar.setFixedWidth(220)
        self.sidebar.setObjectName("sidebar")
        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.setContentsMargins(10, 20, 10, 20)
        self.sidebar_layout.setSpacing(15)
        
        # App logo/title in sidebar
        self.app_logo = QLabel("NeuralGuard")
        self.app_logo.setObjectName("appLogo")
        self.app_logo.setAlignment(Qt.AlignCenter)
        self.sidebar_layout.addWidget(self.app_logo)
        
        # User info panel
        self.user_panel = QWidget()
        self.user_panel.setObjectName("userPanel")
        user_layout = QVBoxLayout(self.user_panel)
        self.user_avatar = QLabel()
        self.user_avatar.setPixmap(QPixmap(":/icons/user.png").scaled(60, 60, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.user_avatar.setAlignment(Qt.AlignCenter)
        self.user_name = QLabel("Guest")
        self.user_name.setAlignment(Qt.AlignCenter)
        self.user_role = QLabel("Unauthorized")
        self.user_role.setAlignment(Qt.AlignCenter)
        
        user_layout.addWidget(self.user_avatar)
        user_layout.addWidget(self.user_name)
        user_layout.addWidget(self.user_role)
        self.sidebar_layout.addWidget(self.user_panel)
        
        # Navigation buttons
        self.nav_buttons = []
        self.create_nav_button("Dashboard", ":/icons/dashboard.png", self.show_dashboard)
        self.create_nav_button("Traffic Monitor", ":/icons/monitor.png", self.show_traffic_monitor)
        self.create_nav_button("Threat Detection", ":/icons/shield.png", self.show_threat_detection)
        self.create_nav_button("Reports", ":/icons/report.png", self.show_reports)
        self.create_nav_button("System Settings", ":/icons/settings.png", self.show_settings)
        
        # Add spacer and logout button
        self.sidebar_layout.addStretch()
        self.create_nav_button("Logout", ":/icons/logout.png", self.logout, True)
        
        # Main content area
        self.content_area = QTabWidget()
        self.content_area.setObjectName("contentArea")
        self.content_area.setTabsClosable(True)
        self.content_area.tabCloseRequested.connect(self.close_tab)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_bar.addPermanentWidget(self.status_label)
        
        # Add widgets to main layout
        self.main_layout.addWidget(self.sidebar)
        self.main_layout.addWidget(self.content_area)
        
        # Initially hide sidebar until login
        self.sidebar.hide()

    def setup_database(self):
        """Initialize database connection and tables"""
        self.conn = sqlite3.connect('network_analysis.db')
        self.create_tables()
        self.users = self.load_users()

    def create_tables(self):
        """Create database tables if they don't exist"""
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    email TEXT NOT NULL,
                    last_login TEXT,
                    avatar TEXT
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS banned_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    reason TEXT,
                    expiry_time REAL NOT NULL,
                    created_by TEXT
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS email_subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    verified INTEGER DEFAULT 0,
                    subscription_type TEXT
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS system_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    setting_name TEXT NOT NULL UNIQUE,
                    setting_value TEXT
                )
            ''')

    def setup_styles(self):
        """Load and apply application styles"""
        # Load fonts
        QFontDatabase.addApplicationFont(":/fonts/Roboto-Regular.ttf")
        QFontDatabase.addApplicationFont(":/fonts/Roboto-Bold.ttf")
        
        # Set style sheet
        self.setStyleSheet('''
            QMainWindow {
                background-color: #f5f7fa;
            }
            #sidebar {
                background-color: #2c3e50;
                border-right: 1px solid #1a252f;
            }
            #appLogo {
                color: #ecf0f1;
                font-size: 24px;
                font-weight: bold;
                padding: 15px 0;
            }
            #userPanel {
                background-color: #34495e;
                border-radius: 8px;
                padding: 15px;
            }
            #userPanel QLabel {
                color: #ecf0f1;
            }
            #userPanel QLabel:first-child {
                font-size: 18px;
                font-weight: bold;
            }
            #userPanel QLabel:last-child {
                font-size: 12px;
                color: #bdc3c7;
            }
            QPushButton#navButton {
                background-color: transparent;
                color: #ecf0f1;
                text-align: left;
                padding: 10px 15px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton#navButton:hover {
                background-color: #34495e;
            }
            QPushButton#navButton:pressed {
                background-color: #2980b9;
            }
            QPushButton#navButton[active="true"] {
                background-color: #3498db;
                font-weight: bold;
            }
            #contentArea {
                background-color: #ffffff;
                border: none;
            }
            QTabWidget::pane {
                border: none;
            }
            QTabBar::tab {
                background: #ecf0f1;
                border: 1px solid #bdc3c7;
                padding: 8px 15px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #3498db;
                color: white;
                border-bottom: 2px solid #2980b9;
            }
            QTabBar::tab:!selected:hover {
                background: #bdc3c7;
            }
        ''')

    def setup_system_tray(self):
        """Create system tray icon and menu"""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
            
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(":/icons/app_icon.png"))
        
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show_normal)
        tray_menu.addAction(show_action)
        
        monitor_action = QAction("Start Monitoring", self)
        monitor_action.triggered.connect(self.start_monitoring)
        tray_menu.addAction(monitor_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(self.close)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_icon_activated)

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_normal()

    def show_normal(self):
        self.show()
        self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
        self.activateWindow()

    def create_nav_button(self, text, icon_path, callback, is_logout=False):
        """Create a styled navigation button"""
        btn = QPushButton(text)
        btn.setObjectName("navButton")
        btn.setIcon(QIcon(icon_path))
        btn.setIconSize(QSize(20, 20))
        btn.setCursor(Qt.PointingHandCursor)
        
        if is_logout:
            btn.setProperty("class", "logout")
            btn.setStyleSheet('''
                QPushButton#navButton[class="logout"] {
                    background-color: #e74c3c;
                    margin-top: 20px;
                }
                QPushButton#navButton[class="logout"]:hover {
                    background-color: #c0392b;
                }
            ''')
        
        btn.clicked.connect(callback)
        self.sidebar_layout.addWidget(btn)
        self.nav_buttons.append(btn)
        return btn

    def check_first_run(self):
        """Check if this is the first run and needs admin setup"""
        with self.conn:
            cursor = self.conn.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            
        if count == 0:
            self.show_admin_setup()

    def show_admin_setup(self):
        """Show first-time admin setup wizard"""
        wizard = QDialog(self)
        wizard.setWindowTitle("Initial Setup")
        wizard.resize(500, 500)
        wizard.setModal(True)
        
        layout = QVBoxLayout(wizard)
        
        # Wizard header
        header = QLabel("Welcome to NeuralGuard")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50;")
        layout.addWidget(header)
        
        # Wizard steps
        self.wizard_stack = QStackedWidget()
        layout.addWidget(self.wizard_stack)
        
        # Step 1: Admin Account
        step1 = QWidget()
        step1_layout = QVBoxLayout(step1)
        
        step1_header = QLabel("Create Admin Account")
        step1_header.setStyleSheet("font-size: 18px;")
        step1_layout.addWidget(step1_header)
        
        form_layout = QFormLayout()
        
        self.admin_username = QLineEdit()
        self.admin_password = QLineEdit()
        self.admin_password.setEchoMode(QLineEdit.Password)
        self.admin_confirm = QLineEdit()
        self.admin_confirm.setEchoMode(QLineEdit.Password)
        self.admin_email = QLineEdit()
        
        form_layout.addRow("Username:", self.admin_username)
        form_layout.addRow("Password:", self.admin_password)
        form_layout.addRow("Confirm Password:", self.admin_confirm)
        form_layout.addRow("Email:", self.admin_email)
        
        step1_layout.addLayout(form_layout)
        
        # Add to wizard
        self.wizard_stack.addWidget(step1)
        
        # Navigation buttons
        nav_buttons = QHBoxLayout()
        self.next_btn = QPushButton("Next")
        self.next_btn.clicked.connect(self.validate_admin_setup)
        nav_buttons.addWidget(self.next_btn)
        
        layout.addLayout(nav_buttons)
        
        wizard.exec_()

    def validate_admin_setup(self):
        """Validate admin setup form"""
        username = self.admin_username.text()
        password = self.admin_password.text()
        confirm = self.admin_confirm.text()
        email = self.admin_email.text()
        
        if not all([username, password, confirm, email]):
            QMessageBox.warning(self, "Missing Information", "All fields are required.")
            return
            
        if password != confirm:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return
            
        if not self.is_valid_email(email):
            QMessageBox.warning(self, "Invalid Email", "Please enter a valid email address.")
            return
            
        # Create admin account
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        with self.conn:
            self.conn.execute('''
                INSERT INTO users (username, password, role, email)
                VALUES (?, ?, 'admin', ?)
            ''', (username, hashed_pw, email))
            
        QMessageBox.information(self, "Setup Complete", "Admin account created successfully.")
        self.sender().parent().accept()

    def show_login(self):
        """Show modern login screen"""
        self.clear_central_widget()
        
        # Create login container
        login_container = QWidget()
        login_container.setObjectName("loginContainer")
        login_layout = QVBoxLayout(login_container)
        login_layout.setAlignment(Qt.AlignCenter)
        
        # App logo
        logo = QLabel()
        logo.setPixmap(QPixmap(":/icons/app_logo_large.png"))
        logo.setAlignment(Qt.AlignCenter)
        login_layout.addWidget(logo)
        
        # Login form
        form_container = QWidget()
        form_container.setObjectName("formContainer")
        form_container.setFixedWidth(350)
        form_layout = QVBoxLayout(form_container)
        form_layout.setContentsMargins(30, 30, 30, 30)
        form_layout.setSpacing(15)
        
        # Form title
        title = QLabel("Sign In")
        title.setObjectName("formTitle")
        title.setAlignment(Qt.AlignCenter)
        form_layout.addWidget(title)
        
        # Username field
        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("Username")
        self.login_username.setProperty("class", "loginField")
        form_layout.addWidget(self.login_username)
        
        # Password field
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Password")
        self.login_password.setProperty("class", "loginField")
        self.login_password.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(self.login_password)
        
        # Remember me checkbox
        self.remember_me = QCheckBox("Remember me")
        form_layout.addWidget(self.remember_me)
        
        # Login button
        login_btn = QPushButton("Login")
        login_btn.setObjectName("loginButton")
        login_btn.clicked.connect(self.handle_login)
        form_layout.addWidget(login_btn)
        
        # Forgot password link
        forgot_link = QLabel("<a href='#' style='color: #3498db; text-decoration: none;'>Forgot password?</a>")
        forgot_link.setAlignment(Qt.AlignCenter)
        forgot_link.linkActivated.connect(self.show_password_reset)
        form_layout.addWidget(forgot_link)
        
        login_layout.addWidget(form_container)
        self.main_layout.addWidget(login_container)
        
        # Apply login-specific styles
        login_container.setStyleSheet('''
            #loginContainer {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #3498db, stop:1 #2c3e50);
            }
            #formContainer {
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            }
            #formTitle {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 20px;
            }
            QLineEdit[class="loginField"] {
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
            }
            QLineEdit[class="loginField"]:focus {
                border-color: #3498db;
            }
            #loginButton {
                background-color: #3498db;
                color: white;
                padding: 12px;
                border: none;
                border-radius: 4px;
                font-size: 16px;
                font-weight: bold;
            }
            #loginButton:hover {
                background-color: #2980b9;
            }
        ''')

    def handle_login(self):
        """Handle login attempt"""
        username = self.login_username.text()
        password = self.login_password.text()
        
        if not username or not password:
            self.show_login_error("Please enter both username and password")
            return
            
        user = self.authenticate_user(username, password)
        if user:
            self.current_user = user
            self.user_name.setText(user['username'])
            self.user_role.setText(user['role'].capitalize())
            
            # Update last login
            with self.conn:
                self.conn.execute('''
                    UPDATE users SET last_login = datetime('now') 
                    WHERE username = ?
                ''', (username,))
                
            # Show main interface
            self.sidebar.show()
            self.clear_central_widget()
            self.main_layout.addWidget(self.sidebar)
            self.main_layout.addWidget(self.content_area)
            
            # Show dashboard by default
            self.show_dashboard()
        else:
            self.show_login_error("Invalid username or password")

    def show_login_error(self, message):
        """Show login error message with animation"""
        error_label = QLabel(message)
        error_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        error_label.setAlignment(Qt.AlignCenter)
        
        # Add to layout if not already there
        if not hasattr(self, 'login_error_label'):
            form_container = self.login_username.parent()
            form_layout = form_container.layout()
            form_layout.insertWidget(1, error_label)
            self.login_error_label = error_label
        else:
            self.login_error_label.setText(message)
            
        # Animation effect
        effect = QGraphicsDropShadowEffect()
        effect.setColor(QColor("#e74c3c"))
        effect.setBlurRadius(10)
        effect.setOffset(0, 0)
        error_label.setGraphicsEffect(effect)
        
        # Timer to remove effect
        QTimer.singleShot(1000, lambda: error_label.setGraphicsEffect(None))

    def authenticate_user(self, username, password):
        """Authenticate user against database"""
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        
        with self.conn:
            cursor = self.conn.execute('''
                SELECT username, role, email FROM users 
                WHERE username = ? AND password = ?
            ''', (username, hashed_pw))
            user = cursor.fetchone()
            
        if user:
            return {
                'username': user[0],
                'role': user[1],
                'email': user[2]
            }
        return None

    def show_dashboard(self):
        """Show the main dashboard"""
        if not self.current_user:
            return
            
        # Create dashboard tab if not exists
        for i in range(self.content_area.count()):
            if self.content_area.tabText(i) == "Dashboard":
                self.content_area.setCurrentIndex(i)
                return
                
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Dashboard header
        header = QLabel("Network Overview")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50;")
        layout.addWidget(header)
        
        # Stats widgets
        stats_container = QWidget()
        stats_layout = QHBoxLayout(stats_container)
        
        # Create stat cards
        self.create_stat_card(stats_layout, "Traffic Today", "45.2 GB", "#3498db")
        self.create_stat_card(stats_layout, "Threats Blocked", "128", "#e74c3c")
        self.create_stat_card(stats_layout, "Devices Online", "24", "#2ecc71")
        self.create_stat_card(stats_layout, "Alerts", "5", "#f39c12")
        
        layout.addWidget(stats_container)
        
        # Traffic chart (placeholder)
        chart_container = QWidget()
        chart_container.setObjectName("chartContainer")
        chart_container.setMinimumHeight(300)
        chart_container.setStyleSheet('''
            #chartContainer {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #ddd;
            }
        ''')
        layout.addWidget(chart_container)
        
        # Recent activity
        activity_header = QLabel("Recent Activity")
        activity_header.setStyleSheet("font-size: 18px; margin-top: 20px;")
        layout.addWidget(activity_header)
        
        activity_table = QTreeWidget()
        activity_table.setColumnCount(4)
        activity_table.setHeaderLabels(["Time", "Event", "Source", "Action"])
        activity_table.setStyleSheet('''
            QTreeWidget {
                border: 1px solid #ddd;
                border-radius: 4px;
            }
        ''')
        
        # Add sample data
        sample_data = [
            ("10:23 AM", "Suspicious packet", "192.168.1.5", "Blocked"),
            ("09:45 AM", "Port scan detected", "10.0.0.12", "Alerted"),
            ("08:30 AM", "New device connected", "192.168.1.8", "Logged"),
            ("07:15 AM", "System update", "Internal", "Completed")
        ]
        
        for time, event, source, action in sample_data:
            item = QTreeWidgetItem([time, event, source, action])
            activity_table.addTopLevelItem(item)
        
        layout.addWidget(activity_table)
        
        # Add tab
        self.content_area.addTab(tab, "Dashboard")
        self.content_area.setCurrentWidget(tab)
        
        # Highlight dashboard button
        self.highlight_nav_button(0)

    def create_stat_card(self, layout, title, value, color):
        """Create a statistic card widget"""
        card = QWidget()
        card.setObjectName("statCard")
        card.setMinimumWidth(200)
        card.setMinimumHeight(100)
        
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(15, 15, 15, 15)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #7f8c8d; font-size: 14px;")
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        
        card_layout.addWidget(title_label)
        card_layout.addWidget(value_label)
        card_layout.addStretch()
        
        card.setStyleSheet(f'''
            #statCard {{
                background-color: white;
                border-radius: 8px;
                border-left: 4px solid {color};
            }}
        ''')
        
        layout.addWidget(card)

    def show_traffic_monitor(self):
        """Show traffic monitoring interface"""
        if not self.current_user:
            return
            
        # Create tab if not exists
        for i in range(self.content_area.count()):
            if self.content_area.tabText(i) == "Traffic Monitor":
                self.content_area.setCurrentIndex(i)
                return
                
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Header
        header = QLabel("Real-time Traffic Monitoring")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50;")
        layout.addWidget(header)
        
        # Interface selector
        interface_container = QWidget()
        interface_layout = QHBoxLayout(interface_container)
        
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.demo_interfaces)
        interface_layout.addWidget(QLabel("Network Interface:"))
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addStretch()
        
        self.start_button = QPushButton("Start Capture")
        self.start_button.setIcon(QIcon(":/icons/play.png"))
        self.start_button.clicked.connect(self.toggle_capture)
        interface_layout.addWidget(self.start_button)
        
        layout.addWidget(interface_container)
        
        # Traffic stats
        stats_container = QWidget()
        stats_layout = QHBoxLayout(stats_container)
        
        self.create_traffic_stat(stats_layout, "Packets/s", "0", "#3498db")
        self.create_traffic_stat(stats_layout, "Bytes/s", "0", "#2ecc71")
        self.create_traffic_stat(stats_layout, "TCP", "0", "#9b59b6")
        self.create_traffic_stat(stats_layout, "UDP", "0", "#e67e22")
        self.create_traffic_stat(stats_layout, "Other", "0", "#34495e")
        
        layout.addWidget(stats_container)
        
        # Packet table
        self.packet_table = QTreeWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.setSortingEnabled(True)
        self.packet_table.setAlternatingRowColors(True)
        layout.addWidget(self.packet_table)
        
        # Add tab
        self.content_area.addTab(tab, "Traffic Monitor")
        self.content_area.setCurrentWidget(tab)
        
        # Highlight button
        self.highlight_nav_button(1)

    def toggle_capture(self):
        """Toggle packet capture"""
        if self.start_button.text() == "Start Capture":
            self.start_button.setText("Stop Capture")
            self.start_button.setIcon(QIcon(":/icons/stop.png"))
            self.start_button.setStyleSheet("background-color: #e74c3c; color: white;")
            
            # Start simulated capture
            self.capture_timer = QTimer()
            self.capture_timer.timeout.connect(self.update_capture_stats)
            self.capture_timer.start(1000)
        else:
            self.start_button.setText("Start Capture")
            self.start_button.setIcon(QIcon(":/icons/play.png"))
            self.start_button.setStyleSheet("")
            self.capture_timer.stop()

    def update_capture_stats(self):
        """Update capture statistics with simulated data"""
        # Update stats
        for i in range(5):
            self.traffic_stats[i].setText(str(random.randint(10, 1000)))
        
        # Add sample packet
        protocols = ["TCP", "UDP", "ICMP", "HTTP", "DNS"]
        src_ips = [f"192.168.1.{x}" for x in range(1, 20)]
        dst_ips = [f"10.0.0.{x}" for x in range(1, 10)] + ["8.8.8.8", "1.1.1.1"]
        
        item = QTreeWidgetItem([
            time.strftime("%H:%M:%S"),
            random.choice(src_ips),
            random.choice(dst_ips),
            random.choice(protocols),
            str(random.randint(40, 1500)),
            "Sample packet info"
        ])
        self.packet_table.insertTopLevelItem(0, item)
        
        # Keep only last 100 items
        if self.packet_table.topLevelItemCount() > 100:
            self.packet_table.takeTopLevelItem(100)

    def create_traffic_stat(self, layout, label, value, color):
        """Create a traffic statistic widget"""
        stat = QWidget()
        stat.setFixedWidth(150)
        
        stat_layout = QVBoxLayout(stat)
        stat_layout.setContentsMargins(10, 10, 10, 10)
        
        label_widget = QLabel(label)
        label_widget.setStyleSheet("color: #7f8c8d; font-size: 12px;")
        label_widget.setAlignment(Qt.AlignCenter)
        
        value_widget = QLabel(value)
        value_widget.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")
        value_widget.setAlignment(Qt.AlignCenter)
        
        stat_layout.addWidget(label_widget)
        stat_layout.addWidget(value_widget)
        
        stat.setStyleSheet('''
            QWidget {
                background-color: white;
                border-radius: 4px;
                border: 1px solid #ddd;
            }
        ''')
        
        layout.addWidget(stat)
        
        # Keep reference to update later
        if not hasattr(self, 'traffic_stats'):
            self.traffic_stats = []
        self.traffic_stats.append(value_widget)

    def show_threat_detection(self):
        """Show threat detection interface"""
        if not self.current_user:
            return
            
        # Create tab if not exists
        for i in range(self.content_area.count()):
            if self.content_area.tabText(i) == "Threat Detection":
                self.content_area.setCurrentIndex(i)
                return
                
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Header
        header = QLabel("Threat Detection Dashboard")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50;")
        layout.addWidget(header)
        
        # Threat summary
        summary_container = QWidget()
        summary_layout = QHBoxLayout(summary_container)
        
        # Threat level indicator
        threat_indicator = QWidget()
        threat_indicator.setFixedWidth(200)
        threat_layout = QVBoxLayout(threat_indicator)
        
        threat_level = QLabel("MEDIUM")
        threat_level.setStyleSheet("font-size: 32px; font-weight: bold; color: #f39c12;")
        threat_level.setAlignment(Qt.AlignCenter)
        
        threat_desc = QLabel("Elevated threat level detected")
        threat_desc.setStyleSheet("font-size: 14px; color: #7f8c8d;")
        threat_desc.setAlignment(Qt.AlignCenter)
        
        threat_layout.addWidget(threat_level)
        threat_layout.addWidget(threat_desc)
        threat_layout.addStretch()
        
        summary_layout.addWidget(threat_indicator)
        
        # Threat breakdown
        breakdown = QWidget()
        breakdown.setStyleSheet("background-color: white; border-radius: 8px;")
        breakdown_layout = QVBoxLayout(breakdown)
        
        breakdown_title = QLabel("Threat Breakdown")
        breakdown_title.setStyleSheet("font-weight: bold; padding: 10px;")
        breakdown_layout.addWidget(breakdown_title)
        
        # Threat progress bars
        threats = [
            ("Malware", 45, "#e74c3c"),
            ("Intrusion Attempts", 28, "#f39c12"),
            ("Policy Violations", 15, "#3498db"),
            ("Suspicious Activity", 12, "#9b59b6")
        ]
        
        for name, value, color in threats:
            threat_row = QWidget()
            row_layout = QHBoxLayout(threat_row)
            
            label = QLabel(name)
            progress = QProgressBar()
            progress.setValue(value)
            progress.setTextVisible(False)
            progress.setStyleSheet(f'''
                QProgressBar {{
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    height: 10px;
                }}
                QProgressBar::chunk {{
                    background-color: {color};
                    border-radius: 4px;
                }}
            ''')
            
            value_label = QLabel(f"{value}%")
            value_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            
            row_layout.addWidget(label)
            row_layout.addWidget(progress)
            row_layout.addWidget(value_label)
            
            breakdown_layout.addWidget(threat_row)
        
        summary_layout.addWidget(breakdown, 1)
        layout.addWidget(summary_container)
        
        # Recent threats table
        threat_table = QTreeWidget()
        threat_table.setColumnCount(5)
        threat_table.setHeaderLabels(["Time", "Threat Type", "Source", "Target", "Action"])
        threat_table.setSortingEnabled(True)
        
        # Sample threat data
        threat_types = ["Malware", "Port Scan", "DDoS", "SQL Injection", "Phishing"]
        actions = ["Blocked", "Alerted", "Quarantined", "Logged"]
        
        for i in range(15):
            item = QTreeWidgetItem([
                f"{(i+8):02d}:{random.randint(10, 59):02d} AM",
                random.choice(threat_types),
                f"192.168.1.{random.randint(1, 254)}",
                f"10.0.0.{random.randint(1, 254)}",
                random.choice(actions)
            ])
            threat_table.addTopLevelItem(item)
        
        layout.addWidget(threat_table)
        
        # Add tab
        self.content_area.addTab(tab, "Threat Detection")
        self.content_area.setCurrentWidget(tab)
        
        # Highlight button
        self.highlight_nav_button(2)

    def show_reports(self):
        """Show reporting interface"""
        if not self.current_user:
            return
            
        # Create tab if not exists
        for i in range(self.content_area.count()):
            if self.content_area.tabText(i) == "Reports":
                self.content_area.setCurrentIndex(i)
                return
                
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Header
        header = QLabel("Reports & Analytics")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50;")
        layout.addWidget(header)
        
        # Report controls
        controls = QWidget()
        controls_layout = QHBoxLayout(controls)
        
        period_combo = QComboBox()
        period_combo.addItems(["Last 24 hours", "Last 7 days", "Last 30 days", "Custom range"])
        controls_layout.addWidget(QLabel("Report Period:"))
        controls_layout.addWidget(period_combo)
        
        report_type = QComboBox()
        report_type.addItems(["Threat Summary", "Traffic Analysis", "Device Activity", "Full Report"])
        controls_layout.addWidget(QLabel("Report Type:"))
        controls_layout.addWidget(report_type)
        
        generate_btn = QPushButton("Generate Report")
        generate_btn.setIcon(QIcon(":/icons/report.png"))
        generate_btn.clicked.connect(self.generate_report)
        controls_layout.addWidget(generate_btn)
        
        export_btn = QPushButton("Export")
        export_btn.setIcon(QIcon(":/icons/export.png"))
        controls_layout.addWidget(export_btn)
        
        layout.addWidget(controls)
        
        # Report preview area
        preview = QTextEdit()
        preview.setReadOnly(True)
        preview.setStyleSheet("background-color: white; border: 1px solid #ddd;")
        layout.addWidget(preview, 1)
        
        # Add sample report
        preview.setHtml('''
            <h2 style="color: #2c3e50;">Network Security Report</h2>
            <h3 style="color: #3498db;">Last 24 Hours Summary</h3>
            <hr>
            <p><b>Total Traffic:</b> 42.7 GB</p>
            <p><b>Threats Detected:</b> 18</p>
            <p><b>Top Threat Types:</b></p>
            <ul>
                <li>Port Scans (7 incidents)</li>
                <li>Malware Attempts (5 incidents)</li>
                <li>Suspicious Logins (3 incidents)</li>
            </ul>
            <p><b>Recommendations:</b></p>
            <ul>
                <li>Review firewall rules for port 22</li>
                <li>Update IDS signatures</li>
                <li>Check device 192.168.1.15 for unusual activity</li>
            </ul>
        ''')
        
        # Add tab
        self.content_area.addTab(tab, "Reports")
        self.content_area.setCurrentWidget(tab)
        
        # Highlight button
        self.highlight_nav_button(3)

    def generate_report(self):
        """Generate a sample report"""
        QMessageBox.information(self, "Report Generated", "The report has been generated successfully.")

    def show_settings(self):
        """Show system settings interface"""
        if not self.current_user or self.current_user['role'] != 'admin':
            QMessageBox.warning(self, "Access Denied", "Only administrators can access system settings.")
            return
            
        # Create tab if not exists
        for i in range(self.content_area.count()):
            if self.content_area.tabText(i) == "System Settings":
                self.content_area.setCurrentIndex(i)
                return
                
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Header
        header = QLabel("System Configuration")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50;")
        layout.addWidget(header)
        
        # Settings tabs
        settings_tabs = QTabWidget()
        
        # General Settings
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)
        
        self.sys_name = QLineEdit("NeuralGuard System")
        general_layout.addRow("System Name:", self.sys_name)
        
        self.sys_email = QLineEdit("alerts@neuralguard.com")
        general_layout.addRow("Notification Email:", self.sys_email)
        
        self.log_retention = QComboBox()
        self.log_retention.addItems(["30 days", "60 days", "90 days", "1 year", "Indefinite"])
        general_layout.addRow("Log Retention:", self.log_retention)
        
        settings_tabs.addTab(general_tab, "General")
        
        # Network Settings
        network_tab = QWidget()
        network_layout = QFormLayout(network_tab)
        
        self.monitor_interfaces = QListWidget()
        self.monitor_interfaces.addItems(self.demo_interfaces)
        self.monitor_interfaces.setSelectionMode(QListWidget.MultiSelection)
        network_layout.addRow("Monitor Interfaces:", self.monitor_interfaces)
        
        self.auto_block = QCheckBox("Automatically block malicious IPs")
        self.auto_block.setChecked(True)
        network_layout.addRow(self.auto_block)
        
        settings_tabs.addTab(network_tab, "Network")
        
        # User Management
        user_tab = QWidget()
        user_layout = QVBoxLayout(user_tab)
        
        user_table = QTreeWidget()
        user_table.setColumnCount(3)
        user_table.setHeaderLabels(["Username", "Role", "Last Login"])
        
        # Add sample users
        users = [
            ("admin", "Administrator", "Today 09:45 AM"),
            ("analyst1", "Security Analyst", "Yesterday 02:30 PM"),
            ("viewer1", "Viewer", "Monday 11:20 AM")
        ]
        
        for username, role, login in users:
            item = QTreeWidgetItem([username, role, login])
            user_table.addTopLevelItem(item)
        
        user_layout.addWidget(user_table)
        
        # User controls
        user_controls = QHBoxLayout()
        add_user_btn = QPushButton("Add User")
        add_user_btn.setIcon(QIcon(":/icons/add_user.png"))
        edit_user_btn = QPushButton("Edit User")
        edit_user_btn.setIcon(QIcon(":/icons/edit_user.png"))
        del_user_btn = QPushButton("Delete User")
        del_user_btn.setIcon(QIcon(":/icons/delete_user.png"))
        
        user_controls.addWidget(add_user_btn)
        user_controls.addWidget(edit_user_btn)
        user_controls.addWidget(del_user_btn)
        user_layout.addLayout(user_controls)
        
        settings_tabs.addTab(user_tab, "Users")
        
        # Save button
        save_btn = QPushButton("Save Settings")
        save_btn.setIcon(QIcon(":/icons/save.png"))
        save_btn.clicked.connect(self.save_settings)
        
        layout.addWidget(settings_tabs, 1)
        layout.addWidget(save_btn, 0, Qt.AlignRight)
        
        # Add tab
        self.content_area.addTab(tab, "System Settings")
        self.content_area.setCurrentWidget(tab)
        
        # Highlight button
        self.highlight_nav_button(4)

    def save_settings(self):
        """Save system settings"""
        QMessageBox.information(self, "Settings Saved", "All changes have been saved successfully.")

    def show_password_reset(self):
        """Show password reset dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Password Recovery")
        dialog.resize(400, 250)
        
        layout = QVBoxLayout(dialog)
        
        title = QLabel("Reset Your Password")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        form = QFormLayout()
        
        email_input = QLineEdit()
        email_input.setPlaceholderText("Your account email")
        form.addRow("Email:", email_input)
        
        layout.addLayout(form)
        
        info = QLabel("A password reset link will be sent to your email address.")
        info.setWordWrap(True)
        info.setStyleSheet("color: #7f8c8d;")
        layout.addWidget(info)
        
        buttons = QHBoxLayout()
        reset_btn = QPushButton("Send Reset Link")
        reset_btn.clicked.connect(lambda: self.send_reset_email(email_input.text(), dialog))
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        
        buttons.addWidget(reset_btn)
        buttons.addWidget(cancel_btn)
        layout.addLayout(buttons)
        
        dialog.exec_()

    def send_reset_email(self, email, dialog):
        """Send password reset email"""
        if not email or not self.is_valid_email(email):
            QMessageBox.warning(dialog, "Invalid Email", "Please enter a valid email address.")
            return
            
        # Check if email exists
        with self.conn:
            cursor = self.conn.execute("SELECT username FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            
        if not user:
            QMessageBox.warning(dialog, "Email Not Found", "No account found with that email address.")
            return
            
        # In a real app, you would send an email here
        QMessageBox.information(dialog, "Reset Sent", 
            "If an account exists with this email, a password reset link has been sent.")
        dialog.accept()

    def highlight_nav_button(self, index):
        """Highlight the currently active navigation button"""
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.setProperty("active", "true")
            else:
                btn.setProperty("active", "false")
            btn.style().polish(btn)

    def close_tab(self, index):
        """Close a content tab"""
        if self.content_area.count() > 1:  # Don't close the last tab
            self.content_area.removeTab(index)

    def clear_central_widget(self):
        """Clear the central widget contents"""
        while self.main_layout.count():
            item = self.main_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def logout(self):
        """Handle user logout"""
        self.current_user = None
        self.sidebar.hide()
        self.content_area.clear()
        self.show_login()

    def is_valid_email(self, email):
        """Validate email format"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_pattern, email) is not None

    def start_monitoring(self):
        """Start network monitoring"""
        if not hasattr(self, 'traffic_monitor_tab'):
            self.show_traffic_monitor()
        self.content_area.setCurrentWidget(self.traffic_monitor_tab)
        self.toggle_capture()

    def closeEvent(self, event):
        """Handle window close event"""
        if hasattr(self, 'tray_icon') and self.tray_icon.isVisible():
            self.hide()
            event.ignore()
        else:
            # Save settings and cleanup
            if hasattr(self, 'conn'):
                self.conn.close()
            event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = ModernTrafficAnalyzer()
    window.show()
    
    sys.exit(app.exec_())