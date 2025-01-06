from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography import x509
import PyKCS11
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sys
from PyQt5 import QtWidgets, QtCore
from multiprocessing import Pipe, Process
from datetime import datetime, timedelta, timezone
import requests
import base64
import uuid
import psutil
import platform
import hashlib
import secrets
import sqlite3
import getpass
from pystray import Icon, Menu, MenuItem
from PIL import Image, ImageDraw
import threading 
import os
import signal
import logging 
import socket

# Configure logging to write to a file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs\\client-{datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime('%Y-%m-%d')}.log"),
        logging.StreamHandler()
    ]
)

def fetch_domain_ip(domain):
    try:
        if domain.replace('.', '').isdigit():
            socket.inet_aton(domain)
            return domain
             
        return socket.gethostbyname(domain)
    except (socket.error, socket.gaierror) as e:
        logging.error(f"Error resolving {domain}: {e}")
        return None
    
def add_domain_mapping(domain):
    try:
        conn = sqlite3.connect('signerData.db')
        cursor = conn.cursor()
        ip = fetch_domain_ip(domain)
        if not ip:
            raise ValueError("Error fetching IP for domain")
        cursor.execute("SELECT * FROM domain_mapping WHERE domain_name = ? AND domain_ip = ?", (domain, ip))
        result = cursor.fetchone()
        if not result:
            conn.execute("BEGIN")
            cursor.execute('''
                INSERT INTO domain_mapping (domain_name, domain_ip)
                VALUES (?, ?)
            ''', (domain, ip))
            conn.commit()
            logging.info(f"Domain mapping added for {domain}")
            return 1
        else:
            logging.info(f"Domain mapping already exists for {domain}")
            return 2
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logging.error(f"Database error in add_domain_mapping: {e}")
        return 0
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Error in add_domain_mapping: {e}")
        return 0
    finally:
        if conn:
            conn.close()

def view_domain_mappings():
    try:
        conn = sqlite3.connect('signerData.db')
        cursor = conn.cursor()
        cursor.execute("SELECT domain_name FROM domain_mapping")
        result = cursor.fetchall()
        if result:
            return [domain[0] for domain in result]
    except sqlite3.Error as e:
        logging.error(f"Database error in view_domain_mappings: {e}")
        return []
    except Exception as e:
        logging.error(f"Error in view_domain_mappings: {e}")
        return []
    finally:
        if conn:
            conn.close()

def remove_domain_mapping(domain):
    try:
        conn = sqlite3.connect('signerData.db')
        cursor = conn.cursor()
        conn.execute("BEGIN")
        cursor.execute('''
            DELETE FROM domain_mapping
            WHERE domain_name = ?
        ''', (domain,))
        conn.commit()
        logging.info(f"Domain mapping removed for {domain}")
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logging.error(f"Database error in remove_domain_mapping: {e}")
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Error in remove_domain_mapping: {e}")
    finally:
        if conn:
            conn.close()

def prompt_for_pin_in_process(conn):
    app = QtWidgets.QApplication(sys.argv)
    pin, ok = QtWidgets.QInputDialog.getText(None, "PIN Entry", "Please enter your PIN:", QtWidgets.QLineEdit.Password)
    if ok and pin.strip():
        conn.send(pin.strip())
    else:
        conn.send(None)
    conn.close()
    app.quit()
    sys.exit(0)  

def prompt_for_pin():
    parent_conn, child_conn = Pipe()
    p = Process(target=prompt_for_pin_in_process, args=(child_conn,))
    p.start()
    p.join()
    return parent_conn.recv()

def message_prompt_in_process(conn, msg):
    app = QtWidgets.QApplication(sys.argv)
    message_box = QtWidgets.QMessageBox()
    message_box.setIcon(QtWidgets.QMessageBox.Information)
    message_box.setText(msg)
    message_box.setWindowTitle("Message")
    message_box.setStandardButtons(QtWidgets.QMessageBox.Ok)
    message_box.exec_()
 
    conn.close()
    app.quit()
    sys.exit(0)

def message_prompt(msg):
    parent_conn, child_conn = Pipe()
    p = Process(target=message_prompt_in_process, args=(child_conn, msg))
    p.start()
    p.join()

def manage_domain_mapping_prompt_in_process(conn):
    app = QtWidgets.QApplication(sys.argv)
    window = QtWidgets.QWidget()
    window.setWindowTitle("Manage Domain Mapping")
    window.setWindowFlags(window.windowFlags() & ~QtCore.Qt.WindowMinimizeButtonHint & ~QtCore.Qt.WindowMaximizeButtonHint & ~QtCore.Qt.WindowSystemMenuHint)
    screen_geometry = app.desktop().availableGeometry()
    window_width, window_height = 400, 400
    window_x = screen_geometry.width() - window_width - 20
    window_y = screen_geometry.height() - window_height - 20
    window.setGeometry(window_x, window_y, window_width, window_height)
    window.setFixedSize(window_width, window_height)

    # Force the window to be in focus
    window.setWindowModality(QtCore.Qt.ApplicationModal)
    window.activateWindow()
    window.raise_()

    layout = QtWidgets.QVBoxLayout()

    # Text box to enter domain name
    domain_input = QtWidgets.QLineEdit()
    domain_input.setPlaceholderText("Enter domain name")
    layout.addWidget(domain_input)

    # Add Domain button
    add_button = QtWidgets.QPushButton("Add Domain")
    layout.addWidget(add_button)

    # Set hover effect for the button
    add_button.setStyleSheet("""
        QPushButton:hover {
            background-color: lightgreen;
        }
    """)

    #add a gap between buttons and label
    spacer = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
    layout.addItem(spacer)

    #add label with text "Mapped Domains"
    mapped_domains_label = QtWidgets.QLabel("Mapped Domains")
    layout.addWidget(mapped_domains_label)

    # List of domain mappings
    domain_list = QtWidgets.QListWidget()
    layout.addWidget(domain_list)

    def refresh_domain_list():
        domain_list.clear()
        domains = view_domain_mappings()
        if domains:
            for domain in domains:
                item = QtWidgets.QListWidgetItem(domain)
                domain_list.addItem(item)

    refresh_domain_list()

    # Delete Domain button
    delete_button = QtWidgets.QPushButton("Delete Selected Domain")
    layout.addWidget(delete_button)

    delete_button.setStyleSheet("""
        QPushButton:hover {
            background-color: lightcoral;
        }
    """)

    def delete_domain():
        selected_items = domain_list.selectedItems()
        if selected_items:
            for item in selected_items:
                domain = item.text()
                remove_domain_mapping(domain)
                refresh_domain_list()

    delete_button.clicked.connect(delete_domain)
 
    def add_domain():
        domain = domain_input.text().strip()
        if domain:
            if domain.startswith('http://') or domain.startswith('https://'):
                domain = domain.split('/')[2].split(':')[0]
            result = add_domain_mapping(domain)
            if result == 1:
                refresh_domain_list()
            elif result == 2:
                message_prompt("Domain mapping already exists.")
            else:
                message_prompt("Error adding domain mapping.")
        domain_input.clear()

    add_button.clicked.connect(add_domain)

    window.setLayout(layout)
    window.show()
    app.exec_()
    conn.close()
    sys.exit(0)

def manage_domain_mapping_prompt():
    parent_conn, child_conn = Pipe()
    p = Process(target=manage_domain_mapping_prompt_in_process, args=(child_conn,))
    p.start()
    p.join()

def on_exit(icon, item):
    """Stop the system tray and Flask server."""
    logging.info("Exiting application...")
    icon.stop()
    stop_flask()

def stop_flask():
    """Stop the Flask server by sending a termination signal."""
    logging.info("Stopping Flask server...")
    os.kill(os.getpid(), signal.SIGINT)  # Send SIGINT to terminate the process gracefully

def create_image():
    """Create an icon image for the tray."""
    width = 64
    height = 64
    color1 = "blue"
    color2 = "white"

    image = Image.new("RGB", (width, height), color1)
    draw = ImageDraw.Draw(image)
    draw.rectangle((width // 4, height // 4, width * 3 // 4, height * 3 // 4), fill=color2)
    return image

def start_tray(): 
    menu = Menu(
        MenuItem("Manage Domain Mappings", manage_domain_mapping_prompt),
        MenuItem("Exit", on_exit)
    )
    icon = Icon("Ultra Signer", create_image(), menu=menu)
    icon.run()

def is_already_running():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 41769))  # Bind to a specific port
    except socket.error:
        message_prompt("An instance of the application is already running...")
        sys.exit(1)

if __name__ == '__main__':
    is_already_running() 

    # Start the system tray
    start_tray()