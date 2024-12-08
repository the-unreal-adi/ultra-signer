from flask import Flask, request, jsonify
from flask_cors import CORS
import PyKCS11 
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from PyQt5 import QtWidgets
import sys
from multiprocessing import Pipe, Process
from datetime import datetime, timezone
import requests
import base64
import uuid
import psutil
import platform
import hashlib
import secrets
import sqlite3
import getpass
import binascii
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app)

def get_mac_address():
    # Fetch the MAC address of the system
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
    return mac

def get_client_id():
    print("Generating client id...")
    try:
        # Get CPU info (brand string or equivalent)
        cpu_info = platform.processor()

        # Get disk information (use the first disk's serial number or mount point)
        disk_info = None
        for disk in psutil.disk_partitions(all=False):
            if disk.fstype:  # Filter only valid partitions
                disk_info = disk.device
                break

        if not disk_info:
            disk_info = "UnknownDisk"

        mac_address = get_mac_address()

        username = getpass.getuser()

        # Combine CPU, Disk information and MAC Address into a unique string
        unique_string = f"USER:{username}--CPU:{cpu_info}-DISK:{disk_info}--MAC:{mac_address}"

        # Generate a UUID based on the unique string
        machine_guid = uuid.uuid5(uuid.NAMESPACE_DNS, unique_string)
        return str(machine_guid), username, cpu_info, disk_info, mac_address
    except Exception as e:
        return f"Error: {str(e)}"

def generate_base64_id(components):
    """
    Generate a 16-byte hash-based ID from a list of components and return it as Base64.
    Each component is concatenated into a single string before hashing.
    
    Args:
        components (list): List of string components to include in the hash.

    Returns:
        str: Base64-encoded 16-byte hash.
    """
    # Join the components into a single string
    combined_data = ''.join(components).encode('utf-8')
    
    # Generate a 16-byte hash (MD5)
    hash_object = hashlib.md5(combined_data)  # Use MD5 for a 16-byte hash
    hash_bytes = hash_object.digest()
    
    # Encode the hash in Base64
    id_base64 = base64.b64encode(hash_bytes).decode('utf-8')
    return id_base64

def init_db():
    connection = None
    try:
        # Connect to the database
        connection = sqlite3.connect("signerData.db")
        cursor = connection.cursor()

        # Begin a transaction
        connection.execute("BEGIN")

        # Create the client_info table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS client_info (
                client_id TEXT PRIMARY KEY,
                user_name TEXT NOT NULL,
                cpu_info TEXT NOT NULL,
                disk_info TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                recent_driver TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS registered_tokens (
                reg_id TEXT PRIMARY KEY,
                key_id TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                nonce TEXT NOT NULL,
                signature TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                is_verified TEXT NOT NULL
            )
        ''')

        # Commit the transaction
        connection.commit()
    except sqlite3.Error as e:
        # Roll back the transaction in case of an error
        if connection:
            connection.rollback()
        print(f"Database error occurred: {e}")
        raise
    except Exception as e:
        # Catch any other exceptions
        if connection:
            connection.rollback()
        print(f"An error occurred: {e}")
        raise
    finally:
        # Ensure the connection is closed
        if connection:
            connection.close()

def init_client():
    try:
        # Connect to the database
        connection = sqlite3.connect("signerData.db")
        cursor = connection.cursor()

        client_id = None
        recent_driver = None

        cursor.execute("SELECT client_id, recent_driver FROM client_info LIMIT 1")
        result = cursor.fetchone()

        if result:
            client_id = str(result[0])
            recent_driver = str(result[1])
        else:
            client_id, user_name, cpu_info, disk_info, mac_address = get_client_id()

            if not client_id:
                print("Error fetching client id")
                raise

            recent_driver = "token_drivers\\windows\\eps2003csp11v264.dll"

            # Begin a transaction
            connection.execute("BEGIN")

            cursor.execute('''
                INSERT INTO client_info (client_id, user_name, cpu_info, disk_info, mac_address, recent_driver)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (client_id, user_name, cpu_info, disk_info, mac_address, recent_driver))

            connection.commit()

        app.client_id = client_id    
        app.driver_path = recent_driver
    except sqlite3.Error as e:
        if connection:
            connection.rollback()
        print(f"Database error occurred: {e}")
        raise
    except Exception as e:
        if connection:
            connection.rollback()
        print(f"An error occurred: {e}")
        raise
    finally:
        # Ensure the connection is closed
        if connection:
            connection.close()

def store_registration_data(unique_id, key_id, owner_name, nonce, signature, timestamp):
    """
    Store the verified registration data in the 'registered_tokens' SQLite database table.
    All fields except the ID are stored in Base64 format. The ID is derived from a hash of provided components.
    """
    try:
        signature_base64 = base64.b64encode(binascii.unhexlify(signature)).decode('utf-8')
        nonce_base64 = base64.b64encode(nonce.encode('utf-8')).decode('utf-8')
        key_id_base64 = base64.b64encode(key_id.encode('utf-8')).decode('utf-8')

        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        # Begin a transaction
        conn.execute("BEGIN")

        # Insert the verified registration data
        cursor.execute('''
            INSERT INTO registered_tokens (reg_id, key_id, owner_name, nonce, signature, timestamp, is_verified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (unique_id, key_id_base64, owner_name, nonce_base64, signature_base64, timestamp, "N"))

        conn.commit()  # Commit the transaction
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def update_registration_status(reg_id):
    try:
        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        conn.execute("BEGIN")

        cursor.execute("""
            UPDATE registered_tokens
            SET is_verified = 'Y'
            WHERE reg_id = ? AND is_verified = 'N'
        """, (reg_id,))

        # Commit the transaction to save changes
        conn.commit()

        # Check if any row was updated
        if cursor.rowcount == 0:
            print(f"No record found with reg_id = {reg_id}.")
            raise

    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def clear_failed_registration():
    try:
        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        conn.execute("BEGIN")
        
        cursor.execute("""
            DELETE FROM registered_tokens
            WHERE is_verified = 'N'
        """,)

        # Commit the transaction to save changes
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def clear_junk_registration(reg_id):
    try:
        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        conn.execute("BEGIN")
        
        cursor.execute("""
            DELETE FROM registered_tokens
            WHERE reg_id = ?
        """,(reg_id,))

        # Commit the transaction to save changes
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def get_dsc_reg_id(key_id):
    reg_id = None

    try:
        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        key_id_base64 = base64.b64encode(key_id.encode('utf-8')).decode('utf-8')

        cursor.execute("SELECT reg_id FROM registered_tokens WHERE key_id = ? AND is_verified = 'Y'", (key_id_base64,))
        result = cursor.fetchone()
         
        if result:
            reg_id = str(result[0])
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    return reg_id

def update_driver_path(recent_driver):
    try:
        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        conn.execute("BEGIN")

        cursor.execute("""
            UPDATE client_info
            SET recent_driver = ?
        """, (recent_driver,))

        # Commit the transaction to save changes
        conn.commit()

        # Check if any row was updated
        if cursor.rowcount == 0:
            print(f"Error updating driver path {recent_driver}.")
            raise

    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def fetch_certificate_publicKey_ownerName(pkcsSession):
    certs = pkcsSession.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
    if not certs:
        raise ValueError("No certificate found on the DSC token")
    
    cert_der = bytes(pkcsSession.getAttributeValue(certs[0], [PyKCS11.CKA_VALUE], True)[0])
    
    certificate = x509.load_der_x509_certificate(cert_der, default_backend())
    
    public_key = certificate.public_key()
    public_key_der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo) 

    owner_name = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

    pub_key = pkcsSession.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)])[0]

    key_id = bytes(pkcsSession.getAttributeValue(pub_key, [PyKCS11.CKA_ID], True)[0])

    return cert_der, public_key_der, owner_name, key_id

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

def get_internet_time():
    try:
        response = requests.get("https://timeapi.io/api/Time/current/zone?timeZone=UTC")
        response.raise_for_status()  
        data = response.json()
        return str(data["dateTime"])  
    except Exception as e:
        print(f"Error fetching internet time: {e}")
        return None

def load_drivers_windows():
    folder_path = "token_drivers\\windows"
    try:
        # List all files in the folder and filter by extensions
        driver_files = [
            os.path.join(folder_path, file)
            for file in os.listdir(folder_path)
            if file.endswith('.dll')  # Adjust for your OS
        ]

        if app.driver_path in driver_files:
            driver_files.pop(driver_files.index(app.driver_path))
            driver_files.insert(0, app.driver_path)

        return driver_files
    except FileNotFoundError:
        print(f"Error: Folder not found at {folder_path}")
        return []
    except Exception as e:
        print(f"Error reading drivers from folder: {str(e)}")
        return []

def load_token():
    """
    Tries to load a PKCS#11 driver from a list of driver paths and checks for available slots.

    Args:
        driver_paths (list): List of PKCS#11 driver paths to check.

    Returns:
        dict: Contains the status, slots information if successful, and the loaded driver path.
    """
    pkcs11 = PyKCS11.PyKCS11Lib()

    driver_paths = load_drivers_windows()

    for driver_path in driver_paths:
        try:
            # Attempt to load the PKCS#11 driver
            pkcs11.load(driver_path)
            print(f"Attempting to load driver: {driver_path}")

            # Check for available slots with tokens
            slots = pkcs11.getSlotList(tokenPresent=True)
            if slots:
                update_driver_path(driver_path)
                app.driver_path = driver_path
                return app.driver_path

        except Exception as e:
            print(f"Failed to load driver: {driver_path}. Error: {str(e)}")

    return app.driver_path

@app.route('/list-token', methods=['GET'])
def list_tokens():
    pkcs11 = PyKCS11.PyKCS11Lib()
    try:
        pkcs11.load(load_token())
    except Exception as e:
        return jsonify({"error": "Failed to load PKCS#11 library. Please check the library path."}), 500

    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        return jsonify({"error": "No tokens available"}), 404
    
    pkcsSession=None
    try:
        pkcsSession = pkcs11.openSession(slots[0])

        cert_der, public_key, owner_name, key_id = fetch_certificate_publicKey_ownerName(pkcsSession)
        
        reg_id = get_dsc_reg_id(key_id.hex())

        return jsonify({"certficate":cert_der.hex(), "public_key":public_key.hex(), "owner_name":owner_name, "key_id":key_id.hex(), "client_id": app.client_id, "reg_id": reg_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if pkcsSession:
            pkcsSession.closeSession()

@app.route('/list-token', methods=['PATCH'])
def delete_junk_reg():
    try:
        reg_id = request.json.get("reg_id")

        if reg_id:
            clear_junk_registration(reg_id)

        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "success"}), 200

@app.route('/register-token', methods=['POST'])
def register_token():
    client_cert_hex = request.json.get("certificate")
    nonce = request.json.get("nonce")
    client_key_id_hex = request.json.get("key_id")
    
    if not client_cert_hex or not nonce or not client_key_id_hex:
        return jsonify({"error": "Certificate, key and nonce are required"}), 400
    
    try:
        x509.load_der_x509_certificate(bytes.fromhex(client_cert_hex), default_backend())
    except ValueError:
        return jsonify({"error": "Invalid certificate format"}), 400
    
    pkcs11 = PyKCS11.PyKCS11Lib()
    try:
        pkcs11.load(app.driver_path)
    except Exception as e:
        return jsonify({"error": "Failed to load PKCS#11 library. Please check the library path."}), 500
    
    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        return jsonify({"error": "No tokens available"}), 404
    
    pin = prompt_for_pin()
    if not pin:
        return jsonify({"error": "Invalid PIN provided"}), 400
    pkcsSession = None
    logged_in = True
    try:
        pkcsSession = pkcs11.openSession(slots[0])
        try:
            pkcsSession.login(pin)
        except PyKCS11.PyKCS11Error:
            logged_in = False
            return jsonify({"error": "Invalid PIN"}), 403

        cert_der, public_key, owner_name, key_id = fetch_certificate_publicKey_ownerName(pkcsSession)
        
        if client_cert_hex != cert_der.hex():
            return jsonify({"error": "Certificate does not match token"}), 403

        if client_key_id_hex != key_id.hex():
            return jsonify({"error": "Certificate key id does not match token"}), 403
        
        timestamp = get_internet_time()
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat() 
        
        combined_data = (nonce + owner_name + timestamp + key_id.hex() + app.client_id).encode('utf-8')
       
        priv_keys = pkcsSession.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        if not priv_keys:
            raise ValueError("No private key found on the DSC token")
        priv_key = priv_keys[0]
       
        signature = bytes(pkcsSession.sign(priv_key, combined_data, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)))

        reg_id = generate_base64_id([app.client_id, key_id.hex()])

        clear_failed_registration()
        
        store_registration_data(reg_id, key_id.hex(), owner_name, nonce, signature.hex(), timestamp)

        return jsonify({"key_id":key_id.hex(), "signature": signature.hex(), "timestamp": timestamp, "client_mac": get_mac_address(), "client_id": app.client_id, "reg_id": reg_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if pkcsSession:
            if logged_in:
                pkcsSession.logout()
            pkcsSession.closeSession()

@app.route('/register-token', methods=['PATCH'])
def verify_registration():
    try:
        reg_id = request.json.get("reg_id")

        update_registration_status(reg_id)

        return jsonify({"status": "success", "reg_id": reg_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/single-data-sign', methods=['POST'])
def single_data_sign():
    hash_hex = request.json.get("hash")
    if not hash_hex:
        return jsonify({"error": "No hash provided"}), 400

    try:
        hash_bytes = bytes.fromhex(hash_hex)
    except ValueError:
        return jsonify({"error": "Invalid hash format"}), 400

    hash_base64 = base64.b64encode(hash_bytes).decode('utf-8')

    pkcs11 = PyKCS11.PyKCS11Lib()
    try:
        pkcs11.load(app.driver_path)
    except Exception as e:
        return jsonify({"error": "Failed to load PKCS#11 library. Please check the library path."}), 500

    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        return jsonify({"error": "No tokens available"}), 404

    pin = prompt_for_pin()
    if not pin:
        return jsonify({"error": "Invalid PIN provided"}), 400
    
    pkcsSession = None
    logged_in = True
    try:
        pkcsSession = pkcs11.openSession(slots[0])

        try:
            pkcsSession.login(pin)
        except PyKCS11.PyKCS11Error:
            logged_in = False
            return jsonify({"error": "Invalid PIN"}), 403

        priv_keys = pkcsSession.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        if not priv_keys:
            raise ValueError("No private key found on the DSC token")
        priv_key = priv_keys[0]

        timestamp = get_internet_time()
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        data = (hash_base64+timestamp).encode('utf-8')

        signature = bytes(pkcsSession.sign(priv_key, data, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)))
        
        return jsonify({"signature": signature.hex(), "timestamp": timestamp})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if pkcsSession:
            if logged_in:
                pkcsSession.logout()
            pkcsSession.closeSession()

if __name__ == '__main__':
    init_db()
    init_client()
    app.run(debug=True, host='127.0.0.1', port=8080)
