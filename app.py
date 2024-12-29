from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography import x509
import PyKCS11
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sys
from PyQt5 import QtWidgets
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
 
# Configure logging to write to a file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs\\app-{datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime('%Y-%m-%d')}.log"),
        logging.StreamHandler()
    ]
)

CRL_REFRESH_INTERVAL = 3600  # 1 hour

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app)

def get_mac_address():
    # Fetch the MAC address of the system
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
    return mac

def get_client_id():
    """
    Generate a unique client ID based on system information.

    Returns:
        tuple: A tuple containing the client ID, username, CPU info, disk info, and MAC address.

    Raises:
        Exception: If there is an error generating the client ID.
    """
    logging.info("Generating client id...")
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
        logging.error(f"Error generating client ID: {str(e)}")
        raise  

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

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crl_cache (
                cdp_id TEXT PRIMARY KEY,
                crl_url TEXT NOT NULL,
                crl_data BLOB NOT NULL,
                last_updated TEXT NOT NULL,
                next_update TEXT NOT NULL
            )
        ''')

        # Commit the transaction
        connection.commit()
    except sqlite3.Error as e:
        # Roll back the transaction in case of an error
        if connection:
            connection.rollback()
        logging.error(f"Database error occurred: {e}")
        raise
    except Exception as e:
        # Catch any other exceptions
        if connection:
            connection.rollback()
        logging.error(f"An error occurred: {e}")
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
                logging.error("Error fetching client id")
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
        logging.error(f"Database error occurred: {e}")
        raise
    except Exception as e:
        if connection:
            connection.rollback()
        logging.error(f"An error occurred: {e}")
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
        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        # Begin a transaction
        conn.execute("BEGIN")

        # Insert the verified registration data
        cursor.execute('''
            INSERT INTO registered_tokens (reg_id, key_id, owner_name, nonce, signature, timestamp, is_verified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (unique_id, key_id, owner_name, nonce, signature, timestamp, "N"))

        conn.commit()  # Commit the transaction
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logging.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def check_reg_status(reg_id, key_id):
    status = False

    try:
        conn = sqlite3.connect('signerData.db')  
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM registered_tokens WHERE reg_id = ? AND key_id = ?", (reg_id, key_id,))
        result = cursor.fetchone()

        if result:
            status = True 
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

    return status  

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
            logging.error(f"No record found with reg_id = {reg_id}.")
            raise

    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logging.error(f"Database error: {e}")
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
        logging.error(f"Database error: {e}")
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
        logging.error(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def get_dsc_reg_id(key_id):
    reg_id = None

    try:
        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        cursor.execute("SELECT reg_id FROM registered_tokens WHERE key_id = ? AND is_verified = 'Y'", (key_id,))
        result = cursor.fetchone()
         
        if result:
            reg_id = str(result[0])
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
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
            logging.error(f"Error updating driver path {recent_driver}.")
            raise

    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logging.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def fetch_crl_from_cache(crl_url):
    try:
        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        cdp_id = generate_base64_id([crl_url])
        current_time = datetime.now(timezone.utc).isoformat()
        
        cursor.execute("SELECT crl_data FROM crl_cache WHERE cdp_id = ? AND next_update >= ?", (cdp_id, current_time,))
        result = cursor.fetchone()

        if result:
            return x509.load_der_x509_crl(result[0], default_backend())
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return None
    finally:
        if conn:
            conn.close()

def store_update_crl_to_cache(crl_url, crl_data):
    try:
        conn = sqlite3.connect('signerData.db')  # Connect to SQLite database
        cursor = conn.cursor()

        cdp_id = generate_base64_id([crl_url])
        last_updated = datetime.now(timezone.utc).isoformat()
        next_update = (datetime.now(timezone.utc) + timedelta(seconds=CRL_REFRESH_INTERVAL)).isoformat()
        crl_data_serialized = crl_data.public_bytes(serialization.Encoding.DER)    

        conn.execute("BEGIN")

        cursor.execute("""
            INSERT OR REPLACE INTO crl_cache (cdp_id, crl_url, crl_data, last_updated, next_update)
            VALUES (?, ?, ?, ?, ?)
        """, (cdp_id, crl_url, crl_data_serialized, last_updated, next_update,))

        cursor.execute("DELETE FROM crl_cache WHERE last_updated < ?", ((datetime.now(timezone.utc) - timedelta(days=45)).isoformat(),))

        conn.commit()  # Commit the transaction
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logging.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def fetch_crl_for_certificate(certificate):
    """
    Fetch and load the CRL from the certificate's CRL Distribution Point (CDP).
    """
    try:
        # Get the CRL Distribution Point (CDP) from the certificate
        crl_dps = certificate.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value

        logging.info(f"Found CRL Distribution Points: {crl_dps}")

        crl_url = crl_dps[0].full_name[0].value  # Assuming the first CRL point is the target

        logging.info("Fetching CRL from cache...")

        crl = fetch_crl_from_cache(crl_url)

        if crl:
            logging.info(f"CRL found in cache for: {crl.issuer}")
        else:
            logging.info("CRL not found in cache.")

            logging.info(f"Fetching CRL from: {crl_url}")

            # Fetch the CRL from the URL
            response = requests.get(crl_url)
            response.raise_for_status()

            # Load the CRL
            crl = x509.load_der_x509_crl(response.content, default_backend())

            logging.info(f"CRL fetched successfully: {crl.issuer}")

            logging.info("Caching CRL...")
            store_update_crl_to_cache(crl_url, crl)

        return crl
    except Exception as e:
        logging.error(f"Error fetching CRL: {e}")
        return None

def is_certificate_revoked(certificate):
    """
    Check if the given certificate is revoked using the provided CRL.

    Args:
        certificate (x509.Certificate): The certificate to check.
        crl (x509.CertificateRevocationList): The CRL to use for checking.

    Returns:
        bool: True if the certificate is revoked, False otherwise.
    """
    try:
        # Get the certificate serial number
        serial_number = certificate.serial_number

        logging.info(f"Checking certificate revocation for: {certificate.subject}")

        crl = fetch_crl_for_certificate(certificate)

        if not crl:
            logging.error("No CRL found for certificate.")
            return True

        # Check the CRL for the serial number
        for revoked_cert in crl: 
            if revoked_cert.serial_number == serial_number:
                logging.warning(f"Certificate {serial_number} is revoked.")
                return True

        return False
    except Exception as e:
        logging.error(f"Error checking certificate revocation: {e}")
        return True  # Assume revoked if an error occurs
    
def is_certificate_expired(certificate):
    """
    Check if the certificate is expired.

    Args:
        certificate (x509.Certificate): The certificate to check.

    Returns:
        bool: True if the certificate is expired, False otherwise.
    """
    current_time = datetime.now(timezone.utc)

    if certificate.not_valid_before_utc > current_time:
        logging.warning("Certificate is not yet valid.")
        return True

    if certificate.not_valid_after_utc < current_time:
        logging.warning("Certificate has expired.")
        return True

    return False

def is_certificate_valid(certificate):
    """
    Check if the certificate is valid.

    Args:
        certificate (x509.Certificate): The certificate to check.

    Returns:
        bool: True if the certificate is valid, False otherwise.
    """
    if is_certificate_expired(certificate):
        return False

    if is_certificate_revoked(certificate):
        return False

    return True

def fetch_certificate_publicKey_ownerName(pkcsSession):
    certs = pkcsSession.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
    if not certs:
        raise ValueError("No certificate found on the DSC token")
    
    cert_der = bytes(pkcsSession.getAttributeValue(certs[0], [PyKCS11.CKA_VALUE], True)[0])
    
    certificate = x509.load_der_x509_certificate(cert_der, default_backend())

    if not is_certificate_valid(certificate):
        message_prompt("Certificate is not valid")
        raise ValueError("Certificate is not valid")
    
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
    
def get_internet_time():
    try:
        response = requests.get("https://timeapi.io/api/Time/current/zone?timeZone=UTC")
        response.raise_for_status()  
        data = response.json()
        return str(data["dateTime"])  
    except Exception as e:
        logging.error(f"Error fetching internet time: {e}")
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
        logging.error(f"Error: Folder not found at {folder_path}")
        return []
    except Exception as e:
        logging.error(f"Error reading drivers from folder: {str(e)}")
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
            logging.info(f"Attempting to load driver: {driver_path}")

            # Check for available slots with tokens
            slots = pkcs11.getSlotList(tokenPresent=True)
            if slots:
                update_driver_path(driver_path)
                app.driver_path = driver_path
                return app.driver_path

        except Exception as e:
            logging.error(f"Failed to load driver: {driver_path}. Error: {str(e)}")

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
        message_prompt("Invalid PIN")
        return jsonify({"error": "Invalid PIN"}), 400
    pkcsSession = None
    logged_in = True
    try:
        pkcsSession = pkcs11.openSession(slots[0])
        
        cert_der, public_key, owner_name, key_id = fetch_certificate_publicKey_ownerName(pkcsSession)

        try:
            pkcsSession.login(pin)
        except PyKCS11.PyKCS11Error:
            logged_in = False
            message_prompt("Invalid PIN")
            return jsonify({"error": "Invalid PIN"}), 403
        
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


@app.route('/data-sign', methods=['POST'])
def data_sign():
    reg_id = request.json.get("reg_id")
    key_id_hex = request.json.get("key_id")
    digests = request.json.get("digests")
    
    # Validate that we have the required data
    if not all([reg_id, key_id_hex, digests]):
        return jsonify({"error": "Missing required fields."}), 400

    # Check that digests is a list
    if not isinstance(digests, list):
        return jsonify({"error": "Digests must be a list"}), 400
    
    is_registered = check_reg_status(reg_id, key_id_hex)
    if not is_registered:
        return jsonify({"error": "DSC Token not Registered"}), 400

    valid_digests = []
    for d in digests:
        digest_id = d.get("digest_id", "").strip() if d.get("digest_id") else None
        digest_value = d.get("digest_value", "").strip() if d.get("digest_value") else None

        if digest_id and digest_value:
            try:
                bytes.fromhex(digest_value)
                valid_digests.append({
                    "digest_id": digest_id,
                    "digest_value": digest_value
                })
            except ValueError as e:
                pass

    # If after filtering, no valid digests remain, handle accordingly
    if len(valid_digests) == 0:
        return jsonify({"error": "No valid digests found after filtering"}), 400

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
        message_prompt("Invalid PIN")
        return jsonify({"error": "Invalid PIN"}), 400
    
    pkcsSession = None
    logged_in = True
    try:
        pkcsSession = pkcs11.openSession(slots[0])

        cert_der, public_key, owner_name, key_id = fetch_certificate_publicKey_ownerName(pkcsSession)

        try:
            pkcsSession.login(pin)
        except PyKCS11.PyKCS11Error:
            logged_in = False
            message_prompt("Invalid PIN")
            return jsonify({"error": "Invalid PIN"}), 403

        if key_id_hex != key_id.hex():
            return jsonify({"error": "Certificate key id does not match token"}), 403

        priv_keys = pkcsSession.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        if not priv_keys:
            raise ValueError("No private key found on the DSC token")
        priv_key = priv_keys[0]

        signed_digests = []
        for vd in valid_digests:
            digest_id = vd.get("digest_id")
            digest_value = vd.get("digest_value")

            timestamp = get_internet_time()
            if not timestamp:
                timestamp = datetime.now(timezone.utc).isoformat()

            data = (digest_value+timestamp).encode('utf-8')

            try:
                signature = bytes(pkcsSession.sign(priv_key, data, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)))
                signed_digests.append({"sign_id": digest_id, "sign_value": signature.hex(), "timestamp": timestamp})
            except Exception:
                pass
        
        if len(signed_digests) == 0:
            return jsonify({"error": "Error signing digests"}), 400

        return jsonify({"signed_digests": signed_digests, "key_id": key_id.hex(), "reg_id": reg_id})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if pkcsSession:
            if logged_in:
                pkcsSession.logout()
            pkcsSession.closeSession()
 
def on_exit(icon, item):
    """Stop the system tray and Flask server."""
    print("Exiting application...")
    icon.stop()
    stop_flask()

def stop_flask():
    """Stop the Flask server by sending a termination signal."""
    print("Stopping Flask server...")
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
    """Start the system tray icon."""
    menu = Menu(MenuItem("Exit", on_exit))
    icon = Icon("Ultra Signer", create_image(), menu=menu)
    icon.run()

def start_flask():
    init_db()
    init_client()
    app.run(host='127.0.0.1', port=8080, use_reloader=False)

if __name__ == '__main__':
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    # Start the system tray
    start_tray()