from flask import Flask, request, jsonify
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
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
 
PKCS11_LIB_PATH = "token_drivers\\windows\\eps2003csp11v264.dll"

def fetch_certificate_publicKey_ownerName(session):
    certs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
    if not certs:
        raise ValueError("No certificate found on the DSC token")
    
    cert_der = bytes(session.getAttributeValue(certs[0], [PyKCS11.CKA_VALUE], True)[0])
    
    certificate = x509.load_der_x509_certificate(cert_der, default_backend())
    
    public_key = certificate.public_key()
    public_key_der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo) 

    owner_name = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

    pub_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)])[0]

    key_id = bytes(session.getAttributeValue(pub_key, [PyKCS11.CKA_ID], True)[0])

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

@app.route('/list-token', methods=['GET'])
def list_tokens():
    pkcs11 = PyKCS11.PyKCS11Lib()
    try:
        pkcs11.load(PKCS11_LIB_PATH)
    except Exception as e:
        return jsonify({"error": "Failed to load PKCS#11 library. Please check the library path."}), 500

    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        return jsonify({"error": "No tokens available"}), 404
    
    session=None
    try:
        session = pkcs11.openSession(slots[0])

        cert_der, public_key, owner_name, key_id = fetch_certificate_publicKey_ownerName(session)
        
        return jsonify({"certficate":cert_der.hex(), "public_key":public_key.hex(), "owner_name":owner_name, "key_id":key_id.hex()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if session:
            session.closeSession()

@app.route('/register-token', methods=['POST'])
def register_token():
    client_cert_hex = request.json.get("certificate")
    nonce = request.json.get("nonce")
    client_key_id_hex = request.json.get("key_id")
    
    if not client_cert_hex or not nonce:
        return jsonify({"error": "Certificate, key and nonce are required"}), 400
    
    try:
        x509.load_der_x509_certificate(bytes.fromhex(client_cert_hex), default_backend())
    except ValueError:
        return jsonify({"error": "Invalid certificate format"}), 400
    
    pkcs11 = PyKCS11.PyKCS11Lib()
    try:
        pkcs11.load(PKCS11_LIB_PATH)
    except Exception as e:
        return jsonify({"error": "Failed to load PKCS#11 library. Please check the library path."}), 500
    
    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        return jsonify({"error": "No tokens available"}), 404
    
    pin = prompt_for_pin()
    if not pin:
        return jsonify({"error": "Invalid PIN provided"}), 400
    session = None
    logged_in = True
    try:
        session = pkcs11.openSession(slots[0])
        try:
            session.login(pin)
        except PyKCS11.PyKCS11Error:
            logged_in = False
            return jsonify({"error": "Invalid PIN"}), 403

        cert_der, public_key, owner_name, key_id = fetch_certificate_publicKey_ownerName(session)
        
        if client_cert_hex != cert_der.hex():
            return jsonify({"error": "Certificate does not match token"}), 403

        if client_key_id_hex != key_id.hex():
            return jsonify({"error": "Certificate key id does not match token"}), 403
        
        timestamp = get_internet_time()
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat() 
        
        combined_data = (nonce + owner_name + timestamp).encode('utf-8')
       
        priv_keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        if not priv_keys:
            raise ValueError("No private key found on the DSC token")
        priv_key = priv_keys[0]
       
        signature = bytes(session.sign(priv_key, combined_data, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)))
        
        return jsonify({"key_id":key_id.hex(), "signature": signature.hex(), "timestamp": timestamp})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if session:
            if logged_in:
                session.logout()
            session.closeSession()

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
        pkcs11.load(PKCS11_LIB_PATH)
    except Exception as e:
        return jsonify({"error": "Failed to load PKCS#11 library. Please check the library path."}), 500

    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        return jsonify({"error": "No tokens available"}), 404

    pin = prompt_for_pin()
    if not pin:
        return jsonify({"error": "Invalid PIN provided"}), 400
    
    session = None
    logged_in = True
    try:
        session = pkcs11.openSession(slots[0])

        try:
            session.login(pin)
        except PyKCS11.PyKCS11Error:
            logged_in = False
            return jsonify({"error": "Invalid PIN"}), 403

        priv_keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        if not priv_keys:
            raise ValueError("No private key found on the DSC token")
        priv_key = priv_keys[0]

        timestamp = get_internet_time()
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        data = (hash_base64+timestamp).encode('utf-8')

        print(hash_base64+timestamp)

        signature = bytes(session.sign(priv_key, data, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)))
        
        return jsonify({"signature": signature.hex(), "timestamp": timestamp})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if session:
            if logged_in:
                session.logout()
            session.closeSession()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8080)
