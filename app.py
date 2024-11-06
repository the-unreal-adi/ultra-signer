import secrets
from flask import Flask, request, jsonify
import PyKCS11
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from PyQt5 import QtWidgets
import sys
from multiprocessing import Pipe, Process

app = Flask(__name__)
 
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

    return cert_der, public_key_der, owner_name

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

@app.route('/list-tokens', methods=['GET'])
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

        cert_der, public_key, owner_name=fetch_certificate_publicKey_ownerName(session)

        return jsonify({"certficate":cert_der.hex(), "public_key":public_key.hex(), "owner_name":owner_name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if session:
            session.closeSession()

@app.route('/sign', methods=['POST'])
def sign_hash():
    hash_hex = request.json.get("hash")
    if not hash_hex:
        return jsonify({"error": "No hash provided"}), 400

    try:
        hash_bytes = bytes.fromhex(hash_hex)
    except ValueError:
        return jsonify({"error": "Invalid hash format"}), 400

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

        signature = bytes(session.sign(priv_key, hash_bytes, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)))

        return jsonify({"signature": signature.hex()})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if session:
            if logged_in:
                session.logout()
            session.closeSession()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8080)
