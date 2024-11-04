import secrets
from flask import Flask, request, jsonify
import PyKCS11
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from PyQt5 import QtWidgets
import sys
from multiprocessing import Pipe, Process

app = Flask(__name__)

# Path to PKCS#11 library
PKCS11_LIB_PATH = "token_drivers\\windows\\eps2003csp11v264.dll"

def fetch_dsc_certificate(session):
    """
    Fetch the DSC certificate from the token.
    """
    certs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
    if not certs:
        raise ValueError("No certificate found on the DSC token")
    cert_der = bytes(session.getAttributeValue(certs[0], [PyKCS11.CKA_VALUE], True)[0])
    return cert_der

def prompt_for_pin_in_process(conn):
    """
    Run the PyQt5 PIN prompt in a separate process.
    Communicates the entered PIN back to the main process via a Pipe connection.
    """
    app = QtWidgets.QApplication(sys.argv)
    pin, ok = QtWidgets.QInputDialog.getText(None, "PIN Entry", "Please enter your PIN:", QtWidgets.QLineEdit.Password)
    
    if ok and pin.strip():  # Check if the dialog was accepted and PIN is non-empty
        conn.send(pin.strip())  # Send the trimmed PIN back to the main process
    else:
        conn.send(None)  # Send None if canceled or invalid PIN

    conn.close()  # Close the connection
    app.quit()  # Properly quit the QApplication instance

def prompt_for_pin():
    """
    Starts a separate process to prompt for a PIN using PyQt5.
    Returns the PIN if valid, or None if the PIN is empty, only spaces, or canceled.
    """
    parent_conn, child_conn = Pipe()  # Create a pipe for inter-process communication
    p = Process(target=prompt_for_pin_in_process, args=(child_conn,))
    p.start()
    p.join()  # Wait for the process to finish

    return parent_conn.recv()  # Receive the PIN from the child process

@app.route('/sign', methods=['POST'])
def sign_hash():
    hash_hex = request.json.get("hash")
    if not hash_hex:
        return jsonify({"error": "No hash provided"}), 400

    try:
        hash_bytes = bytes.fromhex(hash_hex)
    except ValueError:
        return jsonify({"error": "Invalid hash format"}), 400

    # Prompt for PIN
    pin = prompt_for_pin()
    if not pin:
        return jsonify({"error": "Invalid PIN provided"}), 400

    # Initialize PKCS#11 and sign the hash
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(PKCS11_LIB_PATH)
    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        return jsonify({"error": "No tokens available"}), 404

    session = None
    try:
        session = pkcs11.openSession(slots[0])

        # Attempt to log in with the provided PIN
        try:
            session.login(pin)
        except PyKCS11.PyKCS11Error:
            return jsonify({"error": "Invalid PIN"}), 403

        # Fetch the certificate (useful for verification if needed)
        certificate_der = fetch_dsc_certificate(session)

        # Locate the private key object on the token
        priv_keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        if not priv_keys:
            raise ValueError("No private key found on the DSC token")
        priv_key = priv_keys[0]

        # Sign the provided hash using the private key on the token
        signature = bytes(session.sign(priv_key, hash_bytes, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)))

        return jsonify({"signature": signature.hex(), "certificate": certificate_der.hex()})

    except PyKCS11.PyKCS11Error as e:
        return jsonify({"error": f"PKCS#11 error: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if session:
            session.logout()
            session.closeSession()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8080)
