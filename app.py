import secrets
from flask import Flask, request, jsonify
from flask_cors import CORS
import PyKCS11
from cryptography.hazmat.primitives.hashes import Hash, SHA256

app = Flask(__name__)
# CORS(app, resources={r"/sign": {"origins": "http://localhost:3000"}})  # Replace with your web app's URL
API_TOKEN = secrets.token_hex(32)  # Secure token for authentication

# Print the token for use in the web app (for testing purposes)
print(f"API Token: {API_TOKEN}")

# Path to PKCS#11 library (replace this with the actual path to your token's library)
PKCS11_LIB_PATH = "token_drivers\\windows\\eps2003csp11v2.dll"  # Change to .dll on Windows, .so on Linux/macOS

def fetch_dsc_certificate(session):
    """
    Fetch the DSC certificate from the token.
    """
    # Find the certificate object in the token
    certs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
    if not certs:
        raise ValueError("No certificate found on the DSC token")

    # Retrieve certificate in DER format
    cert_der = bytes(session.getAttributeValue(certs[0], [PyKCS11.CKA_VALUE], True)[0])
    return cert_der

@app.route('/sign', methods=['POST'])
def sign_hash():
    # Verify the token
    #if request.headers.get("Authorization") != f"Bearer {API_TOKEN}":
     #   return jsonify({"error": "Unauthorized"}), 401

    # Retrieve the hash from the request
    hash_hex = request.json.get("hash")
    if not hash_hex:
        return jsonify({"error": "No hash provided"}), 400

    # Confirm user consent before signing
    #confirm = input("Do you want to sign the provided hash? (yes/no): ")
    #if confirm.lower() != "yes":
    #    return jsonify({"error": "User declined to sign hash"}), 403

    # Convert the hash from hex to bytes
    try:
        hash_bytes = bytes.fromhex(hash_hex)
    except ValueError:
        return jsonify({"error": "Invalid hash format"}), 400

    # Initialize PKCS#11 and sign the hash
    try:
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(PKCS11_LIB_PATH)
        slots = pkcs11.getSlotList(tokenPresent=True)
        print(pkcs11.getTokenInfo(slots[0])) 
        session = pkcs11.openSession(slots[0])

        # The DSC token may prompt for the PIN automatically at this stage
        # Fetch the certificate (useful for verification if needed)
        certificate_der = fetch_dsc_certificate(session)
        print("Certificate fetched from DSC token:", certificate_der.hex())

        # Locate the private key object on the token
        session.login("0")
        priv_keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])[0]
        if not priv_keys:
            raise ValueError("No private key found on the DSC token")
        priv_key = priv_keys

        # Sign the provided hash using the private key on the token
        signature = bytes(session.sign(priv_key, hash_bytes, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS)))

        session.logout()
  
        session.closeSession()  # Close the session once signing is done
        return jsonify({"signature": signature.hex(), "certificate": certificate_der.hex()})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=8080)
