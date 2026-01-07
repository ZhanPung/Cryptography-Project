import socket
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# TLV type constants
TYPE_IDC   = 1
TYPE_EW_AG = 2
TYPE_EW_BG = 3
TYPE_AUTH  = 4
TYPE_REQ   = 5
TYPE_GEM   = 6

# Helper functions for TLV
def pack_tlv(t, data: bytes) -> bytes:
    if len(data) > 255:
        raise ValueError("Data too long for TLV encoding")
    return bytes([t, len(data)]) + data

def read_tlv(conn) -> (int, bytes):
    t_byte = conn.recv(1)
    if not t_byte:
        return None, None
    t = t_byte[0]
    l_byte = conn.recv(1)
    if not l_byte:
        return None, None
    l = l_byte[0]
    data = conn.recv(l)
    if len(data) < l:
        return None, None
    return t, data

# AES-CTR encrypt/decrypt helper (same function used for both)
def aes_ctr_encdec(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), default_backend())
    cryptor = cipher.encryptor()
    return cryptor.update(data) + cryptor.finalize()

def main():
    HOST = "127.0.0.1"   # listen on all interfaces
    PORT = 9999
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on port {PORT}")

    # For testing, we assume the client's long-term public key (or at least its x-coordinate)
    # is known. In practice, you would obtain this from a database keyed by client ID.
    # For example, suppose you have a known private key (as hex) for your client:
    CLIENT_PRIVKEY_HEX = "1c43912e2471e4cb11ff8d4cee2523f153714a8c241e61fdcfa2224b82fbad5d"  # Replace with actual value
    client_priv = ec.derive_private_key(int(CLIENT_PRIVKEY_HEX, 16), ec.SECP256R1(), default_backend())
    client_pub = client_priv.public_key().public_numbers()
    # Derive the symmetric key w (first 16 bytes from the x-coordinate)
    client_x = client_pub.x.to_bytes(32, 'big')
    w = client_x[:16]

    while True:
        conn, addr = server_socket.accept()
        print("Accepted connection from", addr)
        try:
            # 1. Receive the client ID (TLV type 1)
            t, client_id = read_tlv(conn)
            if t != TYPE_IDC:
                print("Invalid TLV type for client ID")
                conn.close()
                continue
            print("Received client ID:", client_id.decode())

            # 2. Receive client's encrypted ephemeral public key (TLV type 2)
            t, enc_a = read_tlv(conn)
            if t != TYPE_EW_AG:
                print("Expected TYPE_EW_AG")
                conn.close()
                continue

            # Decrypt the client’s ephemeral public key using key w
            iv_a = enc_a[:16]
            ciph_a = enc_a[16:]
            a_bytes = aes_ctr_encdec(w, iv_a, ciph_a)

            # Convert the 64-byte point to an EC public key
            ax = int.from_bytes(a_bytes[:32], 'big')
            ay = int.from_bytes(a_bytes[32:], 'big')
            a_pub = ec.EllipticCurvePublicNumbers(ax, ay, ec.SECP256R1()).public_key(default_backend())
            print("Obtained client's ephemeral public key.")

            # 3. Generate server ephemeral key
            b_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            b_pub = b_priv.public_key().public_numbers()
            b_bytes = b_pub.x.to_bytes(32, 'big') + b_pub.y.to_bytes(32, 'big')

            # Encrypt server's ephemeral public key with w and send (TLV type 3)
            iv_b = os.urandom(16)
            enc_b = aes_ctr_encdec(w, iv_b, b_bytes)
            server_msg = iv_b + enc_b
            conn.sendall(pack_tlv(TYPE_EW_BG, server_msg))
            print("Sent server ephemeral public key.")

            # 4. Derive session key K using ECDH (server's b_priv and client's ephemeral a_pub)
            shared_secret = b_priv.exchange(ec.ECDH(), a_pub)
            K = shared_secret[:16]
# 5. Receive client's auth (TLV type 4)
            t, auth_enc = read_tlv(conn)
            if t != TYPE_AUTH:
                print("Expected TYPE_AUTH")
                conn.close()
                continue
            iv_auth = auth_enc[:16]
            sig = aes_ctr_encdec(K, iv_auth, auth_enc[16:])
            # (Normally, verify the signature using the client's known public key.)
            print("Received client's auth signature.")

            # 6. Receive client's request (TLV type 5)
            t, req_enc = read_tlv(conn)
            if t != TYPE_REQ:
                print("Expected TYPE_REQ")
                conn.close()
                continue
            iv_req = req_enc[:16]
            request = aes_ctr_encdec(K, iv_req, req_enc[16:])
            print("Received request:", request)

            # 7. Respond with a gem (TLV type 6)
            gem = b"639363031663434646362663763386666663236653361336332663639366131363331"  # Replace with actual gem data as needed.
            iv_gem = os.urandom(16)
            enc_gem = aes_ctr_encdec(K, iv_gem, gem)
            conn.sendall(pack_tlv(TYPE_GEM, iv_gem + enc_gem))
            print("Sent gem.")

        except Exception as e:
            print("Server error:", e)
        finally:
            conn.close()

if __name__ == "__main__":
    main()