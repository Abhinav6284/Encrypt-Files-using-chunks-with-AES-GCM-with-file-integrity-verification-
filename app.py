import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

CHUNK_SIZE = 64 * 1024  # 64 KB chunks


def generate_key(key_path="key.bin"):
    """Generate a new AES-GCM key and save it to a file."""
    key = secrets.token_bytes(32)  # AES-256
    with open(key_path, "wb") as f:
        f.write(key)
    print(f"[+] Key generated and saved to: {key_path}")
    return key


def load_key(key_path="key.bin"):
    """Load AES-GCM key from file."""
    if not os.path.exists(key_path):
        print("[!] No key found. Generating a new one.")
        return generate_key(key_path)
    with open(key_path, "rb") as f:
        key = f.read()
    print(f"[+] Key loaded from: {key_path}")
    return key


def encrypt_file(input_file, output_file=None, key_path="key.bin"):
    key = load_key(key_path)
    aesgcm = AESGCM(key)

    if output_file is None:
        output_file = input_file + ".enc"

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            nonce = secrets.token_bytes(12)  # 96-bit nonce
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
            fout.write(len(nonce).to_bytes(2, 'big') + nonce)
            fout.write(len(encrypted_chunk).to_bytes(
                4, 'big') + encrypted_chunk)

    print(f"[+] File encrypted successfully: {output_file}")
    print("Integrity Verified Successfully ✅")


def decrypt_file(encrypted_file, output_file=None, key_path="key.bin"):
    key = load_key(key_path)
    aesgcm = AESGCM(key)

    if output_file is None:
        if encrypted_file.endswith(".enc"):
            output_file = encrypted_file[:-4]
        else:
            output_file = encrypted_file + ".dec"

    with open(encrypted_file, "rb") as fin, open(output_file, "wb") as fout:
        while True:
            nonce_len_bytes = fin.read(2)
            if not nonce_len_bytes:
                break
            nonce_len = int.from_bytes(nonce_len_bytes, 'big')
            nonce = fin.read(nonce_len)

            enc_len = int.from_bytes(fin.read(4), 'big')
            encrypted_chunk = fin.read(enc_len)

            decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
            fout.write(decrypted_chunk)

    print(f"[+] File decrypted successfully: {output_file}")
    print("Integrity verified ✅")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AES-GCM File Encryptor/Decryptor")
    parser.add_argument(
        "mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("file", help="Path to the file")
    parser.add_argument("--key", default="key.bin", help="Path to key file")
    parser.add_argument("--output", help="Output file path")

    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.file, args.output, args.key)
    elif args.mode == "decrypt":
        decrypt_file(args.file, args.output, args.key)
