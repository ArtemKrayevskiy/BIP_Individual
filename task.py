import os
import sys
import time
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from PIL import Image
import argparse
import io
import numpy as np

class RSAKeyGenerator:
    """
    Class to generate and manage RSA key pairs.
    """
    
    def __init__(self, key_size=4096):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self):
        """
        Generate a new RSA key pair with the specified key size.
        """
        print(f"Generating {self.key_size}-bit RSA key pair, please wait...")
        start_time = time.time()
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        
        elapsed_time = time.time() - start_time
        print(f"Key generation completed in {elapsed_time:.2f} seconds.")
        
        return self.private_key, self.public_key
    
    def save_keys(self, private_key_path, public_key_path, password=None):
        """
        Save the keys to disk.
        """
        if not self.private_key or not self.public_key:
            raise ValueError("Keys have not been generated yet. Call generate_keys() first.")
        
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        print(f"Private key saved to: {private_key_path}")
        print(f"Public key saved to: {public_key_path}")
    
    @staticmethod
    def load_private_key(key_path, password=None):
        """
        Load a private key from a file.
        """
        with open(key_path, 'rb') as key_file:
            if password:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=password.encode()
                )
            else:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
    
    @staticmethod
    def load_public_key(key_path):
        """
        Load a public key from a file.
        """
        with open(key_path, 'rb') as key_file:
            return serialization.load_pem_public_key(key_file.read())


class ImageSigner:
    """
    Class to sign images with RSA digital signatures using advanced steganography.
    """
    
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key
        self.embedding_channels = ['R', 'G', 'B']
        self.bits_per_pixel = 1
        self.signature_end_marker = '11111111'

    def compute_image_hash(self, image_path):
        """
        Compute SHA-256 hash of image data, excluding the LSBs.
        """
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        width, height = img.size
        pixels = img.load()
        img_copy = Image.new('RGB', (width, height))
        pixels_copy = img_copy.load()
        
        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                r = r & 0xFE  
                g = g & 0xFE 
                b = b & 0xFE  
                pixels_copy[x, y] = (r, g, b)
        
        img_bytes = io.BytesIO()
        img_copy.save(img_bytes, format='PNG')
        return hashlib.sha256(img_bytes.getvalue()).digest()
    
    def _prepare_image_for_verification(self, img_path):
        """
        Creates a copy of the image with all LSBs zeroed for verification.
        """
        img = Image.open(img_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        temp_path = f"temp_verify_{secrets.token_hex(8)}.png"
        
        width, height = img.size
        pixels = img.load()
        img_copy = Image.new('RGB', (width, height))
        pixels_copy = img_copy.load()
        
        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]
                r = r & 0xFE
                g = g & 0xFE
                b = b & 0xFE
                pixels_copy[x, y] = (r, g, b)
        
        img_copy.save(temp_path)
        return temp_path

    def _generate_embedding_map(self, img, pixels_needed):
        """
        Generates deterministic pseudorandom coordinates for embedding.
        """
        width, height = img.size
        
        if pixels_needed > width * height:
            pixels_needed = width * height
            print("Warning: Requested more pixels than available in image")
        
        seed = 42
        
        rng = np.random.RandomState(seed)
        
        all_coords = [(x, y) for y in range(height) for x in range(width)]
        selected_indices = rng.choice(len(all_coords), pixels_needed, replace=False)
        coords = [all_coords[i] for i in selected_indices]
        
        return coords

    def _encrypt_signature(self, signature):
        """
        Encrypts signature using AES-256 in CFB mode.
        """
        iv = os.urandom(16)
        key = os.urandom(32)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(signature) + encryptor.finalize()
        
        return iv + key + ciphertext

    def _decrypt_signature(self, encrypted_data):
        """
        Decrypts signature using AES-256.
        """
        if len(encrypted_data) < 48:
            raise ValueError("Encrypted data too short")
            
        iv = encrypted_data[:16]
        key = encrypted_data[16:48]
        ciphertext = encrypted_data[48:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


    def _bytes_to_bits(self, data):
        """
        Converts bytes to bit string.
        """
        return ''.join(format(byte, '08b') for byte in data)

    def _bits_to_bytes(self, bits):
        """
        Converts bit string back to bytes.
        """
        if len(bits) % 8 != 0:
            bits = bits + '0' * (8 - len(bits) % 8)
        
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

    def _embed_in_pixels(self, img, encrypted_sig):
        """
        Embeds encrypted signature in image pixels using length prefix.
        """
        pixels = img.load()
        width, height = img.size
        
        length_bytes = len(encrypted_sig).to_bytes(4, byteorder='big')
        data_to_embed = length_bytes + encrypted_sig
        
        bits_to_embed = self._bytes_to_bits(data_to_embed)
        bits_len = len(bits_to_embed)
        
        channels_per_pixel = len(self.embedding_channels)
        pixels_needed = (bits_len + channels_per_pixel - 1) // channels_per_pixel
        
        if pixels_needed > width * height:
            raise ValueError(f"Image too small to embed data. Need {pixels_needed} pixels.")
        
        embedding_map = self._generate_embedding_map(img, pixels_needed)
        
        print(f"Embedding {bits_len} bits ({len(data_to_embed)} bytes) using {len(embedding_map)} pixel coordinates")
        
        bit_pos = 0
        for x, y in embedding_map:
            if bit_pos >= bits_len:
                break
                
            r, g, b = pixels[x, y]
            
            if 'R' in self.embedding_channels and bit_pos < bits_len:
                r = (r & 0xFE) | int(bits_to_embed[bit_pos])
                bit_pos += 1
                
            if 'G' in self.embedding_channels and bit_pos < bits_len:
                g = (g & 0xFE) | int(bits_to_embed[bit_pos])
                bit_pos += 1
                
            if 'B' in self.embedding_channels and bit_pos < bits_len:
                b = (b & 0xFE) | int(bits_to_embed[bit_pos])
                bit_pos += 1
                
            pixels[x, y] = (r, g, b)
        
        if bit_pos < bits_len:
            print(f"Warning: Could not embed all bits. Embedded {bit_pos}/{bits_len}")
        else:
            print(f"Successfully embedded all {bits_len} bits")

    def _extract_from_pixels(self, img):
        """
        Extracts embedded data from image pixels using length prefix.
        """
        pixels = img.load()
        width, height = img.size
        
        embedding_map = self._generate_embedding_map(img, width * height)
        extracted_bits = []
        
        for i, (x, y) in enumerate(embedding_map):
            r, g, b = pixels[x, y]
            
            if 'R' in self.embedding_channels and len(extracted_bits) < 32:
                extracted_bits.append(str(r & 1))
            if 'G' in self.embedding_channels and len(extracted_bits) < 32:
                extracted_bits.append(str(g & 1))
            if 'B' in self.embedding_channels and len(extracted_bits) < 32:
                extracted_bits.append(str(b & 1))
                
            if len(extracted_bits) >= 32:
                break
        
        if len(extracted_bits) < 32:
            print("Could not extract length prefix")
            return None
        
        length_bits = ''.join(extracted_bits[:32])
        length_bytes = self._bits_to_bytes(length_bits)
        data_length = int.from_bytes(length_bytes, byteorder='big')
        
        print(f"Extracted length prefix: {data_length} bytes")
        
        total_bytes = 4 + data_length
        total_bits = total_bytes * 8
        
        extracted_bits = []
        for x, y in embedding_map:
            r, g, b = pixels[x, y]
            
            if 'R' in self.embedding_channels and len(extracted_bits) < total_bits:
                extracted_bits.append(str(r & 1))
            if 'G' in self.embedding_channels and len(extracted_bits) < total_bits:
                extracted_bits.append(str(g & 1))
            if 'B' in self.embedding_channels and len(extracted_bits) < total_bits:
                extracted_bits.append(str(b & 1))
                
            if len(extracted_bits) >= total_bits:
                break
        
        if len(extracted_bits) < total_bits:
            print(f"Warning: Could not extract all bits. Extracted {len(extracted_bits)}/{total_bits}")
        
        try:
            bit_string = ''.join(extracted_bits)
            byte_data = self._bits_to_bytes(bit_string)
            
            return byte_data[4:]
        except Exception as e:
            print(f"Error converting extracted bits to bytes: {e}")
            return None

    def sign_image(self, image_path, signed_image_path=None):
        """
        Signs an image with improved embedding.
        """
        if not self.private_key:
            raise ValueError("Private key is required for signing.")
        
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        image_hash = self.compute_image_hash(image_path)
        print(f"Image hash computed: {len(image_hash)} bytes")
        
        signature = self.private_key.sign(
            image_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"Generated signature: {len(signature)} bytes")
        
        encrypted_sig = self._encrypt_signature(signature)
        print(f"Encrypted signature: {len(encrypted_sig)} bytes")
        
        if not signed_image_path:
            base_name, ext = os.path.splitext(image_path)
            signed_image_path = f"{base_name}_signed{ext}"
        
        self._embed_in_pixels(img, encrypted_sig)
        
        img.save(signed_image_path, "PNG")
        print(f"Signed image saved to: {signed_image_path}")
        return signed_image_path, signature

    def verify_signature(self, signed_image_path):
        """
        Verifies image signature with improved extraction.
        """
        if not self.public_key:
            raise ValueError("Public key is required for verification.")
        
        img = Image.open(signed_image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        print("Extracting embedded data...")
        encrypted_sig = self._extract_from_pixels(img)
        
        if not encrypted_sig:
            print("No valid data found in image.")
            return False
        
        print(f"Extracted encrypted signature: {len(encrypted_sig)} bytes")
        
        try:
            signature = self._decrypt_signature(encrypted_sig)
            print(f"Decrypted signature: {len(signature)} bytes")
            
            image_hash = self.compute_image_hash(signed_image_path)
            
            self.public_key.verify(
                signature,
                image_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verification successful!")
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

def main():
    """
    Main function to handle command-line arguments and execute operations.
    """
    parser = argparse.ArgumentParser(description='RSA Image Digital Signature Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    gen_parser = subparsers.add_parser('generate-keys', help='Generate RSA key pair')
    gen_parser.add_argument('-s', '--size', type=int, default=4096, help='Key size in bits (default: 4096)')
    gen_parser.add_argument('-o', '--output', type=str, default='keys', help='Output directory for keys')
    gen_parser.add_argument('-p', '--password', type=str, help='Password to encrypt the private key (optional)')
    
    sign_parser = subparsers.add_parser('sign', help='Sign an image')
    sign_parser.add_argument('-i', '--image', type=str, required=True, help='Path to the image to sign')
    sign_parser.add_argument('-k', '--key', type=str, required=True, help='Path to the private key')
    sign_parser.add_argument('-o', '--output', type=str, help='Output path for the signed image')
    sign_parser.add_argument('-p', '--password', type=str, help='Password to decrypt the private key (optional)')
    
    verify_parser = subparsers.add_parser('verify', help='Verify an image signature')
    verify_parser.add_argument('-i', '--image', type=str, required=True, help='Path to the signed image')
    verify_parser.add_argument('-k', '--key', type=str, required=True, help='Path to the public key')
    
    args = parser.parse_args()
    
    if args.command == 'generate-keys':
        os.makedirs(args.output, exist_ok=True)
        
        key_gen = RSAKeyGenerator(key_size=args.size)
        key_gen.generate_keys()
        
        private_key_path = os.path.join(args.output, 'private_key.pem')
        public_key_path = os.path.join(args.output, 'public_key.pem')
        key_gen.save_keys(private_key_path, public_key_path, args.password)
    
    elif args.command == 'sign':
        private_key = RSAKeyGenerator.load_private_key(args.key, args.password)
        
        signer = ImageSigner(private_key=private_key)
        signed_image_path, _ = signer.sign_image(args.image, args.output)
        
        print(f"Image signed successfully: {signed_image_path}")
    
    elif args.command == 'verify':
        public_key = RSAKeyGenerator.load_public_key(args.key)
        
        signer = ImageSigner(public_key=public_key)
        result = signer.verify_signature(args.image)
        
        sys.exit(0 if result else 1)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()