import os
from cryptography.fernet import Fernet
import getpass
import base64
import hashlib

class PasswordEncryptor:
    def __init__(self, key_file='encryption.key'):
        """
        Initialize the password encryptor with key management
        """
        self.key_file = key_file
        self.key = self._load_or_generate_key()

    def _load_or_generate_key(self):
        """
        Load an existing encryption key or generate a new one
        """
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as key_file:
                return key_file.read()
        else:
            # Generate a new key
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as key_file:
                key_file.write(key)
            print(f"New encryption key generated and saved to {self.key_file}")
            return key

    def encrypt_password(self, password):
        """
        Encrypt a given password
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Create Fernet instance
        fernet = Fernet(self.key)
        
        # Encrypt the password
        encrypted_password = fernet.encrypt(password.encode())
        
        return encrypted_password

    def decrypt_password(self, encrypted_password):
        """
        Decrypt an encrypted password
        """
        try:
            # Create Fernet instance
            fernet = Fernet(self.key)
            
            # Decrypt the password
            decrypted_password = fernet.decrypt(encrypted_password).decode()
            
            return decrypted_password
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def generate_strong_password(self, length=16):
        """
        Generate a strong random password
        """
        # Use os.urandom for cryptographically secure random bytes
        random_bytes = os.urandom(length)
        
        # Convert to base64 to create a printable password
        password = base64.urlsafe_b64encode(random_bytes).decode()[:length]
        
        return password

def main():
    # Initialize the password encryptor
    encryptor = PasswordEncryptor()

    while True:
        print("\n--- Secure Password Manager ---")
        print("1. Encrypt a Password")
        print("2. Decrypt a Password")
        print("3. Generate Strong Password")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ")

        try:
            if choice == '1':
                # Encrypt Password
                password = getpass.getpass("Enter password to encrypt: ")
                encrypted = encryptor.encrypt_password(password)
                print(f"Encrypted Password: {encrypted.decode()}")

            elif choice == '2':
                # Decrypt Password
                encrypted_input = input("Enter encrypted password: ").encode()
                decrypted = encryptor.decrypt_password(encrypted_input)
                if decrypted:
                    print(f"Decrypted Password: {decrypted}")

            elif choice == '3':
                # Generate Strong Password
                password_length = int(input("Enter desired password length (default 16): ") or 16)
                strong_password = encryptor.generate_strong_password(password_length)
                print(f"Generated Strong Password: {strong_password}")

            elif choice == '4':
                print("Exiting...")
                break

            else:
                print("Invalid choice. Please try again.")

        except ValueError as ve:
            print(f"Error: {ve}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
