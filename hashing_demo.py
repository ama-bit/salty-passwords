import hashlib
import secrets

# Server-side secret pepper (hidden)
PEPPER = "mySecretPepper123"

def hash_with_salt_and_pepper(password, salt=None):
    """
    Hash a password with salt and a server-side pepper.
    If no salt is provided, generate a new one.
    Returns the salt and the hashed password.
    """
    if salt is None:
        salt = secrets.token_hex(8)  # Generate a random salt
    # Combine password + salt + pepper
    salted_password = password + salt + PEPPER
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return salt, hashed_password

def main():
    print("WARNING: This code is for educational purposes only and certainly NOT secure enough for real-world applications.")

    password = input("Enter a password to hash: ")

    # First hash (storing salt + hash)
    salt1, hash1 = hash_with_salt_and_pepper(password)
    print("\nFirst run (hashing password):")
    print(f"Salt: {salt1}")
    print(f"Hash: {hash1}")
    print(f"(Pepper is secret and not stored in database)")

    input("\nPress Enter to simulate login and verify the same password...")

    # Simulate login: retrieve salt from "database" and hash input password
    print("\nVerifying password using stored salt:")
    salt_from_db = salt1  # In real life, you'd get this from your database
    _, hash_check = hash_with_salt_and_pepper(password, salt=salt_from_db)
    print(f"Hash from verification: {hash_check}")

    if hash_check == hash1:
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

if __name__ == "__main__":
    main()
