import hashlib
import secrets

def main():
    password = input("Enter a password: ")

    # Generate a random salt
    salt = secrets.token_hex(8)

    # Combine password and salt
    salted_password = password + salt

    # Hash the salted password
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()

    print("\nSalted SHA-256 hash:")
    print(f"Salt: {salt}")
    print(f"Hash: {hashed_password}")

if __name__ == "__main__":
    main()
