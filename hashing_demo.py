import hashlib
import secrets

def hash_with_salt(password):
        salt = secrets.token_hex(8)
        salted_password = password + salt
        hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
        return salt, hashed_password
    
def main():
    password = input("Enter a password: ")

    print("\nFirst run:")
    salt1, hash1 = hash_with_salt(password)
    print(f"Salt: {salt1}")
    print(f"Hash: {hash1}")

    input("\nPress Enter to hash the SAME password again...")

    print("\nSecond run:")
    salt2, hash2 = hash_with_salt(password)
    print(f"Salt: {salt2}")
    print(f"Hash: {hash2}")

    print("\nNotice:")
    print("- The password stayed the same")
    print("- The salt changed")
    print("- The hash changed")

if __name__ == "__main__":
    main()
