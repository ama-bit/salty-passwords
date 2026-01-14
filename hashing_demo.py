import hashlib
import secrets

# Server-side secret pepper (hidden from user)
PEPPER = "mySecretPepper123"

def hash_with_salt_and_pepper(password):
        salt = secrets.token_hex(8)
        salted_password = password + salt + PEPPER 
        hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
        return salt, hashed_password
    
def main():
    password = input("Enter a password: ")

    print("\nFirst run (with salt + pepper):")
    salt1, hash1 = hash_with_salt_and_pepper(password)
    print(f"Salt: {salt1}")
    print(f"Hash: {hash1}")

    input("\nPress Enter to hash the SAME password again...")

    print("\nSecond run (with new salt + same pepper):")
    salt2, hash2 = hash_with_salt_and_pepper(password)
    print(f"Salt: {salt2}")
    print(f"Hash: {hash2}")

    print("\nNotice:")
    print("- The password stayed the same")
    print("- Salt changed each run")
    print("- Hash changed each run")
    print("- Pepper adds extra security even if the database is leaked")

if __name__ == "__main__":
    main()
