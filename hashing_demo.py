import hashlib
import secrets

# Server-side secret pepper (hidden)
PEPPER1 = "Pepper1"
PEPPER2 = "Pepper2"

def hash_with_salt_and_pepper(password):
        salt = secrets.token_hex(8)
        salted_password = PEPPER + password + salt  
        hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
        return salt, hashed_password
    
def main():

    print("WARNING: This code is for educational purposes only and certainly NOT secure enough for real-world applications.")
    
    password = input("Enter a password: ")

    print("\nFirst run (with pepper + salt):")
    salt1, hash1 = hash_with_salt_and_pepper(password)
    print(f"Pepper (for clarity, not visible in hash directly): {PEPPER1}")
    print(f"Salt: {salt1}")
    print(f"Hash: {hash1}")
        
    print("\nNote: The pepper is a secret, server-side value that is added to the password before salting.")
    print("It is NOT visible in the hash output but adds an additional layer of security.")
        
    input("\nPress Enter to hash the SAME password again to get a DIFFERENT hash output...")

    print("\nSecond run (with new salt + pepper):")
    salt2, hash2 = hash_with_salt_and_pepper(password)
    print(f"Pepper: {PEPPER2}")
    print(f"Salt: {salt2}")
    print(f"Hash: {hash2}")
        
    print("\nNotice:")
    print("- The password stayed the same")
    print("- Pepper changed each run, and adds extra security even if the database is leaked")
    print("- Salt changed each run")
    print("- Hash changed each run")

if __name__ == "__main__":
    main()
