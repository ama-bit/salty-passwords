import hashlib

def main():
    password = input("Enter a password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    print("\nPlain SHA-256 hash:")
    print(hashed_password)

if __name__ == "__main__":
    main()
