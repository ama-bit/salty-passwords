import hashlib
import secrets

# --------------------------------------------------
# Server-side secret pepper (NOT stored in database)
# --------------------------------------------------
PEPPER = "SuperSecretPepper"

# --------------------------------------------------
# Helper for consistent step headers
# --------------------------------------------------
def print_step(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

# --------------------------------------------------
# Salt + Pepper hashing (educational)
# --------------------------------------------------
def hash_with_salt_and_pepper(password, pepper):
    salt = secrets.token_hex(8)
    combined = pepper + password + salt
    hashed = hashlib.sha256(combined.encode()).hexdigest()
    return salt, hashed

# --------------------------------------------------
# STEP 4: Rainbow Table Attack Demo
# --------------------------------------------------
def rainbow_table_attack_demo():
    print("Attacker perspective:\n")

    common_passwords = [
        "123456", "password", "qwerty", "letmein", "admin", "welcome"
    ]

    # Attacker precomputes hashes (no salt, no pepper)
    print("[1] Attacker precomputes hashes (NO salt, NO pepper):")
    rainbow_table = {}

    for pwd in common_passwords:
        hash_val = hashlib.sha256(pwd.encode()).hexdigest()
        rainbow_table[hash_val] = pwd
        print(f"{pwd:<10} -> {hash_val}")

    input("\nPress Enter to continue...")
    
    print("\nNOTE:")
    print("This is a simplified rainbow table (precomputed hash lookup).")
    print("Real rainbow tables use hash chains to reduce storage.")

    # Unsalted victim
    victim_password = "password"
    stolen_hash = hashlib.sha256(victim_password.encode()).hexdigest()

    print("\n[2] Victim uses UNSALTED hashing (INSECURE):")
    print(f"Hash stored in DB: {stolen_hash}")

    input("\nPress Enter to continue...")
    
    print("\n[3] Attacker performs lookup...")
    cracked = rainbow_table.get(stolen_hash)

    if cracked:
        print(f" PASSWORD CRACKED INSTANTLY: '{cracked}'")

    input("\nPress Enter to continue...")
    
    # Salt only
    print("\n[4] Victim uses SALT (no pepper):")
    salt_only = secrets.token_hex(8)
    salted_hash = hashlib.sha256((victim_password + salt_only).encode()).hexdigest()

    print(f"Salt (stored & visible): {salt_only}")
    print(f"Hash stored in DB:       {salted_hash}")

    input("\nPress Enter to continue...")
    
    print("\n[5] Attacker tries rainbow table again...")
    cracked = rainbow_table.get(salted_hash)

    if not cracked:
        print("Attack FAILED — salt breaks precomputation")

    print("\nWhy attackers can't just 'add the salt':")
    print("- Each user has a unique salt")
    print("- Attacker would need a new table per salt")

    # Salt + Pepper
    print("\n[6] Victim uses SALT + PEPPER:")
    salt, secure_hash = hash_with_salt_and_pepper(victim_password, PEPPER)

    print(f"Salt (visible): {salt}")
    print("Pepper: SECRET (server-side)")
    print(f"Hash stored in DB: {secure_hash}")

    input("\nPress Enter to continue...")
    
    print("\n[7] Attacker tries lookup again...")
    cracked = rainbow_table.get(secure_hash)

    if not cracked:
        print("Attack FAILED — pepper is unknown")
    
    input("\nPress Enter to continue...")
    
    print("\nREAL-WORLD BEST PRACTICE:")
    print("- Use bcrypt, argon2, or scrypt")
    print("- Use a constant server-side pepper")
    print("- Never use fast hashes like SHA-256 for passwords")

# --------------------------------------------------
# Main demo flow
# --------------------------------------------------
def main():
    print("WARNING: EDUCATIONAL DEMO — NOT FOR PRODUCTION USE\n")
    print("NOTE: In real systems, pepper is constant and stored securely.\n")

    password = input("Enter a password to hash: ")

    # STEP 1
    print_step("STEP 1: Plain SHA-256 Hash")
    plain_hash = hashlib.sha256(password.encode()).hexdigest()
    print(f"Hash stored in DB: {plain_hash}")
    print("Vulnerable to rainbow table attacks")

    input("\nPress Enter to continue...")

    # STEP 2
    print_step("STEP 2: Salted Hash")
    salt = secrets.token_hex(8)
    salted_hash = hashlib.sha256((password + salt).encode()).hexdigest()

    print(f"Salt (stored & visible): {salt}")
    print(f"Hash stored in DB:       {salted_hash}")
    print("Same password now produces a unique hash")

    input("\nPress Enter to continue...")

    # STEP 3
    print_step("STEP 3: Salt + Pepper")
    salt, secure_hash = hash_with_salt_and_pepper(password, PEPPER)

    print("Pepper: SECRET (server-side)")
    print(f"Salt (stored & visible): {salt}")
    print(f"Hash stored in DB:       {secure_hash}")
    print("Protected even if the database is leaked")

    input("\nPress Enter to continue...")

    # STEP 4
    print_step("STEP 4: Rainbow Table Attack")
    rainbow_table_attack_demo()

# --------------------------------------------------
if __name__ == "__main__":
    main()
