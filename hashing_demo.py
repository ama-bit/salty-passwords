import hashlib
import secrets

# Server-side secret peppers (NOT stored in DB)
PEPPER1 = "Pepper1"
PEPPER2 = "Pepper2"

def hash_with_salt_and_pepper(password, pepper):
    salt = secrets.token_hex(8)
    combined = pepper + password + salt
    hashed = hashlib.sha256(combined.encode()).hexdigest()
    return salt, hashed

def rainbow_table_attack_demo():
    print("\n" + "=" * 70)
    print("RAINBOW TABLE ATTACK DEMONSTRATION (EDUCATIONAL)")
    print("=" * 70)

    common_passwords = [
        "123456", "password", "qwerty", "letmein", "admin", "welcome"
    ]

    # -------------------------------
    # Attacker precomputation
    # -------------------------------
    print("\n[1] Attacker precomputes hashes (NO salt, NO pepper):")
    rainbow_table = {}

    for pwd in common_passwords:
        hash_val = hashlib.sha256(pwd.encode()).hexdigest()
        rainbow_table[hash_val] = pwd
        print(f"{pwd:<10} -> {hash_val}")

    print("\nNOTE:")
    print("This is a simplified rainbow table (precomputed hash lookup).")
    print("Real rainbow tables use hash chains to reduce storage.")

    # -------------------------------
    # Unsalted victim (broken)
    # -------------------------------
    victim_password = "password"
    stolen_hash = hashlib.sha256(victim_password.encode()).hexdigest()

    print("\n[2] Victim uses UNSALTED hashing (INSECURE):")
    print(f"Stored hash in DB: {stolen_hash}")

    print("\n[3] Attacker performs lookup...")
    cracked = rainbow_table.get(stolen_hash)

    if cracked:
        print(f"PASSWORD CRACKED INSTANTLY: '{cracked}'")

    # -------------------------------
    # Salt only
    # -------------------------------
    print("\n[4] Victim uses SALT (no pepper):")
    salt_only = secrets.token_hex(8)
    salted_hash = hashlib.sha256((victim_password + salt_only).encode()).hexdigest()

    print(f"Salt (stored & visible): {salt_only}")
    print(f"Stored hash in DB:      {salted_hash}")

    print("\n[5] Attacker tries rainbow table again...")
    cracked = rainbow_table.get(salted_hash)

    if not cracked:
        print("Attack FAILED — salt breaks precomputation")

    print("\nWhy attackers can't just 'add the salt':")
    print("- Each user has a unique salt")
    print("- Attacker would need a new table per salt")

    # -------------------------------
    # Salt + Pepper
    # -------------------------------
    print("\n[6] Victim uses SALT + PEPPER:")
    salt, secure_hash = hash_with_salt_and_pepper(victim_password, PEPPER1)

    print(f"Salt (visible to attacker): {salt}")
    print("Pepper: SECRET (server-side, NOT in DB)")
    print(f"Stored hash in DB:          {secure_hash}")

    print("\n[7] Attacker tries lookup again...")
    cracked = rainbow_table.get(secure_hash)

    if not cracked:
        print("Attack FAILED — pepper is unknown")

    print("\nSUMMARY:")
    print("- Rainbow tables rely on precomputation")
    print("- Salt makes every hash unique")
    print("- Pepper protects even if the DB is leaked")
    print("- Fast hashes like SHA-256 are still NOT ideal")

def main():
    print("WARNING: EDUCATIONAL DEMO — NOT FOR PRODUCTION USE\n")

    password = input("Enter a password to hash: ")

    print("\n================ PASSWORD HASHING DEMO ================")

    print("\nFirst run (salt + pepper):")
    salt1, hash1 = hash_with_salt_and_pepper(password, PEPPER1)
    print(f"Pepper (hidden): {PEPPER1}")
    print(f"Salt:            {salt1}")
    print(f"Hash:            {hash1}")

    input("\nPress Enter to hash the SAME password again...")

    print("\nSecond run (new salt + new pepper):")
    salt2, hash2 = hash_with_salt_and_pepper(password, PEPPER2)
    print(f"Pepper (hidden): {PEPPER2}")
    print(f"Salt:            {salt2}")
    print(f"Hash:            {hash2}")

    print("\nObservation:")
    print("- Same password")
    print("- Different salt")
    print("- Different pepper")
    print("- Completely different hashes")

    rainbow_table_attack_demo()

if __name__ == "__main__":
    main()
