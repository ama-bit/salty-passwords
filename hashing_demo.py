import hashlib
import secrets
import time

# ============================================================
# CONSTANTS
# ============================================================

# Pepper is a SERVER-SIDE secret.
# It is NEVER stored in the database.
PEPPER = "SERVER_SIDE_SECRET_PEPPER"

# ANSI color codes (ASCII-only, terminal-safe)
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def pause():
    """Pause so users can read before continuing."""
    input(f"\n{CYAN}-- Press Enter to continue --{RESET}")


def header(step, title):
    """Print a consistent, numbered section header."""
    line = "=" * 72
    print(f"\n{CYAN}{line}")
    print(f"[STEP {step}] {title}")
    print(f"{line}{RESET}")


def sha256(data: str) -> str:
    """
    SHA-256 is a FAST cryptographic hash.
    It is NOT recommended for password storage.
    Used here to demonstrate weaknesses.
    """
    return hashlib.sha256(data.encode()).hexdigest()


def pbkdf2_hash(password: str, salt: str, iterations: int = 200_000) -> str:
    """
    PBKDF2-HMAC-SHA256
    - Built into Python
    - Recommended by NIST / OWASP
    - Slow by design to resist brute-force attacks
    """
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        iterations
    )
    return dk.hex()


def ascii_flow(title, lines):
    """Print a simple ASCII data-flow diagram."""
    print(f"\n{YELLOW}{title}{RESET}")
    for line in lines:
        print(line)
        time.sleep(0.2)


def short(value, length=5):
    """Return first few characters for table display."""
    return value[:length] + "..."


# ============================================================
# MAIN DEMO
# ============================================================

def main():
    print(f"\n{CYAN}SALTY PASSWORDS: HASHING DEMO{RESET}")
    print("Intro to hashing, salting, and peppering")
    print("Python standard library only\n")

    pause()

    # --------------------------------------------------------
    # STEP 1 — BASIC HASHING (INSECURE)
    # --------------------------------------------------------
    header(1, "ACCOUNT CREATION — BASIC HASHING")

    # User enters password ONCE; reused throughout the demo
    password = input("Enter a password to use for the demo: ")

    ascii_flow(
        "DATA FLOW:",
        [
            "Plaintext Password",
            "        |",
            "        v",
            "     SHA-256",
            "        |",
            "        v",
            "   Stored Hash"
        ]
    )

    plain_hash = sha256(password)

    print("\nWhat exists:")
    print(f"- Plaintext password: {password}")
    print(f"- Stored hash:        {plain_hash}")

    print(f"\n{RED}Problem:{RESET}")
    print("Fast hashes allow attackers to test billions of guesses per second, making brute-force attacks practical at scale.")

    pause()

    # --------------------------------------------------------
    # STEP 2 — ADDING A SALT
    # --------------------------------------------------------
    header(2, "ADDING A SALT (PER USER, STORED)")

    # A NEW salt is generated at account creation
    # Every user gets a DIFFERENT salt
    salt = secrets.token_hex(16)
    salted_hash = sha256(password + salt)

    print("\nWhat exists for ONE user:")
    print(f"- Password: {password}")
    print(f"- Salt (stored in DB): {salt}")
    print(f"- Hash (stored in DB): {salted_hash}")

    print(f"\n{GREEN}Salt defends against:{RESET}")
    print("- Rainbow tables")
    print("- Precomputed attacks")

    print(f"\n{RED}Salt does NOT defend against:{RESET}")
    print("- Brute-force guessing")
    print("- Weak passwords")

    pause()

    # --------------------------------------------------------
    # STEP 2A — TWO USERS, SAME PASSWORD
    # --------------------------------------------------------
    header("2A", "TWO USERS — SAME PASSWORD, DIFFERENT SALTS")

    # Both users choose the SAME password
    salt_a = secrets.token_hex(16)
    salt_b = secrets.token_hex(16)

    hash_a = sha256(password + salt_a)
    hash_b = sha256(password + salt_b)

    print("USER A".ljust(38) + "|" + "USER B".rjust(38))
    print("-" * 38 + "+" + "-" * 38)

    print(f"{'Password:'.ljust(16)} {password}".ljust(38) + "|" +
          f"{'Password:'.rjust(16)} {password}".rjust(38))

    print(f"{'Salt:'.ljust(16)} {short(salt_a)}".ljust(38) + "|" +
          f"{'Salt:'.rjust(16)} {short(salt_b)}".rjust(38))

    print(f"{'Hash:'.ljust(16)} {short(hash_a)}".ljust(38) + "|" +
          f"{'Hash:'.rjust(16)} {short(hash_b)}".rjust(38))

    print("\nFull values (shown below for clarity):")
    print(f"- USER A salt: {salt_a}")
    print(f"- USER A hash: {hash_a}")
    print(f"- USER B salt: {salt_b}")
    print(f"- USER B hash: {hash_b}")

    print(f"\n{GREEN}Key takeaway:{RESET}")
    print("Same password + different salts = completely different hashes.")
    print("Attackers cannot reuse across users.")

    pause()

    # --------------------------------------------------------
    # STEP 3 — ADDING A PEPPER
    # --------------------------------------------------------
    header(3, "ADDING A PEPPER (SERVER-SIDE SECRET)")

    # Pepper is added BEFORE hashing
    # Pepper is NOT stored in the database
    secure_hash = sha256(PEPPER + password + salt)

    print("\nWhat exists where:")
    print(f"- Password: {password}")
    print(f"- Salt (DB): {salt}")
    print(f"- Hash (DB): {secure_hash}")
    print(f"- Pepper:   {RED}STORED SERVER SIDE, NOT IN DB{RESET}")

    pause()

    # --------------------------------------------------------
    # STEP 4 — DATABASE VS ATTACKER
    # --------------------------------------------------------
    header(4, "DATABASE BREACH — WHO SEES WHAT")

    print("DATABASE VIEW".ljust(38) + "|" + "ATTACKER VIEW".rjust(38))
    print("-" * 38 + "+" + "-" * 38)

    print(f"{'Password:'.ljust(16)} NEVER STORED".ljust(38) + "|" +
          f"{'Password:'.rjust(16)} UNKNOWN".rjust(38))

    print(f"{'Salt:'.ljust(16)} {short(salt)}".ljust(38) + "|" +
          f"{'Salt:'.rjust(16)} {short(salt)}".rjust(38))

    print(f"{'Hash:'.ljust(16)} {short(secure_hash)}".ljust(38) + "|" +
          f"{'Hash:'.rjust(16)} {short(secure_hash)}".rjust(38))

    print(f"{'Pepper:'.ljust(16)} <NOT STORED>".ljust(38) + "|" +
          f"{'Pepper:'.rjust(16)} UNKNOWN".rjust(38))

    print("\nFull values (outside table):")
    print(f"- Full salt: {salt}")
    print(f"- Full hash: {secure_hash}")

    print(f"\n{GREEN}Key idea:{RESET}")
    print("A breach exposes the database — not server-side secrets.")

    pause()

        
    # --------------------------------------------------------
    # STEP 5 — RATE LIMITING (ONLINE ATTACK DEFENSE)
    # --------------------------------------------------------
    header(5, "RATE LIMITING — ONLINE ATTACK DEFENSE")

    print(
        "Rate limiting slows attackers during LIVE login attempts.\n"
        "Instead of allowing unlimited guesses, the system:\n"
        "- Counts failed attempts\n"
        "- Adds delays\n"
        "- Makes attacks slow and noticeable\n"
    )

    max_attempts = 3   # how many tries are allowed
    delay = 2          # seconds of delay after limit is hit

    print("Simulating repeated login attempts:\n")

    for attempt in range(1, 6):
        time.sleep(0.6)  # slow output so each line appears clearly
        print(f"Attempt {attempt}:", end=" ")

        if attempt > max_attempts:
            print(f"{YELLOW}Too many attempts — system slows response{RESET}")
            time.sleep(delay)
        else:
            print("Password check performed")

    print(f"\n{GREEN}Rate limiting defends against:{RESET}")
    print("- Online brute-force attacks")
    print("- Credential stuffing")

    print(f"\n{RED}Rate limiting does NOT defend against:{RESET}")
    print("- Database breaches")
    print("- Offline cracking")
    print("- Phishing")

    pause()

    # --------------------------------------------------------
    # STEP 6 — FAST VS SLOW HASHING
    # --------------------------------------------------------
    header(6, "WHY SLOW HASHING MATTERS")

    start = time.perf_counter()
    sha256(password)
    sha_time = time.perf_counter() - start

    start = time.perf_counter()
    pbkdf2_hash(password, salt)
    pbkdf2_time = time.perf_counter() - start

    print(f"SHA-256 time : {sha_time:.6f} seconds")
    print(f"PBKDF2 time  : {pbkdf2_time:.6f} seconds")

    print(
    f"\n{GREEN}Slow hashes slow attackers down, "
    f"while fast hashes allow attackers many more tries per second!{RESET}"
)
    pause()

    # --------------------------------------------------------
    # STEP 7 — FINAL TAKEAWAYS
    # --------------------------------------------------------
    header(7, "FINAL TAKEAWAYS")

    print("- Passwords are NEVER stored")
    print("- Salts are unique per user and stored")
    print("- Same password does NOT mean same hash")
    print("- Peppers protect breached databases")
    print("- Slow hashes resist brute force")
    print("- Rate limiting protects live systems")

    print(f"\n{RED}NOT defended against:{RESET}")
    print("- Phishing")
    print("- Malware")
    print("- Password reuse")

    print("\nStandards referenced:")
    print("- NIST SP 800-63B")
    print("- OWASP Password Storage Cheat Sheet")

    print(f"\n{CYAN}You've reached the End of this hashing demo - Thank you for your time!{RESET}")


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
