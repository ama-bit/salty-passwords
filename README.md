# Salty Passwords

## Purpose
A beginner-friendly lab demonstrating secure password storage by salting passwords before hashing them. This project introduces basic password security practices in a hands-on, approachable fashion.

## Threat Overview
- Hashing passwords without a salt produces identical outputs for identical passwords, making them vulnerable to rainbow table attacks. 
- Weak hashes are susceptible to brute-force attacks.
- Salting the password before hashing mitigates these risks.

## Implementation
- Passwords are salted before being hashed using SHA-256.
- Verification compares user input against stored salted hashes.
- Simple Python scripts are provided to experiment safely.

## How to Use
1. Clone the repository
2. Run `python_salt_demo.py`
3. Enter a password to hash
4. Verify it using the prompt

## Learning Outcomes
- Understand the importance of salting passwords before hashing.
- Gain hands-on experience with Python hashing functions.
- Appreciate practical security considerations in password storage.

## Optional Steps
- Replace SHA-256 with Argon2 for industry-standard hashing.
- Add unit tests or logging for better maintainability.
- Compare salted vs unsalted hashes using a small dataset.
