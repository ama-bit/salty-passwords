# Salty Passwords

## Purpose
A beginner-friendly lab demonstrating why and how to **salt passwords before hashing**. This project introduces basic password security practices in a hands-on fashion. 

**Salting** means adding a unique set of random characters to a password before hashing it so two identical passwords produce **different hashes**, making attacks like rainbow tables ineffective.

## Threat Overview
- Hashing passwords without a salt produces identical outputs for identical passwords, making them vulnerable to rainbow table attacks. 
- Weak hashes are susceptible to brute-force attacks.
- Salting the password before hashing mitigates these risks by making each hash unique.

## Implementation
- Passwords are **salted** before being hashed using SHA-256.
- Verification compares user input against stored salted hashes.
- Simple Python scripts are provided to experiment safely.

## How to Use
1. Clone the repository
2. Run `python_salt_demo.py`
3. Enter a password to hash
4. Verify it using the prompt

## Learning Outcomes
- Understand the importance of **salting passwords** before hashing.
- Gain hands-on experience with Python **hashing functions**.
- Appreciate practical **security considerations** in password storage.

## Optional Steps
- Replace SHA-256 with Argon2 for industry-standard hashing.
- Add unit tests or logging for better maintainability.
- Compare salted vs unsalted hashes using a small dataset.
