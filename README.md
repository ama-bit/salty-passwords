# Salty Passwords

---

## Purpose
A beginner-friendly project demonstrating **why and how passwords should be salted before hashing**. 

---

## Concepts

---

**Hashing** turns data like passwords into a fixed-length string using a mathematical function. 

`password123 -> SHA-256 -> ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f`

Hashing is one-way -> the original input cannot be reversed or recovered; however, unsalted hashes may be matched using rainbow table lookups.

---

**Salting** is the process of adding unique, randomly generated data to a password before hashing.

`salt (h7&g3T%) + password (password123) -> salted input`

`SHA-256("h7&g3T%password123") -> (unique hash output)`

After salting, identical plaintext passwords produce **different hashes** making rainbow table attacks ineffective.

---

## Threat Overview
1. Unsalted Hashes
   - Same password -> same hash
   - Easy to attack using **precomputed rainbow tables**
   *(tables that map common passwords to their hashes)*
2. Weak Hashing
   - Fast algorithms like raw SHA-256 are vulnerable to **brute force attacks**
3. Salting Mitigates Risk
   - Each password gets a unique salt
   *(random data/bytes combined with the password before hashing)*
   - Attackers must crack **each hash individually**
  
---
  
## Nuances

- Salting does **not** prevent brute force attacks, but it significantly increases the time and computational cost required.
- SHA-256 is used for demonstration only and is **not recommended for production password storage.** 

---

## Implementation
- Passwords are **salted** before being hashed using SHA-256.
- Verification compares user input against stored salted hashes.
- Simple Python scripts are provided to experiment safely.

---

## How to Use
1. Clone the repository
2. Run `python_salt_demo.py`
3. Enter a password to hash
4. Verify it using the prompt

---

## Learning Outcomes
- Understand the importance of **salting passwords** before hashing.
- Gain hands-on experience with Python **hashing and salting functions**.
- Appreciate practical **security considerations** in password storage.

---

## Optional Steps
- Replace SHA-256 with Argon2 for industry-standard hashing.
- Add unit tests or logging for better maintainability.
- Compare salted vs unsalted hashes using a small dataset.

---


