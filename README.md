# Salty Passwords: :salt:
## Hashing Demo

This repository demonstrates **basic password hashing concepts in Python**, including:

1. Plain hashing (SHA-256)
2. Salted hashing
3. Salt + pepper (hidden server-side secret)
4. Rainbow table attack simulation

*The goal is to help beginners understand why salting and peppering passwords improves security.*

---

## Requirements

- Python 3.x
- No external libraries required *(standard library only)*

---

> ⚠️ **For Educational Purposes Only!**
> This project demonstrates concepts and is not intended for production use.

---

## How to Run :desktop_computer:

1. Clone the repository:
   
```
git clone https://github.com/ama-bit/salty-passwords.git
```

2. Navigate into the repo:

```
cd salty-passwords
```

3. Run the demo script:

```
python hashing_demo.py
```

4. Follow the on-screen prompts.

---

## Demo Steps

The script walks through four key stages:

### Step 1: *Plain SHA-256 Hash*

- User enters a password.
- Password is hashed with SHA-256.
- Shows why storing plain hashes is insecure
  (vulnerable to precomputed hash attacks).

### Step 2: *Salted Hash*

- Adds a random salt to each password.
- Same password now produces a unique hash each time.
- Salt is displayed to show how it changes each run.
- Demonstrates why salts break rainbow table attacks. 

### Step 3: *Salt + Pepper*

- Adds a **hidden server-side "pepper"** in addition to the salt.
- Even if the database is leaked, the pepper **prevents simple attacks**.
- Demonstrates the difference between salt and pepper.

### Step 4: *Rainbow Table Attack Demo*

- Shows how attackers precompute hashes of common passwords.
- Demonstrates why unsalted hashes are vulnerable.
- Shows how salt and pepper make rainbow tables ineffective.
- Includes a clear explanation of attacker visibility
  (salt is visible, pepper is secret).

---

## Key Takeaways :bookmark:

- Plain hashes are insecure; attackers can crack them easily using rainbow tables.
- Salts prevent identical passwords from producing the same hash, reducing the risk of precomputed attacks.
- Pepper adds an extra layer of security, protecting passwords even if the database is leaked.
- Hashing with salt + pepper is a educational demonstration of password security fundamentals.
- Fast hashes (SHA-256) are not suitable for production systems.
- Instead, argon2 or bcrypt are recommended for real-world applications. 

---

## Resources 📚

**Python for Beginners**

1. [Official Python Tutorial](https://docs.python.org/3/tutorial/)

2. [Python 'hashlib' Documentation](https://docs.python.org/3/library/hashlib.html)

3. [Python 'secrets' Module](https://docs.python.org/3/library/secrets.html)

**Password Security & Best Practices**

1. [NIST Digital Identity Guidelines (SP 800-63B)](https://pages.nist.gov/800-63-3/sp800-63b.html)

2. [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

