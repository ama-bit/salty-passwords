# Salty Passwords :salt:
## Hashing Demo

This repository demonstrates **basic password hashing concepts in Python** to show what hashing is, why naive hashing fails, and how salting and peppering improve password security. 

Below is the order of topics covered in the `hashing_demo.py`:

1. Plain hashing (SHA-256)
2. Salted hashing
3. Salt + pepper (hidden server-side secret)
4. Rainbow table attack simulation

---

## Requirements

- Python 3.x
- No external libraries required *(standard library only)*

---

## Before We Begin 🔏

1. **Hashing**
   - A hash is a one-way function that converts input data (like a password) into a fixed-length output.
   - The same input always produces the *same hash value*.
   - Hashes cannot be reversed to recover the original password.
     
2. **Plain hashing is not enough** 
   - Fast hashes (like SHA-256) are *designed for speed, not password security*.
   - Attackers can precompute hashes of common passwords and compare them against leaked databases.
   - This weakness is shown later using a rainbow table attack simulation.
     
3. **Salting**
   - A salt is *a random value added to a password before hashing*.
   - Each password gets a **unique salt**.
   - Salts are stored with the hash and are *visible to attackers*.
   - Salting prevents identical passwords from producing the same hash and *breaks precomputed attacks*.
     
4. **Peppering**
   - A pepper is a **secret value** added to the password *before hashing*.
   - Unlike salts, peppers are never stored in the database.
   - The pepper is *kept server-side* and is unknown to attackers.
   - Even if the database is leaked, the pepper adds an extra layer of protection.

5. **Attacker Perspective**
    - Attackers assume the hashing algorithm and salts are known.
    - They attempt to crack passwords by *hashing common guesses and comparing results*.
    - Without the pepper, attacks are easier.

6. **Educational Scope**
   - Salting and peppering increase password security by mitigating attack risk. 
   - **SHA-256** is used here only to illustrate hashing at a basic level.

> ⚠️ **For Educational Purposes Only!**
> This project demonstrates concepts and **is not intended for production use**.
> 

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

The `hashing_demo.py` script goes through four stages:

### Step 1: *Plain SHA-256 Hash*

- User enters a password.
- Password is hashed with SHA-256.
- Shows why storing plain hashes is insecure.
- *(Vulnerable to precomputed hash attacks)*.

### Step 2: *Salted Hash*

- Adds a *random* salt to each password.
- Same password now produces a *unique* hash each time.
- Salt is displayed to show how it changes each run.
- Demonstrates why salts *break rainbow table attacks*. 

### Step 3: *Salt + Pepper*

- Adds a **hidden server-side "pepper"** in addition to the salt.
- Even if the database is leaked, the pepper **prevents simple attacks**.
- Shows the difference between salt and pepper.

### Step 4: *Rainbow Table Attack Demo*

- Illustrates *how* attackers precompute hashes of common passwords.
- Shows *why* unsalted hashes are vulnerable.
- Demonstrates *how* salt and pepper make rainbow tables ineffective.
- Includes a clear explanation of attacker visibility.
- *(Salt is visible, pepper is secret)*.

---

## Key Takeaways :bookmark:

- Plain hashes are insecure; attackers can crack them easily using *rainbow tables*.
- Salts *prevent* identical passwords from *producing the same hash, reducing* the risk of precomputed attacks.
- Pepper adds an extra layer of security, protecting passwords even if the database is leaked.
- Hashing with salt + pepper is an educational demonstration of password security fundamentals.
- Fast hashes (SHA-256) are not suitable for production systems.
*(Instead, **Argon2** or **bcrypt** are typically recommended)*. 

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

