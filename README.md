# Salty Passwords :salt: 
## Hashing Demo

This repository demonstrates basic password hashing concepts using **Python**, with a focus on:

1. Plain hashing (SHA-256)
2. Salted hashing
3. Salt + pepper (hidden server-side secret)

*The goal is to help beginners understand the purpose of salting and peppering passwords.*

---

## Requirements

- Python 3.x
- No external libraries required *(only standard library)*

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

### Step 1: *Plain SHA-256 Hash*

- User enters a password.
- Password is hashed with SHA-256.
- Shows why storing plain hashes is insecure.

### Step 2: *Salted Hash*

- Adds a random salt to each password.
- Same password now produces a unique hash each time.
- Salt is displayed to show how it changes each run.

### Step 3: *Salt + Pepper*

- Adds a hidden "pepper" (server-side secret) to the password in addition to salt. 
- Demonstrates how pepper adds extra security even if the database is leaked.

---

## Key Takeaways :bookmark:

- **Salts** prevent identical passwords from producing the same hash.
- **Pepper** adds an extra layer of security, especially against database leaks.
- Simple Python scripts can effectively demonstrate **password security fundamentals**.

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

