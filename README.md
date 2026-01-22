# 🧑‍🍳 Peppered Passwords 🔏 
## Python Hashing Demo

An **interactive, terminal-based Python demo** that explains how passwords are
*actually* protected in real systems — and why naïve hashing fails.

This project walks through **hashing, salting, peppering, slow hashing, and rate limiting**
using **only Python’s standard library**, with clear output showing what users,
databases, and attackers can see at each step.

---

## Requirements

- Python 3.x
- No external libraries required *(standard library only)*
- Works on macOS, Linux, and Windows terminals

---

## What the Demo Covers

The script progresses step-by-step through:

1. Plain hashing (SHA-256) and why it fails
2. Salting (**unique** per user, *stored*)
3. Two users with the *same password → different hashes*
4. Peppering (**server-side** secret)
5. Database breach: *attacker vs database visibility*
6. **Rate limiting** (online attack defense)
7. Fast vs slow hashing (**SHA-256 vs PBKDF2**)

Each step pauses so users can follow along.

---

## Before We Begin 🛑

1. **Hashing**
   - A hash is a one-way function that converts input data (like a password) into a fixed-length output.
   - The same input always produces the *same hash value*.
   - Hashes cannot be reversed to recover the original password.
     
2. **Plain hashing is not enough** 
   - Fast hashes (like SHA-256) are *designed for speed, not password security*.
   - Attackers can precompute hashes of common passwords and compare them against leaked databases.
     
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

---

> ⚠️ **For Educational Purposes Only!**
> This project is designed to teach concepts, not serve as production code.
> Production systems should:
>    - Use argon2, bcrypt, or scrypt
>    - Store peppers securely (env vars / secrets managers)
>    - Rely on established authentication frameworks.
>      
> 📑 **Educational Scope**
>   - Salting and peppering increase password security by mitigating attack risk.
>   - **SHA-256** is used here only to illustrate hashing at a basic level.

---


## How to Run :desktop_computer:

1. Clone the repository:
   
```
git clone https://github.com/ama-bit/peppered-passwords.git
```

2. Navigate into the repo:

```
cd peppered-passwords
```

3. Run the demo script:

```
python hashing_demo.py
```

4. Follow the on-screen prompts.

---

## Example of Output

```
PEPPERED PASSWORDS: HASHING DEMO
Intro to hashing, salting, and peppering
Python standard library only


-- Press Enter to continue --

========================================================================
[STEP 1] ACCOUNT CREATION — BASIC HASHING
========================================================================
Enter a password to use for the demo: Pass321

DATA FLOW:
Plaintext Password
        |
        v
     SHA-256
        |
        v
   Stored Hash

What exists:
- Plaintext password: Pass321
- Stored hash:        abe4991221a146043c3deebd1e0f880e7ac2ba321a2ed6b46aca6ec6fe7dd62a

Problem:
Fast hashes allow attackers to test billions of guesses per second, making brute-force attacks practical at scale.

-- Press Enter to continue --

========================================================================
[STEP 2] ADDING A SALT (PER USER, STORED)
========================================================================

What exists for ONE user:
- Password: Pass321
- Salt (stored in DB): c2febae2c622983bc4a8120616fc5430
- Hash (stored in DB): 607af17adec1ff2ffa7e615d439786033dda92b1948e7185f75258385384936e

Salt defends against:
- Rainbow tables
- Precomputed attacks

Salt does NOT defend against:
- Brute-force guessing
- Weak passwords

-- Press Enter to continue --

========================================================================
[STEP 2A] TWO USERS — SAME PASSWORD, DIFFERENT SALTS
========================================================================
USER A                                |                                USER B
--------------------------------------+--------------------------------------
Password:        Pass321              |                     Password: Pass321
Salt:            572ce...             |                        Salt: 9553c...
Hash:            923c6...             |                        Hash: 46607...

Full values (shown below for clarity):
- USER A salt: 572cea66e59ad27a8b3a23af169ca94f
- USER A hash: 923c68110959967be7ff851e9159b22edf4124732a1bedcbd20e19ea34e1a2ac
- USER B salt: 9553c6aa1eb34ec1db57fb2fa9bc1f41
- USER B hash: 46607ffdaf1d52cc6851c086e3eca9bd341831d2c30d19af982f96ad976662ca

Key takeaway:
Same password + different salts = completely different hashes.
Attackers cannot reuse across users.

-- Press Enter to continue --

========================================================================
[STEP 3] ADDING A PEPPER (SERVER-SIDE SECRET)
========================================================================

What exists where:
- Password: Pass321
- Salt (DB): c2febae2c622983bc4a8120616fc5430
- Hash (DB): 4238ec0d699777af6ad6a6d4fbba1431471bf7bb64106531a56ce166fbc43057
- Pepper:   STORED SERVER SIDE, NOT IN DB

-- Press Enter to continue --

========================================================================
[STEP 4] DATABASE BREACH — WHO SEES WHAT
========================================================================
DATABASE VIEW                         |                         ATTACKER VIEW
--------------------------------------+--------------------------------------
Password:        NEVER STORED         |                     Password: UNKNOWN
Salt:            c2feb...             |                        Salt: c2feb...
Hash:            4238e...             |                        Hash: 4238e...
Pepper:          <NOT STORED>         |                       Pepper: UNKNOWN

Full values (outside table):
- Full salt: c2febae2c622983bc4a8120616fc5430
- Full hash: 4238ec0d699777af6ad6a6d4fbba1431471bf7bb64106531a56ce166fbc43057

Key idea:
A breach exposes the database — not server-side secrets.

-- Press Enter to continue --

========================================================================
[STEP 5] RATE LIMITING — ONLINE ATTACK DEFENSE
========================================================================
Rate limiting slows attackers during LIVE login attempts.
Instead of allowing unlimited guesses, the system:
- Counts failed attempts
- Adds delays
- Makes attacks slow and noticeable

Simulating repeated login attempts:

Attempt 1: Password check performed
Attempt 2: Password check performed
Attempt 3: Password check performed
Attempt 4: Too many attempts — system slows response
Attempt 5: Too many attempts — system slows response

Rate limiting defends against:
- Online brute-force attacks
- Credential stuffing

Rate limiting does NOT defend against:
- Database breaches
- Offline cracking
- Phishing

-- Press Enter to continue --

========================================================================
[STEP 6] WHY SLOW HASHING MATTERS
========================================================================
SHA-256 time : 0.000019 seconds
PBKDF2 time  : 0.055075 seconds

Slow hashes slow attackers down, while fast hashes allow attackers many more tries per second!

-- Press Enter to continue --

========================================================================
[STEP 7] FINAL TAKEAWAYS
========================================================================
- Passwords are NEVER stored
- Salts are unique per user and stored
- Same password does NOT mean same hash
- Peppers protect breached databases
- Slow hashes resist brute force
- Rate limiting protects live systems

NOT defended against:
- Phishing
- Malware
- Password reuse

Standards referenced:
- NIST SP 800-63B
- OWASP Password Storage Cheat Sheet

You've reached the End of this hashing demo - Thank you for your time!
```

---

## What This Demo Does Not Protect Against ❌

- Phishing

- Malware / keyloggers

- Password reuse across sites

- Compromised endpoints
*(Those require different controls.)*

---

## Why Not SHA-256?

- SHA-256 is cryptographically secure, but it is too fast.

- Modern GPUs can compute billions of SHA-256 hashes per second

- This makes brute-force and dictionary attacks practical

- Password hashing should be slow by design

- This demo uses SHA-256 only to illustrate the concepts covered.

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

## License

MIT License — free to use, modify, and share for learning and teaching.

---
