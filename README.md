# 🧑‍🍳 Peppered Passwords 🔏 
## Python Hashing Demo

This interactive Python demo explores secure password storage, covering techniques like hashing, salting, peppering, slow hashing, and rate limiting. 

You'll learn why basic hashing alone isn't enough to protect sensitive data, using only Python’s standard library for clear, accessible explanations.

---

## Requirements

- Python 3.x
- No external libraries required *(standard library only)*
- Works on macOS, Linux, and Windows terminals

---

## What You’ll Learn

The demo covers the following key concepts step-by-step:

1. Plain Hashing (SHA-256): Understand why hashing alone isn’t secure.

2. Salting: Learn how adding random data (a salt) to a password improves security.

3. Peppering: See how a secret value on the server side adds another layer of protection.

4. Rate Limiting: Understand how limiting failed login attempts can help prevent brute-force attacks.

5. Slow Hashing: Compare SHA-256 (fast) to PBKDF2 (slow) and see how it impacts security.

---

> ⚠️ **For Educational Purposes Only!**
> This project is designed to teach concepts, not serve as production code.
> Production systems should:
>    - Use argon2, bcrypt, or scrypt
>    - Store peppers securely (env vars / secrets managers)
>    - Rely on established authentication frameworks.

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

4. Follow the instructions on-screen as you work through the steps.

---

## What You’ll See 👀

The demo will guide users through each concept, illustrating how passwords are processed and what happens at every step:

1. **Basic Hashing (SHA-256)**
The demo begins by showing SHA-256, a simple hashing algorithm, and explaining why it’s insufficient on its own.

2. **Salting**
Next, a salt will be added to each password to demonstrate how this unique, random string enhances security.

3. **Peppering**
Peppering will then be introduced—this is a secret value stored on the server side, providing an extra layer of protection in case the database is compromised.

4. **Rate Limiting**
The demo will also cover rate limiting, which helps mitigate brute-force attacks by restricting the number of failed login attempts.

5. **Slow Hashing**
Lastly, the demo compares fast hashing (SHA-256) with slow hashing (PBKDF2) to explain why slower hashing is more effective for password security.

**Why This Matters**

In real-world applications, passwords need to be secured properly to prevent attackers from easily gaining unauthorized access. This demo walks through fundamental concepts for secure password storage, illustrating how each technique enhances security. Understanding these concepts is crucial for anyone interested in software security.

---

## Example of Output

Below is a snippet of the output which prompts the user to type a password for the demo. This same password is used later to show how a salt and pepper are added for secure storage. 

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
```

Below is a section of the output that shows how two users can have the same password, yet the hash values are different. This is because the salts are different every instance for each user. 

```
========================================================================
[STEP 2A] TWO USERS — SAME PASSWORD, DIFFERENT SALTS
========================================================================
USER A                                |                                USER B
--------------------------------------+--------------------------------------
Password:        Pass321              |                     Password: Pass321
Salt:            572ce...             |                        Salt: 9553c...
Hash:            923c6...             |                        Hash: 46607...

```
Below is a snippet of output showing why slow hashing is important by comparing SHA-256 with PBKDF2.

```-- Press Enter to continue --

========================================================================
[STEP 6] WHY SLOW HASHING MATTERS
========================================================================
SHA-256 time : 0.000019 seconds
PBKDF2 time  : 0.055075 seconds

Slow hashes slow attackers down, while fast hashes allow attackers many more tries per second!

-- Press Enter to continue --
```

---

## *Why* Not SHA-256?

- SHA-256 is cryptographically secure, providing integrity - but it is too fast.

- Billions of SHA-256 hashes can be computed - per second

- This makes brute-force and dictionary attacks practical (easier)

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
