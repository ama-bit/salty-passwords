# Salty Passwords
### Password Salting and Hashing Demo 

---

## Purpose
A beginner-friendly cybersecurity project demonstrating **why passwords must be salted before hashing** and how improper storage introduces security risk.

---

## Project Overview :pushpin:

| *Category* | *Details* |
|-----|-------|
| Domain | Application Security |
| Language | Python |
| Standard | NIST SP 800-63B |
| Level | Beginner |

---

## Core Concepts 

### Hashing
- Converts input (e.g., passwords) into a fixed-length value using a mathematical function.
- **One-way**: original password cannot be recovered.
- Unsalted hashes are vulnerable to rainbow table attacks.  
`password123 → SHA-256 → ef92b778bafe771...`

### Salting
- Adds **unique, random data** to a password before hashing.
- Ensures identical passwords produce **different hashes**, mitigating precomputed attacks.  
`salt + password → SHA-256("%S41T%password123") → unique hash`

---

## Threat Model

**Unsalted Hashes**
- Identical passwords → identical hashes
- Vulnerable to rainbow table attacks

**Weak Hashing**
- Fast algorithms (e.g., raw SHA-256) allow brute-force attacks

**Salting Mitigation**
- Unique salt per password
- Attackers must crack each hash individually, increasing effort and cost

---

> **Why This Matters** :mag_right:
> Compromised password databases are a leading cause of account takeover. Proper salting significantly reduces offline cracking effectiveness.

---

## Attack Scenario 

**Unsalted Passwords**
- Attacker obtains DB → identical hashes
- Rainbow tables recover weak passwords quickly
- High credential exposure risk

**Salted Passwords**
- Attacker obtains DB → unique hash per password
- Rainbow tables fail
- Each hash must be brute-forced individually → higher time/cost

---

## Security Considerations :thought_balloon:
- Salting **does not prevent brute-force attacks** but increases computational cost.
- **SHA-256 is for demonstration only**; not suitable for production.
- Recommended to use **memory-hard algorithms** like Argon2 in real systems.

---

## Standards Alignment (NIST)
Aligned with **NIST SP 800-63B – Digital Identity Guidelines**:  
- Never store plaintext passwords  
- Use salted & hashed storage  
- Avoid fast, unsalted hashing algorithms  
- Apply modern password hashing techniques  

*This project demonstrates these principles in a safe, educational environment.*

---

## Implementation Overview
- Salt passwords before hashing
- Verify user input against stored salted hashes
- Lightweight Python scripts for hands-on experimentation

---

## How to Run :computer:
1. Clone the repository  
2. Run the demo: `python_salt_demo.py`  
3. Enter a password to generate a salted hash  
4. Verify the password when prompted

---

## Learning Outcomes
- Understand **importance of salting**  
- Gain experience with **hashing & salting in Python**  
- Develop **threat awareness** around password compromise

---

## Optional Enhancements
- Replace SHA-256 with **Argon2**, **bcrypt**, or **PBKDF2**  
- Add unit tests for verification logic  
- Compare salted vs unsalted hashes  
- Log authentication attempts for analysis

---

> **Security Disclaimer** :warning:
> Educational use only. Do not deploy in production.

---

## References
- NIST, *Digital Identity Guidelines (SP 800-63B)*: https://pages.nist.gov/800-63-3/sp800-63b.html  
- AuditBoard, *NIST Password Guidelines*: https://auditboard.com/blog/nist-password-guidelines
