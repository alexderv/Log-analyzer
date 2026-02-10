# Log-analyzer
A lightweight Python CLI tool for analyzing system and authentication logs.   It parses log files, detects suspicious patterns like failed logins and brute-force bursts, and generates structured CSV and HTML reports for easy review.  This project was built as a hands-on exercise in log parsing, pattern detection, and automated reporting.

# 🔍

This is a lightweight Python CLI tool for analyzing system and authentication logs.  
It detects suspicious activity such as failed login attempts, brute-force bursts, and error spikes, then generates structured reports for quick review.

This project was built to demonstrate practical skills in log parsing, pattern detection, and automated reporting — core tasks in IT operations, cybersecurity, and system administration.

---

## 🚀 Features

- Parses `.log`, `.txt`, and `.csv` files recursively
- Detects:
  - Failed logins
  - Successful logins
  - Errors / exceptions
  - Brute-force bursts (rapid failures)
- Identifies:
  - Top offending IP addresses
  - Targeted usernames
  - Activity timeline
- Generates:
  - 📄 CSV structured dataset
  - 🌐 HTML visual dashboard
- Includes demo log generator for testing

