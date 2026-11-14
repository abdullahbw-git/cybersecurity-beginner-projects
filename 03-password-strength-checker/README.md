
# Password Strength Checker

## Project Overview

A beginner-friendly Python cybersecurity application
that evaluates password strength using basic security
rules and character analysis.

## Features

- Password length checking
- Lowercase letter detection
- Uppercase letter detection
- Number detection
- Special character detection
- Common password detection
- Simple sequence detection
- Repeated character detection
- Password scoring
- WEAK, MEDIUM and STRONG classification

## Technologies Used

- Python 3
- getpass
- Regular Expressions (re)

## Installation

Python 3 is required.

No third-party Python packages are needed.

## How to Run

1. Open the project folder in VS Code.
2. Open the terminal.
3. Run:

   python password_checker.py

4. Enter a fictional test password.
5. Review the analysis report.

## Scoring System

- WEAK: 0–39
- MEDIUM: 40–74
- STRONG: 75–100

## Privacy

The application hides password input using Python's
getpass module.

It does not send passwords to external services
or save them to files.

## Limitations

This project uses basic educational rules.

It does not calculate password entropy, check breached
password databases, or guarantee that a password is
secure.

## Learning Outcomes

- Python functions
- Password security
- Authentication concepts
- Regular expressions
- Conditional statements
- Basic security assessment

## Disclaimer

Created for educational and defensive cybersecurity
learning purposes.
