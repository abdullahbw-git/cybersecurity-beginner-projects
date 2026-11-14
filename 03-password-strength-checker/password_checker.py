
import getpass
import re


# ---------------------------------------
# 1. COMMON PASSWORDS
# ---------------------------------------

COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "qwerty",
    "admin",
    "letmein",
    "welcome"
}


# ---------------------------------------
# 2. PASSWORD ANALYSIS FUNCTION
# ---------------------------------------

def analyze_password(password):

    score = 0
    findings = []

    # Check password length

    if len(password) >= 20:
        score += 55
        findings.append("Excellent password length.")

    elif len(password) >= 16:
        score += 40
        findings.append("Good password length.")

    elif len(password) >= 12:
        score += 25
        findings.append("Acceptable password length.")

    elif len(password) >= 8:
        score += 15
        findings.append("Password length could be improved.")

    else:
        findings.append("Password is too short.")

    # Check lowercase letters

    if any(char.islower() for char in password):

        score += 10
        findings.append("Lowercase letters detected.")

    else:
        findings.append("Add lowercase letters.")

    # Check uppercase letters

    if any(char.isupper() for char in password):

        score += 10
        findings.append("Uppercase letters detected.")

    else:
        findings.append("Add uppercase letters.")

    # Check numbers

    if any(char.isdigit() for char in password):

        score += 10
        findings.append("Numbers detected.")

    else:
        findings.append("Consider including numbers.")

    # Check special characters

    if any(
        not char.isalnum() and not char.isspace()
        for char in password
    ):

        score += 15
        findings.append("Special characters detected.")

    else:
        findings.append("Consider adding special characters.")

    # Check common passwords

    if password.lower() in COMMON_PASSWORDS:

        score -= 40

        findings.append(
            "Warning: This is a commonly used password."
        )

    # Check simple sequences

    simple_patterns = [
        "1234",
        "abcd",
        "qwerty"
    ]

    if any(
        pattern in password.lower()
        for pattern in simple_patterns
    ):

        score -= 10

        findings.append(
            "Warning: A predictable sequence was detected."
        )

    # Check repeated characters

    if re.search(r"(.)\1{3,}", password):

        score -= 10

        findings.append(
            "Warning: Repeated characters detected."
        )

    # Keep score between 0 and 100

    score = max(0, min(score, 100))

    # Classify password strength

    if score >= 75:

        strength = "STRONG"

    elif score >= 40:

        strength = "MEDIUM"

    else:

        strength = "WEAK"

    return score, strength, findings


# ---------------------------------------
# 3. MAIN APPLICATION
# ---------------------------------------

def main():

    print("\n================================")
    print("      PASSWORD STRENGTH CHECKER")
    print("================================")

    print("\nEnter a fictional test password.")
    print("Your input will remain hidden.\n")

    password = getpass.getpass(
        "Enter password: "
    )

    if not password:

        print("\nNo password entered.")
        return

    # Analyze password

    score, strength, findings = analyze_password(
        password
    )

    # Display report

    print("\n================================")
    print("       PASSWORD ANALYSIS REPORT")
    print("================================")

    print(f"\nPassword Score: {score}/100")

    print(f"Strength Level: {strength}")

    print("\nSecurity Findings:")

    for finding in findings:

        print(f"[+] {finding}")

    print("\n================================")

    print("Analysis completed.")

    print("Never reuse passwords across accounts.")

    print("================================")


# ---------------------------------------
# 4. START APPLICATION
# ---------------------------------------

if __name__ == "__main__":

    main()
