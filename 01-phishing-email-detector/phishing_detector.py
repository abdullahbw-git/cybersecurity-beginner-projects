
import re
from urllib.parse import urlparse
from ipaddress import ip_address


# -----------------------------------
# 1. SUSPICIOUS EMAIL PHRASES
# -----------------------------------

SUSPICIOUS_PHRASES = [
    "verify your account",
    "account is suspended",
    "confirm your password",
    "urgent action required",
    "claim your prize",
    "password expires",
    "unusual activity",
    "payment failed"
]


# -----------------------------------
# 2. URL SHORTENER DOMAINS
# -----------------------------------

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd"
}


# -----------------------------------
# 3. URL EXTRACTION PATTERN
# -----------------------------------

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE
)


# -----------------------------------
# 4. EXTRACT URLS FROM TEXT
# -----------------------------------

def extract_urls(text):

    matches = URL_PATTERN.findall(text)

    urls = []

    for url in matches:

        url = url.rstrip(".,!?;:)]}")

        if url not in urls:
            urls.append(url)

    return urls


# -----------------------------------
# 5. CHECK IP ADDRESSES
# -----------------------------------

def is_ip_address(hostname):

    try:
        ip_address(hostname)
        return True

    except ValueError:
        return False


# -----------------------------------
# 6. MAIN EMAIL ANALYSIS ENGINE
# -----------------------------------

def analyze_email(subject, body):

    combined_text = (subject + " " + body).lower()

    score = 0
    findings = []

    # Check suspicious phrases

    matched_phrases = []

    for phrase in SUSPICIOUS_PHRASES:

        if phrase in combined_text:
            matched_phrases.append(phrase)

    score += min(len(matched_phrases) * 10, 30)

    for phrase in matched_phrases:

        findings.append(
            f"Suspicious phrase detected: {phrase}"
        )

    # Extract URLs

    urls = extract_urls(body)

    if not urls:
        findings.append("No HTTP/HTTPS URLs detected.")

    # Analyze URLs

    for url in urls:

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname

        except ValueError:

            score += 10
            findings.append("Malformed URL detected.")
            continue

        if not hostname:

            score += 10
            findings.append("Invalid URL hostname.")
            continue

        hostname = hostname.lower().rstrip(".")

        # Check HTTP links

        if parsed.scheme.lower() == "http":

            score += 5

            findings.append(
                f"Unencrypted HTTP link detected: {hostname}"
            )

        # Check IP address hostnames

        if is_ip_address(hostname):

            score += 20

            findings.append(
                f"IP address used as hostname: {hostname}"
            )

        # Check shortened URLs

        for domain in SHORTENER_DOMAINS:

            if (
                hostname == domain
                or hostname.endswith("." + domain)
            ):

                score += 20

                findings.append(
                    f"URL shortener detected: {hostname}"
                )

                break

        # Check internationalized domain patterns

        if hostname.startswith("xn--") or ".xn--" in hostname:

            score += 15

            findings.append(
                f"Internationalized domain pattern: {hostname}"
            )

        # Check embedded URL credentials

        if parsed.username is not None or parsed.password is not None:

            score += 15

            findings.append(
                "URL contains embedded login information."
            )

    # Maximum score = 100

    score = min(score, 100)

    # Risk classification

    if score >= 50:
        risk = "HIGH"

    elif score >= 20:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    return score, risk, findings, urls


# -----------------------------------
# 7. MAIN APPLICATION
# -----------------------------------

def main():

    print("\n================================")
    print("       PHISHING EMAIL DETECTOR")
    print("================================\n")

    sender = input("Enter sender email: ")

    subject = input("Enter email subject: ")

    print("\nEnter email body (one line):")

    body = input("> ")

    # Analyze the email

    score, risk, findings, urls = analyze_email(
        subject, body
    )

    # Display the report

    print("\n================================")
    print("          ANALYSIS REPORT")
    print("================================")

    print(f"\nSender: {sender}")

    print(f"Risk Score: {score}/100")

    print(f"Risk Level: {risk}")

    print("\nDetected URLs:")

    if urls:

        for url in urls:
            print(f"- {url}")

    else:
        print("No URLs found.")

    print("\nSecurity Findings:")

    for finding in findings:
        print(f"[!] {finding}")

    print("\n================================")
    print("Analysis completed.")
    print("A LOW score does not guarantee safety.")
    print("================================")


# -----------------------------------
# 8. START APPLICATION
# -----------------------------------

if __name__ == "__main__":
    main()
