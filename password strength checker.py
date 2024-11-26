import re

def assess_password_strength(password):
    score = 0
    feedback = []

    # Length Check
    length = len(password)
    if length < 8:
        feedback.append("Password should be at least 8 characters long.")
    elif length >= 12:
        score += 2
    else:
        score += 1

    # Complexity Checks
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Add at least one digit.")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Add at least one special character.")

    # Uniqueness Check
    if len(set(password)) / length < 0.7:
        feedback.append("Avoid repeated characters to make your password stronger.")
    else:
        score += 1

    # Common Password Check (Basic Example)
    common_passwords = ["123456", "password", "qwerty", "abc123", "letmein"]
    if password.lower() in common_passwords:
        feedback.append("Avoid using common passwords.")
    else:
        score += 1

    # Determine Password Strength
    if score >= 7:
        strength = "Strong"
    elif 4 <= score < 7:
        strength = "Moderate"
    else:
        strength = "Weak"

    return {
        "strength": strength,
        "score": score,
        "feedback": feedback
    }

# Test the Function
password = input("Enter your password: ")
result = assess_password_strength(password)
print(f"Password Strength: {result['strength']}")
print(f"Score: {result['score']}/8")
print("Feedback:")
for comment in result['feedback']:
    print(f"- {comment}")
