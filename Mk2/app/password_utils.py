"""
password_utils.py — Password generation and strength checking utilities.
"""

import secrets
from datetime import date

def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
        Desc: Generate a random secure password.
        Arguments: length, use_upper, use_lower, use_digits, use_symbols
        Returns: str, the generated password
    """
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not (use_upper or use_lower or use_digits or use_symbols): raise ValueError("At least one character set must be enabled.")
    
    if length < 8 or length > 128: raise ValueError("Password length must be between 8 and 128 characters.")

    character_pool = ""

    if use_upper: character_pool += upper
    if use_lower: character_pool += lower
    if use_digits: character_pool += digits
    if use_symbols: character_pool += symbols

    password = ""
    for _ in range(length):
        password += secrets.choice(character_pool)

    return password


def check_password_strength(password: str) -> dict:
    """
        Desc: Evaluate the strength of a password
        Arguments: password
        Returns: dict, score and feedback
    """
    score = 0
    feedback = []

    if len(password) >= 8: score += 1
    else: feedback.append("Password is too short.")

    if any(c.isupper() for c in password): score += 1
    else: feedback.append("Add uppercase letters.")

    if any(c.islower() for c in password): score += 1
    else: feedback.append("Add lowercase letters.")

    if any(c.isdigit() for c in password): score += 1
    else: feedback.append("Add digits.")

    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): score += 1
    else: feedback.append("Add special characters.")

    score = min(score - 1, 4) if score > 0 else 0

    if score == 0:
        label = "Very Weak"
    elif score == 1:
        label = "Weak"
    elif score == 2:
        label = "Fair"
    elif score == 3:
        label = "Strong"
    else:
        label = "Very Strong"

    return {
        "score": score,
        "label": label,
        "feedback": feedback
    }

def current_date_string() -> str:
    return date.today().isoformat()
