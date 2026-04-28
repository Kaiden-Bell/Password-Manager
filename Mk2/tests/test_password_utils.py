"""
test_password_utils.py - tests for password_utils.py

Run with:
    python -m pytest tests/test_password_utils.py -v

"""

import pytest
from app.password_utils import (
    generate_password,
    check_password_strength,
    current_date_string,
)

@pytest.mark.parametrize("length, should_raise", [
    (8, False),
    (128, False),
    (7, True),
    (129, True),
])

def test_generate_password_length_bounds(length, should_raise):
    """Test password length bounds."""
    if should_raise:
        with pytest.raises(ValueError):
            generate_password(length=length)
    else:
        assert len(generate_password(length=length)) == length


@pytest.mark.parametrize("flag, charset", [
    ("use_upper",   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("use_lower",   "abcdefghijklmnopqrstuvwxyz"),
    ("use_digits",  "0123456789"),
    ("use_symbols", "!@#$%^&*()_+-=[]{}|;:,.<>?"),
])

def test_generate_password_single_charset(flag, charset):
    """Test password generation with a single character set."""
    kwargs = {k: False for k in ("use_upper", "use_lower", "use_digits", "use_symbols")}
    kwargs[flag] = True
    pw = generate_password(length=32, **kwargs)
    assert all(c in charset for c in pw)
