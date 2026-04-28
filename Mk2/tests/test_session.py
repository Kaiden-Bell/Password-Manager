"""
test_session.py — Session manager unit tests

run via python3 -m pytest tests/test_session.py

"""

import pytest
from unittest.mock import patch
import time
import app.session

# -------------------
# Fixtures          |
# -------------------

def test_create_session():
    """
    Test that a new session is created correctly.
    """
    session = app.session.create_session(
        user_id=1,
        vault_id=1,
        auth_method='password',
        decrypted_vault={"test":"test"},
        master_key=b"test"
    )
    assert session.get('active_user_id') == 1
    assert session.get('active_vault_id') == 1
    assert session.get('auth_method') == 'password'
    assert session.get('decrypted_vault') == {"test":"test"}
    assert session.get('vault_master_key') == b"test"
    assert session.get('is_unlocked') is True
    assert session.get('last_activity') is not None

def test_is_unlocked():
    """
    Test that is_unlocked returns True for an unlocked session.
    """
    session = app.session.create_session(
        user_id=1,
        vault_id=1,
        auth_method='password',
        decrypted_vault={"test":"test"},
        master_key=b"test"
    )
    assert app.session.is_unlocked(1) is True

def test_get_session():
    """
    Test that get_session returns the session for a vault.
    """
    session = app.session.create_session(
        user_id=1,
        vault_id=1,
        auth_method='password',
        decrypted_vault={"test":"test"},
        master_key=b"test"
    )
    assert app.session.get_session(1) == session

def test_touch_session():
    """
    Test that touch_session updates the last_activity timestamp.
    """
    with patch('time.time', return_value=1000.0):
        session = app.session.create_session(
            user_id=1,
            vault_id=1,
            auth_method='password',
            decrypted_vault={"test":"test"},
            master_key=b"test"
        )
    assert session['last_activity'] == 1000.0

    with patch('time.time', return_value=1002.0):
        app.session.touch_session(1)
        assert app.session.is_unlocked(1) is True
        assert app.session.get_session(1)['last_activity'] == 1002.0

def test_lock_session():
    """
    Test that lock_session locks the session.
    """
    session = app.session.create_session(
        user_id=1,
        vault_id=1,
        auth_method='password',
        decrypted_vault={"test":"test"},
        master_key=b"test"
    )
    app.session.lock_session(1)
    assert app.session.is_unlocked(1) is False

def test_expire_old_sessions():
    """
    Test that expire_old_sessions expires old sessions.
    """
    with patch('time.time', return_value=1000.0):
        session = app.session.create_session(
            user_id=1,
            vault_id=1,
            auth_method='password',
            decrypted_vault={"test":"test"},
            master_key=b"test"
        )

    with patch('time.time', return_value=1006.0):
        app.session.expire_old_sessions()
        assert app.session.is_unlocked(1) is False

def test_clear_secrets():
    """
    Test that clear_secrets clears the session secrets.
    """
    session = app.session.create_session(
        user_id=1,
        vault_id=1,
        auth_method='password',
        decrypted_vault={"test":"test"},
        master_key=b"test"
    )
    app.session.clear_secrets(1)
    raw_session = app.session._sessions.get(1)
    assert raw_session['decrypted_vault'] is None
    assert raw_session['vault_master_key'] is None
    assert raw_session['is_unlocked'] is False

def test_open_passphrase_window():
    """
    Test that open_passphrase_window opens the passphrase window.
    """
    app.session.open_passphrase_window(1)
    assert app.session.is_passphrase_window_active(1) is True

def test_is_passphrase_window_active():
    """
    Test that is_passphrase_window_active returns True for an active window.
    """
    app.session.open_passphrase_window(1)
    assert app.session.is_passphrase_window_active(1) is True

def test_close_passphrase_window():
    """
    Test that close_passphrase_window closes the passphrase window.
    """
    app.session.open_passphrase_window(1)
    app.session.close_passphrase_window(1)
    assert app.session.is_passphrase_window_active(1) is False