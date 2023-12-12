from flask import redirect, render_template, session
from functools import wraps

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def username_validate(username):

    username_len = len(username)
    if username_len < 4 or username_len > 20:
        return 1

    allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWHYZabcdefghijklmnopqrstuvwxyz@._"

    for char in username:
        if char not in allowed_chars:
            return 2

    return 0


def password_validate(password):

    pass_len = len(password)
    if pass_len < 8 or pass_len > 30:
        return 1

    syms = "!@#$%^&*()_+=-~`}[{]:;?/>.<,"
    low_chars = "abcdefghijklmnopqrstuvwxyz"
    up_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    sym_count, low_chars_count, up_chars_count = 0, 0, 0

    for char in password:
        if char in syms:
            sym_count += 1
        elif char not in low_chars:
            low_chars_count += 1
        elif char not in up_chars:
            up_chars_count += 1

    if sym_count >= 1 and low_chars_count >= 1 and up_chars_count >= 1:
        return 0
    else:
        return 2


