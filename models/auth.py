#!/usr/bin/env python3
"""auth.py - Hash password"""

import os
import jwt
import bcrypt
import random, ssl
from uuid import uuid4
from smtplib import SMTP_SSL
from functools import wraps
from decouple import config
from models.users import User
from email.mime.text import MIMEText
from flask import make_response, session
from datetime import datetime, timedelta
from flask_jwt_extended import get_jwt_identity


SMTPserver = 'smtp.mail.yahoo.com'
USER_NAME = config('USER_NAME')
PASSWORD = config('PASSWORD')


def _hash_password(password: str) -> bytes:
    """ hash password """
    if password and type(password) == str:
        byte_password = bytes(password, 'utf-8')
        return bcrypt.hashpw(byte_password, bcrypt.gensalt())
    return None


def _generate_uuid() -> str:
    """return a string representation of a new UUID"""
    return str(uuid4())


def auth_role(role):
    """wrapper fucntion to authenticate with roles"""
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            user = User.search({'email': get_jwt_identity().get('email')})
            if not user:
                return make_response(
                        {'message': 'Unathorized User'}, 403)
            roles = role if isinstance(role, list) else [role]
            if all(not user[0].has_role(r) for r in roles):
                return make_response(
                {'message': f"Missing roles in [{', '.join(roles)}]"}, 403)
            return fn(*args, **kwargs)
        return decorator
    return wrapper


class Auth:
    """Auth class to interact with the authentication database.
    """

    def register_user(self,first_name: str,
                      last_name: str, email: str, password: str) -> User:
        """return a User object."""
        user = User.search({'email': email})
        if type(password) is not str:
            raise AttributeError('password must be string')
        if not user:
            hashed_password = _hash_password(password)
            password = hashed_password.decode('utf-8')
            user = User(first_name=first_name, last_name=last_name,
                        email=email, password=password)
            try:
                user.save()
            except Exception as e:
                 raise ValueError(f"{e}")
            return user
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """validates login"""
        user = User.search({'email': email})
        if type(password) is not str:
            raise AttributeError('password must be string')
        if not user:
            return False
        if not password:
            return False
        byte_password = bytes(password, 'utf-8')
        hashed_password = bytes(user[0].password, 'utf-8')
        if bcrypt.checkpw(byte_password, hashed_password):
            return True
        return False


    def email_verification(self, receiver_email: str) -> str:
        """verify email"""
        email_check1 = ["gmail","hotmail","yahoo","outlook"]
        email_check2 = [".com",".in",".org",".edu",".co.in"]
        count = 0

        for domain in email_check1:
            if domain in receiver_email:
                count+=1
        for site in email_check2:
            if site in receiver_email:
                count+=1

        if "@" not in receiver_email or count!=2:
            return False
        return True


    def send_otp_code(self, email: str) -> int:
        """send OTP to email"""
        otp = random.randint(100000,999999)
        content = f"Your OTP Verification Code is {otp}"
        msg = MIMEText(content, 'plain')
        msg['subject'] = "SIMPLE API - IDEATION OTP Verification"
        msg['from'] = USER_NAME
        context = ssl.create_default_context()
        with SMTP_SSL(SMTPserver, 465, context=context) as server:
            server.login(USER_NAME, PASSWORD)
            server.sendmail(USER_NAME, email, msg.as_string())
            server.quit()
        return otp


    def create_session(self, email: str) -> str:
        """returns the session ID as a string."""
        user = User.search({'email': email})
        if not user:
            return None
        session_id = _generate_uuid()
        user[0].session_id=session_id
        user[0].update()
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """returns the corresponding User to session_id"""
        if session_id and type(session_id) == str:
            user = User.search({'session_id': session_id})
            if not user:
                return None
            return user[0]
        return None

    def destroy_session(self, user_id: int) -> None:
        """destroys a session by setting to None"""
        user = User.get(id=user_id)
        if not user:
            return False
        user.session_id = None
        user.update()
        return user.to_json()#True

    def get_reset_password_token(self, email: str) -> str:
        """get reset password token"""
        user = User.search({'email': email})
        if not user:
            raise ValueError
        reset_token = _generate_uuid()
        user[0].reset_token=reset_token
        user[0].update()
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """update password"""
        if not reset_token or not password:
            raise ValueError
        user = User.search({'reset_token': reset_token})
        if not user:
            raise ValueError
        hashed_password = _hash_password(password)
        user[0].password = hashed_password.decode('utf-8')
        user[0].reset_token=None
        user[0].update()
        return True
