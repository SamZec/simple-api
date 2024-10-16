#!/bin/python3
"""Blocked token module"""
from models.base import Base


class TokenBlocklist(Base):
    """blocked tokens class"""
    def __init__(self, *args, **kwargs):
        """Intatiate TokenBlocklist object"""
        super().__init__(*args, **kwargs)
        self.jti = kwargs.get('jti')
