#!/bin/python3
"""Users and Admins object module"""
from models.base import Base


class User(Base):
    "Users class object"
    def __init__(self, *args, **kwargs):
        """ Initialize a User instance
        """
        super().__init__(*args, **kwargs)
        self.first_name = kwargs.get('first_name')
        self.last_name = kwargs.get('last_name')
        self.email = kwargs.get('email')
        self.password = kwargs.get('password')
        self.session_id = kwargs.get('session_id')
        self.reset_token = kwargs.get('reset_token')


    def has_role(self, role=None):
        """check if a user has the assinged role"""
        set_role = SetRole.search({'user_id': self.id})
        if not set_role:
            return False
        roles = Role.search({'name': role})
        if roles and set_role:
            return any(roles[0].id == i.role_id for i in set_role)
        #if set_role:
        #    return True
        return False

    def unset_role(self, setrole_id):
        """remove a user from a role"""
        """
        get_role = Role.objects(name=role).first()
        if self.has_role(role) and get_role:
            obj = SetRole.objects(users=self).filter(roles=get_role).first()
            obj.delete()
            return True
        """
        setrole = SetRole.get(id=setrole_id)
        if setrole:
            setrole.remove()
            return True
        return False


class Role(Base):
    """Roles objects class"""
    def __init__(self, *args, **kwargs):
        """Intantiate Role object"""
        super().__init__(*args, **kwargs)
        self.name = kwargs.get('name')


class SetRole(Base):
    """Assigns a user to a role"""
    def __init__(self, *args, **kwargs):
        """Intantiate setrole object"""
        super().__init__(*args, **kwargs)
        #self.name = kwargs.get('name')
        self.role_id = kwargs.get('role_id')
        self.user_id =  kwargs.get('user_id')
