#!/usr/bin/env python3
""" Base module
"""
from datetime import datetime
from typing import TypeVar, List, Iterable
from os import path
import json
import uuid


TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"


class Base():
    """ Base class
    """

    def __init__(self, *args: list, **kwargs: dict):
        """ Initialize a Base instance
        """
        self.id = kwargs.get('id', str(uuid.uuid4()))
        if kwargs.get('created_at') is not None:
            self.created_at = datetime.strptime(kwargs.get('created_at'),
                                                TIMESTAMP_FORMAT)
        else:
            self.created_at = datetime.utcnow()
        if kwargs.get('updated_at') is not None:
            self.updated_at = datetime.strptime(kwargs.get('updated_at'),
                                                TIMESTAMP_FORMAT)
        else:
            self.updated_at = datetime.utcnow()

    def __eq__(self, other: TypeVar('Base')) -> bool:
        """ Equality
        """
        if type(self) != type(other):
            return False
        if not isinstance(self, Base):
            return False
        return (self.id == other.id)

    def to_json(self, for_serialization: bool = False) -> dict:
        """ Convert the object a JSON dictionary
        """
        result = {}
        for key, value in self.__dict__.items():
            if not for_serialization and key[0] == '_':
                continue
            if type(value) is datetime:
                result[key] = value.strftime(TIMESTAMP_FORMAT)
            else:
                result[key] = value
        return result

    @classmethod
    def load_from_file(cls):
        """ Load all objects from file
        """
        s_class = cls.__name__
        JSON = {s_class: []}
        file_path = ".db_{}.json".format(s_class)
        if not path.exists(file_path):
            return

        with open(file_path, 'r') as f:
            objs_json = json.load(f)
            for item in objs_json:
                for obj_id, obj_json in item.items():
                    JSON[s_class].append(cls(**obj_json))
        return JSON

    @classmethod
    def path(cls):
        """check for file existence
        """
        file_path = ".db_{}.json".format(cls.__name__)
        return path.exists(file_path)

    @classmethod
    def save_to_file(cls, DATA: dict = {}):
        """ Save all objects to file
        """
        s_class = cls.__name__
        if DATA is None:
            DATA[s_class] = [{cls.id: cls}]
        file_path = ".db_{}.json".format(s_class)
        objs_json = {}
        l_objs = []

        for item in DATA[s_class]:
            for obj_id, obj in item.items():
                objs_json[obj_id] = obj.to_json(True)

        if path.exists(file_path) and path.getsize(file_path) != 0:
            with open(file_path, 'r') as f:
                l_objs = json.load(f)

        with open(file_path, 'w') as f:
            l_objs.append(objs_json)
            json.dump(l_objs, f)

    @classmethod
    def update_file(cls, objs: list):
        """update the content of file"""
        s_class = cls.__name__
        file_path = ".db_{}.json".format(s_class)
        l_objs = []

        for item in objs:
            objs_json = {item.id: item.to_json(True)}
            l_objs.append(objs_json)

        with open(file_path, 'w') as f:
            json.dump(l_objs, f)

    def save(self):
        """ Save current object
        """
        s_class = self.__class__.__name__
        self.updated_at = datetime.utcnow()
        DATA = {s_class: [{self.id: self}]}
        self.__class__.save_to_file(DATA)

    def update(self):
        """update object"""
        objs = self.__class__.all()
        for indx, obj in enumerate(objs):
            if self.id == obj.id:
                self.updated_at = datetime.utcnow()
                objs[indx] = self
                break
        self.__class__.update_file(objs)

    def remove(self):
        """ Remove object
        """
        objs = self.__class__.all()
        for item in objs:
            if item == self:
                objs.remove(item)
                self.__class__.update_file(objs)
                break

    @classmethod
    def count(cls) -> int:
        """ Count all objects
        """
        objs = cls.all()
        return len(objs[:]) if objs else 0

    @classmethod
    def all(cls) -> Iterable[TypeVar('Base')]:
        """ Return all objects
        """
        return cls.search()

    @classmethod
    def get(cls, id: str) -> TypeVar('Base'):
        """ Return one object by ID
        """
        objs = cls.all()
        for item in objs:
            if item.id == id:
                return item
        return None

    @classmethod
    def search(cls, attributes: dict = {}) -> List[TypeVar('Base')]:
        """ Search all objects with matching attributes
        """
        s_class = cls.__name__
        JSON = cls.load_from_file()
        if not JSON:
            return None
        def _search(obj):
            if len(attributes) == 0:
                return True
            for k, v in attributes.items():
                if (getattr(obj, k) != v):
                    return False
            return True

        return list(filter(_search, (i for i in JSON[s_class])))
