from flask_limiter import Limiter
from models.users import default_user
from flask_limiter.util import get_remote_address

default_user()

limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["10 per day", "50 per hour"])
