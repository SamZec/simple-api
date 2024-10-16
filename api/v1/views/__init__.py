from flask import Blueprint
import logging


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app_views = Blueprint("app_views", __name__, url_prefix="/api/v1")
from api.v1.views.index import *
from api.v1.views.users import *
from api.v1.views.oauth2 import *
