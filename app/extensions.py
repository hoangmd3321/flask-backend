import logging
import os

import redis
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from logging.handlers import RotatingFileHandler

jwt = JWTManager()

# init SQLAlchemy
db = SQLAlchemy()

os.makedirs("logs", exist_ok=True)
app_log_handler = RotatingFileHandler('logs/app.log', maxBytes=1000000, backupCount=30)

# logger
logger = logging.getLogger('api')
logger.setLevel(logging.DEBUG)
logger.addHandler(app_log_handler)

# redis
# red = redis.StrictRedis(host='mayno-prd.mip1ht.0001.apse1.cache.amazonaws.com', port=6379, db=0)
