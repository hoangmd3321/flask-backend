# coding=utf-8
import os

ALLOWED_EXTENSIONS_FILES = {}
ALLOWED_EXTENSIONS_IMG = {'png', 'jpg', 'jpeg', 'gif'}
TIME_FORMAT_LOG = "[%Y-%b-%d %H:%M]"

URL_SERVER = "http://127.0.0.1:5012" if os.environ.get('DevConfig') == '1' else "http://127.0.0.1:5012"
FILE_PATH = "app/files/"
AVATAR_PATH = FILE_PATH + "avatars/"
AVATAR_PATH_SEVER = URL_SERVER + "/avatars/"

DEFAULT_AVATAR = "default_avatar.png"
DEFAULT_GROUP_AVATAR = "default_group_avatar.png"

# Order status
PENDING_CONFIRMATION = 0
DELIVERING = 1
SUCCESSFUL_DELIVERY = 2
CANCELED = 3

# Payment method
CASH = 0
BANKING = 1
MOMO = 2
ZALO_PAY = 3

# Delivery method
OWNER = 0
EXPRESS = 1
VIETTEL_POST = 2
