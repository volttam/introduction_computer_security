
from db_manager import DBManager
from logger import get_logger
from settings.settings import

class Context:
    def __init__(self):
        self.db_manager = DBManager()
        self.logger = get_logger("logger")

