
from pathlib import Path
from loggers.logger import logger


class FileManager:

    BASE_DIR = Path(__file__).resolve().parent.parent
    BRUTE_FORCE_PASSWORDS_FILE_PATH = (BASE_DIR / "attempted_passwords" / "brute_force_passwords.txt")

    def __init__(self):
        logger.info(f"Initializing file manager")

    @staticmethod
    def __save_text_file_to_list(file_path: Path, delimiter: str = "\n") -> list[str]:
        """
        Read a text file and return its contents as a list,
        split by the given delimiter.
        :param delimiter: delimiter used to split entries
        :return: list of elements
        """
        logger.info(f"Reading text file: {file_path}")
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        items = [item.strip() for item in content.split(delimiter) if item.strip()]
        return items

    @property
    def get_brute_force_passwords(self) -> list[str]:
        return self.__save_text_file_to_list(self.BRUTE_FORCE_PASSWORDS_FILE_PATH)
