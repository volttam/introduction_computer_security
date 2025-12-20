
from pathlib import Path
from loggers.logger import logger


class FileManager:
    def __init__(self, file_path: str | Path):
        logger.info(f"Initializing file manager with {file_path}")
        self.file_path = Path(file_path)

    def save_text_file_to_list(self, delimiter: str = "\n") -> list[str]:
        """
        Read a text file and return its contents as a list,
        split by the given delimiter.
        :param delimiter: delimiter used to split entries
        :return: list of elements
        """
        logger.info(f"Reading text file: {self.file_path}")
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        with self.file_path.open("r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        items = [item.strip() for item in content.split(delimiter) if item.strip()]
        return items
