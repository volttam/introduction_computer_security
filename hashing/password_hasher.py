from abc import ABC, abstractmethod
from logger import get_logger

class PasswordHasher(ABC):
    """
    Abstract base class for password hashing strategies.
    """

    @staticmethod
    @abstractmethod
    def hash_password(password: str) -> str:
        """
        Hash a plaintext password and return a stored hash.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def verify_password(*args, **kwargs) -> bool:
        """
        Verify a plaintext password against a stored hash.
        """
        raise NotImplementedError

