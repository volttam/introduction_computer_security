



class PepperManager:
    def __init__(self, pepper_enabled: bool, pepper_value: str):
        self.pepper_enabled = pepper_enabled
        self.pepper_value = pepper_value

    def apply_pepper_if_activated(self, password: str) -> str:
        """
        Return the password combined with a pepper
        """
        if not self.pepper_enabled:
            return password
        return f"{password}{self.pepper_value}"
