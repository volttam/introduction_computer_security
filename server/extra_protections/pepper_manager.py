



class PepperManager:
    def __init__(self, pepper_enabled: bool, pepper_value: str):
        self.pepper_enabled = pepper_enabled
        self.pepper_value = pepper_value

    def get_peppered_password_if_enabled(self, password: str) -> str:
        """
        Return the password combined with a pepper if enabled
        """
        if not self.pepper_enabled:
            return password
        return f"{password}{self.pepper_value}"


    def get_peppered_password(self, password: str) -> str:
        """
        Return peppered password
        :param password:
        :return:
        """
        return f"{password}{self.pepper_value}"
