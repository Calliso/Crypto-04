from cryptography.fernet import Fernet, InvalidToken


class Symmetric:
    """
    symmetric cryptography functions
    """
    def __init__(self):
        self.key = ''
        self.create_key()

    def create_key(self):
        """
        creates random key

        Returns:
           key: Random generated key
        """
        key = Fernet.generate_key().hex()
        return key

    def set_key(self, value):
        """
        sets key value given by user

        Args:
            value (str): symmetric key given by user

        Returns:
            status: Informs if key was set successful
        """
        status = True
        try:
            value = bytes.fromhex(value)
            f = Fernet(value)
            self.key = value
        except ValueError as e:
            status = False

        return status

    def encode_message(self, message):
        """
        encodes given message

        Args:
            message (str): message to endode

        Returns:
            encrypted_message: encrypted message
        """

        encrypted_message = ''
        try:
            f = Fernet(self.key)
            encrypted_message = f.encrypt(message.encode('UTF-8')).hex()
        except ValueError as e:
            encrypted_message = message

        return encrypted_message

    def decode_message(self, message):
        """
        decodes given message

        Args:
            message (str): message to decode

        Returns:
            decrypted_message: decrypted message
        """
        decrypted_message = "Incorrect value"

        try:
            f = Fernet(self.key)
            decrypted_message = f.decrypt(bytes.fromhex(message)).decode('utf-8')
        except (ValueError, InvalidToken):
            decrypted_message = message

        return decrypted_message