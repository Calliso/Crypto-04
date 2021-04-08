from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.exceptions import InvalidSignature


class Asymmetric:
    """
    asymmetric cryptography functions
    """

    def __init__(self):
        self.keys = {}
        self.public_key = None
        self.private_key = None

    def random_rsa(self):
        """
        Generates PEM keys
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        self.keys['private'] = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()

        self.keys['public'] = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()

    def random_ssh(self):
        """
        Generates SSH keys
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        self.keys['private'] = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()

        self.keys['public'] = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).hex()

    def create_pem_keys(self):
        """
        creates keys (PEM encoding)
        """
        self.random_rsa()

        return self.keys

    def create_ssh_keys(self):
        """
        creates keys (SSH encoding)
        """
        self.random_ssh()

        return self.keys

    def set_keys(self, public_key, private_key):

        check = True
        try:
            self.keys['public'] = public_key
            self.keys['private'] = private_key
            self.public_key = serialization.load_pem_public_key(
                bytes.fromhex(self.keys['public']))
            self.private_key = serialization.load_pem_private_key(
                bytes.fromhex(self.keys['private']), password=None)
        except ValueError as ve:
            self.random_rsa()
            check = False

        return check

    def sign_message(self, message):

        signature = ''
        try:
            signature = self.private_key.sign(
                message.encode('UTF-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            ).hex()
        except ValueError as ve:
            signature = message

        return signature

    def verify_message(self, message, signature):
        """
        Verifies message's siganture

        Args:
            message (str): message to verify
            signature (str): signature

        Returns:
            status: returns True if verification passed
        """
        status = True

        try:
            verification = self.public_key.verify(
                bytes.fromhex(signature),
                message.encode('UTF-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except (InvalidSignature, ValueError):
            status = False

        return status

    def encode_message(self, message):
        """Encode given message

        Args:
            message (str): decoded message
        Returns:
            encrypted_message: encoded message
        """
        encrypted_message = ''

        try:
            encrypted_message = self.public_key.encrypt(message.encode('UTF-8'), padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )).hex()
        except ValueError:
            encrypted_message = message

        return encrypted_message

    def decode_message(self, message):
        """
        Decodes given message

        Args:
            message (str): Encoded message

        Returns:
            decrypted_message: decoded message.
        """
        decrypted_message = ""
        try:
            decrypted_message = self.private_key.decrypt(bytes.fromhex(message), padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )).decode('utf-8')

        except ValueError as e:
            decrypted_message = message

        return decrypted_message
