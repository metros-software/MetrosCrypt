from abc import ABC, abstractmethod

class BaseEncryptionPlugin(ABC):
    """Base class for encryption plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the encryption method"""
        raise NotImplementedError
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Returns the description of the encryption method"""
        raise NotImplementedError
    
    @abstractmethod
    def encrypt(self, data: bytes, key: str) -> bytes:
        """Encrypts the data using the provided key"""
        raise NotImplementedError
    
    @abstractmethod
    def decrypt(self, data: bytes, key: str) -> bytes:
        """Decrypts the data using the provided key"""
        raise NotImplementedError
    
    @property
    def author(self) -> str:
        """Returns the author of the plugin"""
        raise NotImplementedError
    
    @property
    def version(self) -> str:
        """Returns the version of the plugin"""
        raise NotImplementedError
    
    @property
    def requires_key(self) -> bool:
        """Returns whether this encryption method requires a key"""
        return True 