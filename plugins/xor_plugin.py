from .base_plugin import BaseEncryptionPlugin

class XOREncryptionPlugin(BaseEncryptionPlugin):
    
    @property
    def name(self) -> str:
        return "XOR"
    
    @property
    def description(self) -> str:
        return "XOR encryption plugin"
    
    @property
    def author(self) -> str:
        return "Metros Software"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def encrypt(self, data: bytes, key: str) -> bytes:
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
            
        # Extend key to match data length
        key_extended = key * (len(data) // len(key) + 1)
        key_extended = key_extended[:len(data)]
        
        # Perform XOR operation
        return bytes(a ^ b for a, b in zip(data, key_extended))
    
    def decrypt(self, data: bytes, key: str) -> bytes:
        # XOR is symmetric, so encryption and decryption are the same
        return self.encrypt(data, key) 