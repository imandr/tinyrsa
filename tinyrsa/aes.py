import secrets, Crypto, hashlib, struct              # pycrypto is requred
from Crypto.Cipher import AES as _AES

class AES(object):
    
    HEAD_PAD = 64
    
    def __init__(self, key=None, iv=None):
        import secrets, Crypto              # pycrypto is requred
        if key is None:
            key = secrets.token_bytes(16)   # AES uses 16 bytes key
        elif isinstance(key, str):
            # very weak !
            h = hashlib.new("sha256")
            h.update(key.encode("utf-8"))
            key = h.digest()[:16]
        assert isinstance(key, bytes) and len(key) == 16
        self.Key = key
        iv = iv or secrets.token_bytes(16)
        self.init(key, iv)
        
    def init(self, key, iv):
        self.Cipher = _AES.new(key, _AES.MODE_CBC, iv)
        self.IV = iv
        self.InBytes = self.OutBytes = 0
        self.RemoveHead = True
        self.Head = secrets.token_bytes(self.HEAD_PAD)
        
    def encrypt(self, data):
        import secrets, Crypto              # pycrypto is requred
        if isinstance(data, str):
            data = data.encode("utf-8")
        l = len(data)
        self.InBytes += l
        padded_l = ((l+15)//16)*16
        pad_l = padded_l - l
        padded_data = data + secrets.token_bytes(pad_l) if pad_l > 0 else data
        padded_data = self.Head + padded_data
        self.Head = b''
        #print("encrypt: padded_data:", len(padded_data))
        encrypted = self.Cipher.encrypt(padded_data)
        self.OutBytes += len(encrypted)
        return encrypted
        
    def decrypt(self, encrypted):
        if isinstance(encrypted, str):   encrypted = encrypted.encode("utf-8")
        self.InBytes += len(encrypted)
        data = self.Cipher.decrypt(encrypted)
        if self.RemoveHead:
            data = data[self.HEAD_PAD:]
            self.RemoveHead = False
        self.OutBytes += len(data)
        return data       
        
    BLOCK_SIZE = 8*1024
        
    def encrypt_file_stream(self, f):
        eof = False
        while not eof:
            data = f.read(self.BLOCK_SIZE)
            if data:
                yield self.encrypt(data)
            else:
                eof = True
        #print("In/out bytes:", self.InBytes, self.OutBytes)
                
    def decrypt_file_stream(self, f, length):
        eof = False
        while not eof and length > 0:
            data = f.read(self.BLOCK_SIZE)
            if data:
                decrypted = self.decrypt(data)
                l = min(len(decrypted), length)
                #print("decrypted length, l:", len(decrypted), l)
                yield decrypted[:l]
                length -= l
            else:
                eof = True
        #print("In/out bytes:", self.InBytes, self.OutBytes)
                
    HEADER_LENGTH = 8+16
                
    def encrypt_file(self, inp, out):
        #
        # header:
        # original length, 128 bytes, big endian
        # IV, 8 bytes
        # (encrypted data)
        #
        start = out.tell()
        out.seek(start+self.HEADER_LENGTH)
        for block in self.encrypt_file_stream(inp):
            out.write(block)
        out.truncate()
        out.seek(start)
        out.write(self.InBytes.to_bytes(8, byteorder="big"))
        out.write(self.IV)
        out.seek(0, 2)
        return self.InBytes

    def decrypt_file(self, inp, out):
        length = int.from_bytes(inp.read(8), byteorder="big")
        #print("decrypt:length:", length)
        iv = inp.read(16)
        self.init(self.Key, iv)
        for block in self.decrypt_file_stream(inp, length):
            out.write(block)
        return self.OutBytes
        
                
if __name__ == "__main__":
    import sys
    
    # header
    
    command, key, inp, out = sys.argv[1:]
    aes = AES(key)
    inp = open(inp, "rb")
    out = open(out, "wb")
    
    if command == "encrypt":
        print(aes.encrypt_file(inp, out))
    else:
        print(aes.decrypt_file(inp, out))
            
        
        
        
        
