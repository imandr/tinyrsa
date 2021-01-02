from tinyrsa.rnd import read_random_int, read_random_bytes
from tinyrsa.keys import to_b64, from_b64
    
import hashlib, base64

class RSA(object):
    
    def __init__(self, key):
        self.Key = key

    def pad(self, data):
        z = 0
        while z == 0:
            z = read_random_int(8)
        return int.from_bytes(bytes([z]) + data, byteorder="big", signed=False)
        
    def unpad(self, x):
        data_bytes = (x.bit_length()+7)//8
        return x.to_bytes(data_bytes, byteorder="big")[1:]
        
    def rsa(self, x, e, n):
        ys = []
        x0 = x
        while x:
            x, r = divmod(x, n)
            yy = pow(r, e, n)
            #print("rsa: r:", r, " -> yy:", yy)
            ys.append(yy)
        y = 0
        for yy in ys[::-1]:
            y = y * n + yy
        #print("rsa: %x -> %x" % (x0, y))
        return y
        
    def encrypt(self, data, key=None):
        if key is None: key = self.Key      # use public key by default
        x = self.pad(data)
        e, n = key.E, key.N
        y = self.rsa(x, e, n)
        y_bytes = (y.bit_length() + 7)//8
        return y.to_bytes(y_bytes, byteorder="big")
        
    def decrypt(self, data, key=None):
        if key is None: key = self.Key.private_key()    # use private key by default
        y = int.from_bytes(data, byteorder="big")
        #print("decrypt: y bits:", y.bit_length())
        d, n = key.E, key.N
        x = self.rsa(y, d, n)
        return self.unpad(x)
        
    SIGNATURE_SALT = 64 # bytes
    
    def hash_data(self, h, data_source):
        if isinstance(data_source, str):
            data_source = data_source.encode("utf-8")
        if isinstance(data_source, bytes):
            h.update(data_source)
        elif hasattr(data_source, "read"):
            data = b" "
            while data:
                data = data_source.read(8*1024)
                if data:
                    h.update(data)
        else:
            for data in data_source:
                h.update(data)

    def sign(self, data_source, hash_metbhod="sha3_256"):
        salt = read_random_bytes(self.SIGNATURE_SALT)
        h = hashlib.new(hash_metbhod)
        h.update(salt)
        self.hash_data(h, data_source)
        digest = h.digest() + salt
        signed = base64.b64encode(self.encrypt(digest, self.Key.private_key()))
        return hash_metbhod + ":" + signed.decode("utf-8")
    
    def verify_signature(self, data_source, signature):
        assert isinstance(signature, str)
        method, encrypted_digest = signature.split(":", 1)
        encrypted_digest = base64.b64decode(encrypted_digest)
        digest = self.decrypt(encrypted_digest, self.Key.public_key())
        h = hashlib.new(method)
        hash, salt = digest[:h.digest_size], digest[h.digest_size:]
        h = hashlib.new(method)
        h.update(salt)
        self.hash_data(h, data_source)
        return hash == h.digest()
        
if __name__ == "__main__":
    
    from keys import KeyPair
    from rnd import read_random_bytes
    import random
    
    k = KeyPair.generate(256)
    
    print("key pair:", k.as_json())
    print("public key:", k.public_key("key").as_json())
    
    r = RSA(k)

    print ("encrypting/decrypting ...")
    
    for _ in range(1000):
        N = 1024
        nzeros = random.randint(0,5)
        m = bytes([0]*nzeros) + read_random_bytes(N-nzeros)
    
        c = r.encrypt(m)
        #print("extra:", e)
        #if len(c) != len(m):
        #    print (len(m), nzeros, "->", len(c))
    
        mm = r.decrypt(c)
    
        if m != mm:
            print("error") 
    
    print ("signing/verifying ...")
    
    r1 = RSA(k.public_key())
    
    for _ in range(1000):
        N = 1024
        m = read_random_bytes(N)
        s = r.sign(m)
        #print("signature:", s)
        if random.random() < 0.5:
            v = r1.verify_signature(m, s)
            if not v:
                print("Invalid signature")
        else:
            m = [x for x in m]
            m[random.randint(0, len(m)-1)] ^= 1
            m = bytes(m)
            v = r1.verify_signature(m, s)
            if v:
                print("Undetected forgery")
            
        
        
                
            
        
        
        
            