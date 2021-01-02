from tinyrsa.primes import generate_p_q, extended_gcd
from tinyrsa.rnd import read_random_bytes
    
import json, base64, hashlib, uuid

def to_b64(x):
    nbytes = (x.bit_length()+7)//8
    return base64.b64encode(x.to_bytes(nbytes, byteorder="big")).decode("utf-8")

def from_b64(b):
    return int.from_bytes(base64.b64decode(b), byteorder="big", signed=False)

class Key(object):

    def __init__(self, e, n, id):
        self.E = e
        self.N = n
        self.ID = id
        
    def as_jsonable(self):
        return dict(e=to_b64(self.E), n=to_b64(self.N), id=self.ID, type="key", 
                length=self.N.bit_length())
                
    def as_json(self):
        return json.dumps(self.as_jsonable(), indent=2)+"\n"
    
    @staticmethod
    def from_jsonable(obj):
        assert obj["type"] == "key"
        e = from_b64(obj["e"])
        n = from_b64(obj["n"])
        id = obj["id"]
        return Key(e, n, id)

    @staticmethod
    def from_json(text):
        dct = json.loads(text)
        if dct["type"] == "key":
            return Key.from_jsonable(dct)
        else:
            return KeyPair.from_jsonable(dct)
    
    def nbytes(self):
        return (self.N.bit_length()+7)//8

    def public_key(self, format="key"):
        # key is always public
        if format == "key":
            return self
        else:
            return (self.E, self.N)
        
class KeyPair(Key):
    
    def __init__(self, e, d, n, id=None):
        id = id or uuid.uuid1().hex
        Key.__init__(self, e, n, id)
        self.D = d              # private exponent
        
    def as_jsonable(self):
        dct = Key.as_jsonable(self)
        dct["type"] = "keypair"
        dct["d"] = to_b64(self.D)
        return dct

    def as_json(self):
        return json.dumps(self.as_jsonable(), indent=2)+"\n"
        
    @staticmethod
    def from_jsonable(data):
        assert data["type"] == "keypair"
        kp = KeyPair(from_b64(data["e"]), from_b64(data["d"]), from_b64(data["n"]), id=data["id"])
        return kp
        
    @staticmethod
    def from_json(text):
        dct = json.loads(text)
        assert dct["type"] == "keypair"
        return KeyPair.from_jsonable(dct)
        
    def private_key(self, format="key"):
        if format == "key":
            return Key(self.D, self.N, self.ID)
        else:
            return (self.D, self.N)
            
    def public_key(self, format="key"):
        if format == "key":
            return Key(self.E, self.N, self.ID)
        else:
            return (self.E, self.N)
            
    @staticmethod
    def generate(nbits=512, e=65537):
        p, q = generate_p_q(nbits, e)
        n = p * q
        L = (p-1)*(q-1)
        d = extended_gcd(e, L)[1]
        private = (d, n, p, q, e)
        public = (e, n)
        return KeyPair(e, d, n)
        
if __name__ == "__main__":
    import random
    nbits = 256
    key_pair = KeyPair.generate(nbits)

    e, n = key_pair.public_key()
    d, n = key_pair.private_key()

    #
    # check if the math works
    #
    for _ in range(10000):
        m = random.randint(1, n-1)
        c = pow(m,e,n)
        mm = pow(c,d,n)
        if mm != m:
            print (m, c, mm, "<---- different!" if m != mm else "")

    print("key pair:")
    print(key_pair.as_json())
    print("private key:")
    print(key_pair.private_key("key").as_json())
    print("public key:")
    print(key_pair.public_key("key").as_json())
    