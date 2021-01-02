from tinyrsa import Key, KeyPair, RSA
from tinyrsa.aes import AES

import sys, getopt, os


Usage = """
tinyrsa   generate [-s <key size, bits>] -k <keypair file>
          public -k <keypair file> [-o <public key file>]
          encrypt -k <keypair or public key file> <input file> <output file>
          decrypt -k <keypair or public key file> <input file> <output file>
          sign -k <keypair file> <input file> (<signature file>|-)
          verify -k <keypair or public key file> <input file> <signature file>
"""

def do_generate(argv):
    opts, args = getopt.getopt(argv, "s:k:")
    opts = dict(opts)
    size = int(opts.get("-s", 512))
    kp = KeyPair.generate(size)
    fd = os.open(opts["-k"], os.O_WRONLY | os.O_CREAT, mode=0o700)
    os.fdopen(fd, "w").write(kp.as_json())
    
def do_public(argv):
    opts, args = getopt.getopt(argv, "k:o:")
    opts = dict(opts)
    kp = KeyPair.from_json(open(opts["-k"], "r").read())
    public = kp.public_key()
    out = open(opts["-o"], "w") if "-o" in opts else sys.stdout
    out.write(public.as_json())
    
def do_encrypt(argv):
    opts, args = getopt.getopt(argv, "k:")
    opts = dict(opts)
    k = Key.from_json(open(opts["-k"], "r").read())
    rsa = RSA(k)
    aes = AES()
    enc_key = aes.Key
    enc_key = rsa.encrypt(enc_key)

    inp, out = args
    inp = open(inp, "rb")
    out = open(out, "wb")

    out.write(bytes([len(enc_key)]))
    out.write(enc_key)
    
    aes.encrypt_file(inp, out)
    
def do_decrypt(argv):
    opts, args = getopt.getopt(argv, "k:")
    opts = dict(opts)
    k = KeyPair.from_json(open(opts["-k"], "r").read())
    rsa = RSA(k)

    inp, out = args
    inp = open(inp, "rb")
    out = open(out, "wb")

    l = inp.read(1)[0]
    enc_key = inp.read(l)
    enc_key = rsa.decrypt(enc_key)

    aes = AES(enc_key)
    aes.decrypt_file(inp, out)
    
def do_sign(argv):
    opts, args = getopt.getopt(argv, "k:")
    opts = dict(opts)
    k = KeyPair.from_json(open(opts["-k"], "r").read())
    rsa = RSA(k)
    
    inp, sig = args
    inp = open(inp, "rb")
    signature = rsa.sign(inp)
    out = sys.stdout if sig == "-" else open(sig, "w")
    out.write(signature+"\n")
    

def do_verify(argv):
    opts, args = getopt.getopt(argv, "k:")
    opts = dict(opts)
    k = Key.from_json(open(opts["-k"], "r").read())
    rsa = RSA(k)
    
    inp, sig = args
    inp = open(inp, "rb")
    signature = open(sig, "r").read().strip()
    ok = rsa.verify_signature(inp, signature)
    print ("verified" if ok else "forged")
    sys.exit(0 if ok else 1)
    
def main():    
    if len(sys.argv) < 2:
        print(Usage)
        sys.exit(2)

    command, args = sys.argv[1], sys.argv[2:]
    if command in ["generate","public","encrypt","decrypt","sign","verify"]:
        {
            "generate": do_generate,
            "public":   do_public,
            "encrypt":  do_encrypt,
            "decrypt":  do_decrypt,
            "sign":     do_sign,
            "verify":   do_verify
        }[command](args)
    else:
        print(Usage)
        sys.exit(2)
    
if __name__ == "__main__":
    main()
