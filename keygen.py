import argparse
from nacl.encoding import Base64Encoder as b64
from nacl.public import PrivateKey

def write(filename, buf):
    fp = open(filename, 'w')
    fp.write(buf)
    fp.close()
    pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('privkey', nargs='?', default='private.b64', help="Private key file")
    ap.add_argument('pubkey', nargs='?', default='pubkey.b64', help='Public key file, is really public')
    args = ap.parse_args()
    pk = PrivateKey.generate() # Private key, generated
    write(args.privkey, pk.encode(encoder=b64).decode())
    write(args.pubkey, pk.public_key.encode(encoder=b64).decode())
    pass

if __name__ == '__main__':
    main()
