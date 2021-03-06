import base64

from nacl.encoding import Base64Encoder as b64
from nacl.public import PrivateKey, PublicKey, Box
import nacl.utils


class CryptoContext(object):
    """
    Context used for performing cryptography on a stream
    """

    def __init__(self, pubkey):
        super(CryptoContext, self).__init__()
        self.tcvpub = PublicKey(pubkey, encoder=b64)

    def keygen(self):
        self.cvpriv = pk = PrivateKey.generate()
        self.cvpub = pk.public_key
        pass

    def createproposal(self):
        return self.cvpub.encode()

    def precompute(self):
        self.box = Box(self.cvpriv, self.tcvpub)
        pass

    def encrypt(self, pt):
        nonce = nacl.utils.random(24)
        return self.box.encrypt(pt, nonce)

    def decrypt(self, ct):
        pt = None
        try:
            pt = self.box.decrypt(ct)
        except Exception as e:
            print(e)
            return b'', False
        else:
            return pt, True
        pass
