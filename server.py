import socket
import wvlib.servercrypto as crypt
import multiprocessing as mp
import conf

def read(fn):
    fp = open(fn, 'r')
    buf = fp.read()
    fp.close()
    return buf
    pass

def PTtoCT(pt, ct, state):
    """
    Motto: Get plaintext, make it ciphertext since 1993
    """
    while True:
        buf = pt.recv(256)
        print("At plaintext counter, I got {}".format(buf))
        if not buf: break
        cbuf = state['ctx'].encrypt(buf)
        ct.send(cbuf)
    pass

def CTtoPT(pt, ct, state):
    """
    Motto: Get ciphertext, make it plaintext additionally authenticating it, since 1993
    """
    while True:
        buf = ct.recv(256)
        print("At ciphertext counter, I got {}".format(buf))
        if not buf: break
        pbuf, valid = state['ctx'].decrypt(buf)
        if not valid:
            continue
        pt.send(pbuf)
    pass

def handshake(conn, state):
    buf = conn.recv(44) # Base64-encoded
    s = state.copy()
    try:
        s['ctx'] = ctx = crypt.CryptoContext(buf, read("private.b64"))
        ctx.precompute()
        # Propose
        conn.send(b"true ")
    except Exception:
        conn.send(b'false')
    return s

def setup():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 9040))
    s.listen(1)
    ps = list()
    while True:
        ct, addr = s.accept() # Client socket
        state = dict()
        pt = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # VPN socket
        pt.connect(('127.0.0.1', 1194))
        state = dict()
        state = handshake(ct, state)
        with ct:
            p1 = mp.Process(target=CTtoPT, args=(pt, ct, state))
            p2 = mp.Process(target=PTtoCT, args=(pt, ct, state))
            p1.start()
            p2.start()
            ps.append(p1)
            ps.append(p2)
    pass

if __name__ == '__main__':
    setup()
