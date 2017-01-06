import socket
import wvlib.crypto as crypt
import multiprocessing as mp
import json
import conf

global state
state = dict()

def read(fn):
    fp = open(fn, 'r')
    buf = fp.read()
    fp.close()
    return buf
    pass

def ClientToServer(client, server):
    """
    Receive plaintext, make ciphertext
    """
    while True:
        buf = client.recv(256)
        if not buf: break
        cbuf = state['ctx'].encrypt(buf)
        server.send(cbuf)
    pass

def ServerToClient(client, server):
    """
    Receive ciphertext, make plaintext
    """
    while True:
        buf = server.recv(256)
        if not buf: break
        pbuf, valid = state['ctx'].decrypt(buf)
        if not valid:
            continue
        client.send(pbuf)
    pass

def handshake(conn):
    state['ctx'] = ctx = crypt.CryptoContext(read(conf.pubkey))
    ctx.keygen()
    ctx.precompute()
    # Propose
    conn.send(ctx.createproposal())
    m = conn.recv(5)
    print(m)
    b = json.loads(m.decode())
    if b is True:
        print("Handshaked")
    else:
        raise Exception("Handshaker failed")
    pass

def setup():
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host, port = conf.target.split(':')
    c.connect((host, int(port)))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((conf.host, conf.port))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        handshake(c)
        p1 = mp.Process(target=ClientToServer, args=(conn, c))
        p2 = mp.Process(target=ServerToClient, args=(conn, c))
        p1.start()
        p2.start()
        p1.join()
        p2.join()
    pass

if __name__ == '__main__':
    setup()
