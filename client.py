import socket
import wvlib.crypto as crypt
import multiprocessing as mp
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
    while True:
        buf = client.read(256)
        if not buf: break
        cbuf = state['ctx'].encrypt(buf)
        server.send(cbuf)
    pass

def ServerToClient(client, server):
    while True:
        buf = server.read(256)
        if not buf: break
        pbuf = state['ctx'].decrypt(buf)
        client.send(buf)
    pass

def handshake(conn):
    state['ctx'] = ctx = crypt.CryptoContext(read(conf.pubkey))
    ctx.keygen()
    ctx.precompute()
    # Propose
    conn.send(ctx.createproposal)
    m = conn.read(5)
    b = json.loads(m)
    if b is True:
        print("Handshaked")
    else:
        raise Exception("Handshaker failed")
    pass

def setup(args):
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((conf.host, conf.port))
    s.listen()
    conn, addr = s.accept()
    handshake(conn)
    p1 = mp.Process(target=ClientToServer, args=(c, s))
    p1 = mp.Process(target=ServerToClient, args=(c, s))
    p1.start()
    p2.start()
    p1.join()
    p2.join()
    pass

if __name__ == '__main__':
    setup()
