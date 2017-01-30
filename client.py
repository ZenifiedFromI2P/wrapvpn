import json
import socket

import conf
import multiprocessing as mp
import wvlib.crypto as crypt

BUFSIZE = 1024
OVERHEAD = 50  # 24-byte nonce, 16-byte Poly1305 MAC

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
        # Client gets non-overhead (unencrypted buf)
        buf = client.recv(BUFSIZE)
        print("At plaintext counter, I got {}".format(buf))
        if not buf:
            break
        cbuf = state['ctx'].encrypt(buf)
        server.send(cbuf)
    pass


def ServerToClient(client, server):
    """
    Receive ciphertext, make plaintext
    """
    while True:
        buf = server.recv(BUFSIZE + OVERHEAD)
        print("At ciphertext counter, I got {}".format(buf))
        if not buf:
            break
        pbuf, valid = state['ctx'].decrypt(buf)
        if valid is False:
            continue
        print(
            "Validity confirmed, original buffer: {0}, plaintext buffer: {1}".format(
                buf,
                pbuf))
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
    # Listener code
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((conf.host, conf.port))
    s.listen(1)

    # Upstream forwarder code

    host, port = conf.target.split(':')
    if conf.useTor:
        import socks
        c = socks.socksocket()
        c.set_proxy(socks.SOCKS5, conf.torhost, conf.torport)
    else:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    c.connect((host, int(port)))

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
