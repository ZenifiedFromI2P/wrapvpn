# WrapVPN - A universal solution to encrypting TCP sockets..

This implements a TCP proxy that encrypts any TCP socket, with a pre-shared public key, and generates keys on-the-fly.

This uses the state-of-the-art NaCl library and its public-key constructs (ECDH over Curve25519, XSalsa20, Poly1305) and without any abstraction. (Uses pynacl, though)

This will work irrespective of any TCP protocol, though is explicitly tested against OpenVPN.

# Caveats

This program is designed for working with *streams* **NOT** short-term sockets like the ones used for HTTP..

VPN connections usually last for a long period, this program's client is explicitly designed to only accept one client.

So configure your client to stop reconnecting after 1 attempt, and run this program along side the VPN in a shell script while loop..

# Compatibility

This program is only tested in Linux and BSDs (FreeBSD, OpenBSD as of now), it's not guaranteed (not even implicitly) that this will work with Windows (and I honestly don't want it to).
