import socket
import struct
import sys
import threading
import msgpack # python -m pip install msgpack
import ssl

PORT = 10139
HEADER_LENGTH = 2

atos = lambda address: f'[{address[0]}:{address[1]}]'

def setup_SSL_context(cert: str, key: str, CA: str):
  #uporabi samo TLS, ne SSL
  context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
  # certifikat je obvezen
  context.verify_mode = ssl.CERT_REQUIRED
  #nalozi svoje certifikate
  context.load_cert_chain(certfile=cert, keyfile=key)
  # nalozi certifikate CAjev (samopodp. cert.= svoja CA!)
  context.load_verify_locations(CA)
  # nastavi SSL CipherSuites (nacin kriptiranja)
  context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
  return context

def receive_fixed_length_msg(sock: socket.socket, msglen: int):
    message = b''
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message))  # preberi nekaj bajtov
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk  # pripni prebrane bajte sporocilu

    return message


def receive_message(sock: socket.socket):
    header = receive_fixed_length_msg(sock,
                                      HEADER_LENGTH)  # preberi glavo sporocila (v prvih 2 bytih je dolzina sporocila)
    # pretvori dolzino sporocila v int
    message_length = struct.unpack("!H", header)[0]

    message = None
    if message_length > 0:  # ce je vse OK
        message = receive_fixed_length_msg(
            sock, message_length)  # preberi sporocilo
        message = message.decode("utf-8")

    return message


def send_message(sock: socket.socket, message: str):
    # pretvori sporocilo v niz bajtov, uporabi UTF-8 kodno tabelo
    encoded_message = message.encode("utf-8")

    # ustvari glavo v prvih 2 bytih je dolzina sporocila (HEADER_LENGTH)
    # metoda pack "!H" : !=network byte order, H=unsigned short
    header = struct.pack("!H", len(encoded_message))

    # najprj posljemo dolzino sporocilo, slee nato sporocilo samo
    message = header + encoded_message
    sock.sendall(message)

def send_pack(sock: socket.socket, o: dict):
    msg = msgpack.packb(o)
    header = struct.pack("!H", len(msg))
    message = header + msg
    sock.sendall(message)

def read_pack(sock: socket.socket):
    header = receive_fixed_length_msg(sock,HEADER_LENGTH) 
    message_length = struct.unpack("!H", header)[0]
    message = None
    if message_length > 0:
        message = receive_fixed_length_msg(sock, message_length)
        message = msgpack.unpackb(message)

    return message

if __name__ == '__main__':
    # message_receiver funkcija tece v loceni niti
    def message_receiver():
        while True:
            try:
                if msg_received := read_pack(sock):  # ce obstaja sporocilo
                    if msg_received['type'] == 'msg':
                        print(f"[{msg_received['from']}] : {msg_received['msg']}")  # izpisi
                    elif msg_received['type'] == 'msg-dm':
                        print(f"[* {msg_received['from']}] : {msg_received['msg']}")  # izpisi
                    elif msg_received['type'] == 'status':
                        print(f"!{msg_received['for']} : {msg_received['status']}")  # izpisi
                    else:
                        print(msg_received)
            except ConnectionResetError:
                print("[system] Connection reset by peer!")
                sys.exit()

    target_addr = 'localhost'
    if addr := input(f'[system] Target chat server [{target_addr}]: '):
        target_addr = addr

    cert = 'cert/elektron.crt'
    if new_cert := input(f'[system] Certificate [{cert}]: '):
        cert = new_cert

    key = 'cert/elektron.key'
    if new_key := input(f'[system] Key [{key}]: '):
        key = new_key

    ca = 'cert/streznik.crt'
    if new_ca := input(f'[system] Verify location [{ca}]: '):
        ca = new_ca
    
    ctx = setup_SSL_context(cert, key, ca)

    # povezi se na streznik
    print("[system] Connecting to chat server ...")
    sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    try:
        sock.connect((target_addr, PORT))
    except ConnectionRefusedError:
        print("[system] Cannot connect to server!")
        sys.exit()

    print("[system] Connected!")
    
    # zazeni message_receiver funkcijo v loceni niti
    thread = threading.Thread(target=message_receiver)
    thread.daemon = True
    thread.start()


    # pocakaj da uporabnik nekaj natipka in poslji na streznik
    while sock.fileno() != -1:
        try:
            if msg_send := input(f""):
                for_ = ''
                if msg_send.startswith('/w'):
                    try:
                        _, for_, msg_send = msg_send.split(' ', 2)
                    except ValueError:
                        print('Usage: /w [user] [message...]')
                        continue

                send_pack(sock, {"type": "msg", "msg" : msg_send, "for" : for_})
        except KeyboardInterrupt:
            sys.exit()
