import socket
import struct
import sys
import threading
import random
import msgpack # python -m pip install msgpack
from string import ascii_lowercase, digits

PORT = 10139
HEADER_LENGTH = 2

atos = lambda address: f'[{address[0]}:{address[1]}]'

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

def registerNickname(sock: socket.socket, nickname: str):
    send_pack(sock, {"type": "register", "user" : nickname})
    while True:
            try:
                if msg_received := read_pack(sock):  # ce obstaja sporocilo
                    if msg_received["type"] != "status" or msg_received["for"] != "register":
                        continue
                    if(msg_received["status"] == "success"):
                        return True
                    return msg_received["status"]
            except Exception as e:
                return e

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
                    if msg_received['type'] == 'status':
                        print(f"!{msg_received['for']} : {msg_received['status']}")  # izpisi
                    else:
                        print(msg_received)
            except ConnectionResetError:
                print("[system] Connection reset by peer!")
                sys.exit()

    target_addr = 'localhost'
    if addr := input(f'[system] Target chat server [{target_addr}]: '):
        target_addr = addr


    # povezi se na streznik
    print("[system] Connecting to chat server ...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((target_addr, PORT))
    except ConnectionRefusedError:
        print("[system] Cannot connect to server!")
        sys.exit()

    user = ''.join(random.sample(list(ascii_lowercase), 4) + random.sample(list(digits), 2))
    if new_user := input(f'[system] Nickname [{user}]: '):
        user = new_user
    print("[system] Connected!")
    
    if (status := registerNickname(sock, user)) != True:
        print(f"[system] Failed to register nickname! {status}")
        sys.exit()
    
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
