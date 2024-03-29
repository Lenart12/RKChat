import signal
import socket
import threading
from chatClient import *

# funkcija za komunikacijo z odjemalcem (tece v loceni niti za vsakega odjemalca)
def client_thread(client_sock: socket.socket, client_addr: tuple[str, int], current_user: str):
    global clients
    global users

    print(f"[system] Connected {atos(client_addr)} (total {len(clients)})")

    try:
        while True:  # neskoncna zanka
            msg_received = read_pack(client_sock)

            if not msg_received:  # ce obstaja sporocilo
                break

            print(f"[RKchat] {atos(client_addr)} : {msg_received}")
            if msg_received["type"] == "msg":
                if msg_received["for"] == "":
                    for client in clients:
                        if client != client_sock:
                            send_pack(client, {"type": "msg", "msg": msg_received["msg"], "from" : current_user})
                else:
                    if sock := users.get(msg_received['for'], None):
                        send_pack(sock, {"type": "msg-dm", "msg": msg_received["msg"], "from" : current_user})
                    else:
                        send_pack(client_sock, {"type": "status", "for": "msg-dm", "status": "User doesn't exist!"})
            else:
                send_pack(sock, {"type": "msg", "msg": "Wrong message type", "from" : "RKCHAT"})
    except Exception as e:
        try:
            send_pack(client_sock, {"type": "status", "for": "*", "status": "error", "error": e})
        except:
            pass
        finally:
            print(f"Client {atos(client_addr)} has exception: {e}")

    # prisli smo iz neskoncne zanke
    with clients_lock:
        clients.remove(client_sock)
    with users_lock:
        users.pop(current_user, None)
    
    print(f"[system] Disconnected {atos(client_addr)} (total {len(clients)})")
    client_sock.close()

clients = set()
users = dict()
clients_lock = threading.Lock()
users_lock = threading.Lock()

def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    # kreiraj socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind_addr = ("0.0.0.0", PORT)
    server_socket.bind(bind_addr)
    server_socket.listen(1)

    ctx = setup_SSL_context('cert/streznik.crt', 'cert/streznik.key', 'cert/odjemalci.pem')

    # cakaj na nove odjemalce
    print(f"[system] Listening on {atos(bind_addr)}")
    while True:
        try:
            # pocakaj na novo povezavo - blokirajoc klic
            client_sock, client_addr = server_socket.accept()

            client_sock = ctx.wrap_socket(client_sock, server_side=True)

            cert = client_sock.getpeercert()
            user = ''
            for sub in cert['subject']:
                for key, value in sub:
                    # v commonName je ime uporabnika
                    if key == 'commonName':
                        user = value

            if not user:
                send_pack(client_sock, {"type": "status", "for": "register", "status": "error", "error": "No name in certificate!"})
                client_sock.close()
                continue

            if users.get(user, None) is not None:
                send_pack(client_sock, {"type": "status", "for": "register", "status": "error", "error": "User already logged in!"})
                client_sock.close()
                continue
            
            with clients_lock:
                clients.add(client_sock)

            with users_lock:
                users[user] = client_sock

            thread = threading.Thread(target=client_thread, args=(client_sock, client_addr, user));
            thread.daemon = True
            thread.start()

        except KeyboardInterrupt:
            break

    print("[system] closing server socket ...")
    server_socket.close()

if __name__ == '__main__':
    main()
