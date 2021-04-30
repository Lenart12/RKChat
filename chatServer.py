import signal
import socket
import threading
from chatClient import *

# funkcija za komunikacijo z odjemalcem (tece v loceni niti za vsakega odjemalca)
def client_thread(client_sock: socket.socket, client_addr: tuple[str, int]):
    global clients

    print(f"[system] Connected {atos(client_addr)} (total {len(clients)})")

    try:

        while True:  # neskoncna zanka
            msg_received = receive_message(client_sock)

            if not msg_received:  # ce obstaja sporocilo
                break

            print(f"[RKchat] {atos(client_addr)} : {msg_received}")

            for client in clients:
                send_message(client, msg_received.upper())
    except:
        # tule bi lahko bolj elegantno reagirali, npr. na posamezne izjeme. Trenutno kar pozremo izjemo
        pass

    # prisli smo iz neskoncne zanke
    with clients_lock:
        clients.remove(client_sock)
    print(f"[system] Disconnected {atos(client_addr)} (total {len(clients)})")
    client_sock.close()

clients = set()
clients_lock = threading.Lock()

def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    # kreiraj socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", PORT))
    server_socket.listen(1)

    # cakaj na nove odjemalce
    print("[system] listening ...")
    while True:
        try:
            # pocakaj na novo povezavo - blokirajoc klic
            client_sock, client_addr = server_socket.accept()
            with clients_lock:
                clients.add(client_sock)

            thread = threading.Thread(target=client_thread, args=(client_sock, client_addr));
            thread.daemon = True
            thread.start()

        except KeyboardInterrupt:
            break

    print("[system] closing server socket ...")
    server_socket.close()

if __name__ == '__main__':
    main()
