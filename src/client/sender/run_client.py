import socket
import time
from config.config import load_server_address, TCP_RECV_SIZE
from sender.cs_auth import login



def connect_to_server():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = load_server_address()
    client_socket.connect(server_address)
    print("Connecting to server")
    return client_socket

def command_loop(client_socket: socket.socket):
    try:
        while True:
            command = input(">> ")
            if not command.strip():
                continue

            # You can JSON-encode the message or just send raw strings
            msg = command.encode()
            try:
                client_socket.sendall(msg)
            except socket.error as e:
                print(f"Error sending command: {e}")
                raise ConnectionResetError("Server socket closed")

            try:
                response = client_socket.recv(TCP_RECV_SIZE)
                if not response:
                    raise ConnectionResetError("Server closed the connection.")
                print(f"Server: {response.decode()}")
            except socket.error as e:
                print(f"Error receiving response: {e}")
                raise ConnectionResetError("Socket error")
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"[!] Lost connection in command loop: {e}")
        raise Exception("Lost Connection in command loop")

def run_client():
    """
    Runs in the main thread and responsible for handling user input
    and sending packets to the server and other clients.
    """
    while True:
        client_socket = connect_to_server()
        if client_socket is None:
            print("Retrying in 3 seconds...")
            time.sleep(3)
            continue

        try:
            login(client_socket)
            print("[+] Authenticated. You can now enter commands.")
            command_loop(client_socket)
        except (ConnectionResetError, BrokenPipeError, socket.error) as e:
            print(f"[!] Disconnected or error occurred: {e}")
            print("Attempting to reconnect in 3 seconds...")
        except KeyboardInterrupt:
            print("Client interrupted by user.")
            break
        except Exception as e:
            print(f"Exception OCCURED: {e}")
        finally:
            print(f"Closing Socket")
            client_socket.close()
            time.sleep(2)



    