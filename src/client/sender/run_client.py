import socket
import time
from config.config import load_server_address, client_store, client_store_lock, TCP_RECV_SIZE
from client.sender.cs_auth import login
from crypto_utils.core import generate_random_port
from client.commands import command_loop
from config.exceptions import LogoutClient

def connect_to_server():
    cs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = load_server_address()
    cs_socket.connect(server_address)
    print("Connecting to server")
    return cs_socket

def run_client():
    """
    Runs in the main thread and responsible for handling user input
    and sending packets to the server and other clients.
    """
    # start_time = time.time()
    while True:
        with client_store_lock:
            if not client_store or not client_store.get("self").get("listen_address"):
                continue
        # print(f"Elapsed: {time.time() - start_time}")
        cs_socket = connect_to_server()
        if cs_socket is None:
            print("Retrying in 3 seconds...")
            time.sleep(3)
            continue
        try:
            with client_store_lock:
                client_store.setdefault("server",{})["socket"] = cs_socket
            login(cs_socket)
            print("[+] Authenticated. You can now enter commands.")
            command_loop(cs_socket)
        except (ConnectionResetError, BrokenPipeError, socket.error) as e:
            print(f"[!] Disconnected or error occurred: {e}")
            print("Attempting to reconnect in 3 seconds...")
        except KeyboardInterrupt:
            print("Client interrupted by user.")
            break
        except LogoutClient:
            print(f"Logging Out!")
            break
        except Exception as e:
            print(f"Exception OCCURED: {e}")
        finally:
            print(f"Closing Socket")
            cs_socket.close()
            time.sleep(2)



    