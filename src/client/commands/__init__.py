import socket
import time
import inspect
from client.helpers import display_error
from client.commands.commands import send_list_packet, send_message_packet, send_logout_packet
from config.exceptions import RecipientOffline
from config.config import client_store, client_store_lock

def command_loop(cs_socket: socket.socket):
    while True:
        try:
            command = input("+> ").split(" ")
            operation = command[0].lower()
            
            match operation:
                case "list":
                    send_list_packet(cs_socket)
                case "send":
                    recipient = command[1]
                    message = " ".join(command[2:])
                    signed_in_users = send_list_packet(cs_socket)
                    if recipient not in signed_in_users:
                        with client_store_lock:
                            if client_store.get("peers",{}).get(recipient):
                                del client_store["peers"][recipient]
                        raise RecipientOffline(f"{recipient} is not online currently.")
                    send_message_packet(cs_socket, recipient, message)
                case "logout":
                    send_logout_packet(cs_socket)
                case _:
                    error = inspect.cleandoc(f"""
                            +> Operation {operation} is not supported
                            +> Suppoerted Operations: 
                            +> list
                            +> send <USERNAME> <MESSAGE>
                            +> logout""")
                    print(f"{error}")
            time.sleep(0.1)
        except RecipientOffline as e:
            display_error(e)