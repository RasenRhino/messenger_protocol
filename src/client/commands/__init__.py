import socket
import time
import sys
import inspect
from config.config import TCP_RECV_SIZE
from client.commands.commands import send_list_packet, send_message_packet, send_logout_packet

def command_loop(cs_socket: socket.socket):
    try:
        while True:
            command = input("+> ").split(" ")
            operation = command[0].lower()
            
            match operation:
                case "list":
                    send_list_packet(cs_socket)
                case "send":
                    recipient = command[1]
                    message = " ".join(command[2:])
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
                    sys.stderr.write(f"{error}\n")
            time.sleep(0.1)
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"[!] Lost connection in command loop: {type(e).__name__}: {e}")
        raise Exception("Lost Connection in command loop")