import socket
import time
import sys
import inspect
from config.config import TCP_RECV_SIZE
from client.commands.commands import send_list_packet, send_message_packet

def command_loop(client_socket: socket.socket):
    try:
        while True:
            command = input("+> ").split(" ")
            operation = command[0].lower()
            
            match operation:
                case "list":
                    send_list_packet(client_socket)
                case "send":
                    recipient = command[1]
                    message = " ".join(command[2:])
                    send_message_packet(client_socket, recipient, message)
                case _:
                    error = inspect.cleandoc(f"""
                            +> Operation {operation} is not supported
                            +> Suppoerted Operations: 
                            +> list
                            +> send <USERNAME> <MESSAGE>""")
                    sys.stderr.write(f"{error}\n")
            time.sleep(0.1)
            # command = input(">> ")
            # if not command.strip():
            #     continue
            # msg = command.encode()
            # try:
            #     client_socket.sendall(msg)
            # except socket.error as e:
            #     print(f"Error sending command: {e}")
            #     raise ConnectionResetError("Server socket closed")

            # try:
            #     response = client_socket.recv(TCP_RECV_SIZE)
            #     if not response:
            #         raise ConnectionResetError("Server closed the connection.")
            #     print(f"Server: {response.decode()}")
            # except socket.error as e:
            #     print(f"Error receiving response: {e}")
            #     raise ConnectionResetError("Socket error")
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"[!] Lost connection in command loop: {e}")
        raise Exception("Lost Connection in command loop")