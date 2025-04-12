import threading
from client.sender.run_client import run_client
from client.listener import start_listener

if __name__=="__main__":
    """
    Setup cs socket and connect to server
    Start Listener Thread
    Interpret commands
    """
    listener_thread = threading.Thread(target=start_listener, daemon=True)
    listener_thread.start()
    run_client()

