import threading
from client.sender.run_client import run_client
from client.listener import start_listener
from config.config import init_config

if __name__=="__main__":
    """
    Setup cs socket and connect to server
    Start Listener Thread
    Interpret commands
    """
    init_config()
    listener_thread = threading.Thread(target=start_listener, daemon=True)
    listener_thread.start()
    run_client()

