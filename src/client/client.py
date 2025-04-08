import sys
import socket
from pathlib import Path
ROOT_DIR = str(Path(__file__).parent.parent.resolve())
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR) 
print(sys.path)
from sender.run_client import run_client




if __name__=="__main__":
    """
    Setup cs socket and connect to server
    Start Listener Thread
    Interpret commands
    """
    run_client()

