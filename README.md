# Docker Setup

```bash
docker build -t chat-app:latest .
docker run --rm -it --name chat-server chat-app src/server/server.py
docker run --rm -it --name chat-client --network container:chat-server chat-app src/client.py
```