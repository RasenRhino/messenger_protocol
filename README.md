# Docker Setup

```bash
docker build -t chat-app:latest .
docker run --rm -it --name chat-server chat-app src/server/server.py
docker run --rm -it --name chat-client --network container:chat-server chat-app src/client.py
```

# To-Do
- [ ] Add Robust Error Handling
- [ ] Add Rate Limit on Server Side
- [ ] Refactor and Optimize Code. Hardcode packet types in switch case. Update aad to take packet_type from recieved data. 