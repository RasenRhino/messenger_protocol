# User Setup

### Run this before running the application

##### Usage

```
python populate_db.py -h

Initialize user details and store them in an SQLite database.

options:
  -h, --help       show this help message and exit
  --file, -f FILE  Path to a JSON file containing user data (username -> password).
```

Outputs to `userdetails.json`

Running `populate_db.py` without `-f` will generate dummy user data. 

To use your own user data, generate a file like `temp.json`

```
{
    "Ritik":{
        "password":"1234"
    },
    "Ridham":{
        "password":"4567"
    }
}
```

# Docker Setup

```bash
docker build -t chat-app:latest .
docker run --rm -it --name chat-server chat-app src/server/server.py
docker run --rm -it --name chat-client --network container:chat-server chat-app src/client.py
```


# To-Do
- [ ] Add Robust Error Handling
- [x] Add Rate Limit on Server Side. (Done for username enumeration, but we need to think about where else to put it)
- [ ] Refactor and Optimize Code. Hardcode packet types in switch case. Update aad to take packet_type from recieved data. 