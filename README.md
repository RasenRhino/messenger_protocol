# User Setup 
### (Run this before running the application)

#### Usage

```
python populate_db.py -h

Initialize user details and store them in an SQLite database.

options:
  -h, --help       show this help message and exit
  --file, -f FILE  Path to a JSON file containing user data (username -> password).
```

Outputs to `userdetails.json` 

##### Sample `userdetails.json`

```
{
    "Alice": {
        "password": "3",
        "salt": "auOnzxQbb3vrn4Ea",
        "verifier": "0x9f58e24653c1449160a236766a8f6a5261644b8509563485a01cad3bebfc42660bdbe1b79724c657548f287f4553d3038c9b24cc5e9850fb4e188cfa21f6a2f91522a041e88f3a3e9c4bfce5fa538a6563c5d9f0339f0d03f174738233763d8c4f14fa971f7c05dde1e226b3f6d3e0edaed6621d53e053d24416c53b8f4a0e640d24e61fe85b438fcd73a9e05d81756db818a7cfd0fee44ea86b8398b25198fdc468b36fe16b9fe858964814291807a0ed0ecacb4dc5d481c2041292a1e3089d52a77253ad2a6a105b6750eccf70318c40a58329200f1f183c4bfe410c019bc0efa27474c4d1ba12c81441b5d247f1ac458c0edaf0ab5ecb6951d958a20e362bd943d1a0983d0c87066f39725fd215a0844fc344c233da60fd51257721e7449112fe9b2ffd10267effb410f758b03d26f6659413e0fea61f8798448a99695adfdac34cb49028980d4e0e85ad4c6ae7c557c3824280a6ffb3fd0357198d70889625e25ec8af9a4fd7c0d10319c4fdfc9cf2c109a3d87d2eb6f18753247f016c78ac77f7982441a89c217f6084adc4e0cc6e74feb6f977c0b85e7f69df642516e30f7febb93c776192c6dc37e6a546276d7fd2e455a545cedb14a13fe939fbe528b7f854ba9e0e2039317cf749dbc5e0e523cab5c35e422f7f4781615ccdafee168425dfd9b6ad95f809d9207d6955554f02ab525520afdb0ce25cba093997a8bc"
    },
    "Bob": {
        "password": "0",
        "salt": "bDH8DD3YAm3ue8fU",
        "verifier": "0xf69507d6a8c4a2798b78c27b9cb5c490e8025a79cefd2b1e7f3b8b775ae2af3b05eee6d791d85497ead364edd4bdd415babdfbeec60749f54a3e0febcf1657f893d81b16c9d5b579beb7e10f856d2ef2584c508f38d74b0c31d54fdc2389dbc439c9f585dd88fc2847f9cb2b079332eeb7df72ac48c29053e47e475bd317a6427d435c08919c9dbb56d54051afd33e58adb5823771a91ef2cd2cfd84bcb55d51c26a09a924fea7702972f134a2d4a0ad9290178fc839829deb0fdad3fce6c101416592c52f5fb958ed862e3d9f91b4c266993b047c4288918d685cd767196ed0b38bd0d0d525500935fb3b0756cfe14ab67fe406c57c8ead108bf68da26f0da840529ebdb514a95f41e2922fefa9f8b8e50d09127a6e2073a044b1b0174a079937853fbdf3a62e2fa1f6f61e90123458a6cb768e6cdd01917af17a5bf05e0652beebd87980428bbf54683b30f158e2677789837ffcae0bfe9787376d80bf896543e510b51d1826e9b5d002ee96d279a76375f994f5f61d26535f05a02f4f1df0f1ff9ceb0df0500880473199e8468f260d98844b71e108f9e9c695ed54cf5f04c8f9fcd96a2604a8e7ba8997f207d046e4e55d1d612aad921be9a2a9cc6cae98273a356bcd4d7bf9bc11b145eae7af6a0f40d57fc1c96b490caf4ad55464ced669a3259ba2affeb8244d8be58a01d0375c64a3b8eea02f9beaacc7c920287e4e"
    },
    "Mallory": {
        "password": "2",
        "salt": "gIbPw5cjivIEsjY8",
        "verifier": "0x3b3870b23e48bf05ca0265de3256f09b3a4858565d85d83b117d7811a0d6e940ef24b92e3f6613393d0d70be54b3f7fb903d64ed35a69f281e404eaa3c0fd96c03c40f315e9823e39120cbb21b00adc14a3963875b516ea2dafc9e715431744c26d83ce633402967b4a8111d2fd9b01f154f11fb26e3bb72a5d9f689374907bc74de00658dc1c9c4f51c993b6d39e12d0bda3eeca260acf58d211bd60e530bd55a39eeac44562005a70e0fe3ef644a88f884d6629d063365304e1c3012ccfe0e5e577a215fa77825edfcae0255cea7254c2c0f31389fb081ba6971ddda42e126793f37bc99b9109da883cee42cfaca6f1efdb0ad17a55b29c3103dd841089c32b7f183b5a0a7b5f78b5309432bafa3d051ffab44a5cb4594e43fc35492a66b2999513ac291b120110a7e2f44fc91a048f9619f85d3274bfa00518a01c3b93f3d3111820711db7353ffc1d825b3ef3f6e0d9b81374acf0c39820fb6cdd9effc0889296e456f4f78eec86823090b729fc2a7f37d769afea52b8be423981efe84116d994d5c45da9ae58d5bff64355cf2f36607f0e8516da55360ec38f46ea66dbd7d59ab6127060bf477d35391ad92b85af8420ba54b1263fb0557bec6b110fe25a78eaee616935dad2a93ce81391a955d235c543cfa2d6c6666eb783cf66d3ecdb538b8093153af7887bf766a788a40bdd4cccad0daea3e8f220cef2ed2537b8d"
    }
}
```

Server has no access to `userdetails.json` , hence has no access to user's passwords. It only knows the relevant verifiers and salts corresponding to passwords which are populated into `store.db`

Running `populate_db.py` without `-f` will generate dummy user data. 

To use your own user data, generate a custom file 

##### Sample custom user file 

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

Example file can be found in `src/custom_userdetails.json`


# SQLite schema 


Insertion is handled by `populate_db.py` script. Stores the verifier and salt corresponding to the user password in `store.db` 

###### Schema

```
    CREATE TABLE users (
        username TEXT PRIMARY KEY,
        verifier TEXT NOT NULL,
        salt TEXT NOT NULL
    )
```

`username` is unique endpoint identifier
`verifier` and `salt` are genetated during the execution of `populate_db.py` in the `userdetails.json`

# Generate Keys

From the `src` directory, run `genkey.sh` if you need new key pairs. 
Keypairs are stored in the `src/config` directory  

# Configuration

Information about application configuration files 

###### dh_public_params.json
Contains the public params required for generating DH contributions. 

###### server_details.json 
Contains server host and port

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