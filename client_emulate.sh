#!/bin/bash

# Start client 1 in the background
(echo "Hello from client1" ; echo "More data...") | nc 127.0.0.1 9000 &

# Start client 2 in the background
(echo "Hello from client2" ; echo "Extra data...") | nc 127.0.0.1  9000 &


(echo "Hello from client3" ; echo "3 data...") | nc 127.0.0.1 9000 &
(echo "Hello from client4" ; echo "4 data...") | nc 127.0.0.1 9000 &
(echo "Hello from client5" ; echo "5 data...") | nc 127.0.0.1 9000 &
# Wait for both background jobs to finish
wait

