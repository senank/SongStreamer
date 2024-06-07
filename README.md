This C application can stream audio and text files from one server to multiple clients.

To run the server:
./aserver
(note: all files are stored in ./library)
(To host a server online, must specify different port in port.mk)

To connect with a client once server is running:
./asclient

Once connected as a client, type `help` to get a list of commands that can be used to interact with the server

