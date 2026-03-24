Phase 2: Functional (Unsecured) Implementation

This project provides a simple group server + file server (unsecured) and a client that can talk to both.

Requirements:
- Python 3.8+ (tested with Python 3.11)

1) Start the Group Server (in one terminal):

   python group_server.py --host 0.0.0.0 --port 12345

2) Start the File Server (in another terminal):

   python file_server.py --host 0.0.0.0 --port 12346

3) Run the client (in a third terminal):

   python p2client.py --group-host localhost --group-port 12345 --file-host localhost --file-port 12346

4) In the client prompt, obtain a token and perform operations:

   # get a token for the "admin" user (pre-created)
   getToken admin

   # create a user (requires ADMIN membership)
   createUser bob

   # create a group (you become owner)
   createGroup research

   # add the new user to the group (owner-only)
   addUserToGroup bob research

   # switch to a different user
   getToken bob

   # upload a file into the group
   upload localfile.txt remote.txt research

   # list available files
   listFiles

   # download a file from the server
   download remote.txt downloaded.txt

Notes:
- Tokens are plain JSON objects (no crypto for Phase 2).
- Server state is stored in JSON files under the working directory: groupserver_state.json and fileserver_metadata.json.
- Uploaded files are stored in the `storage/` directory.
