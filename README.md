# CIS 3319 Lab 5 - Kerberos

## Libraries Used
1. socket - for socket programming
2. time - for generating timestamps
3. struct
4. Crypto.Cipher (part of pycryptodome) - for implementing DES
5. Crypto.Random (part of pycryptodome) - for implementing DES

## Project Files

**client.py** - The client's operation begins with an initialization phase where essential constants are defined, such as its own identity (IDc), the identities of the Authentication
Server (AS) (IDtgs) and the target server (IDv), additional data (ADc), and the encryption keys (Kc, Ktgs, Kv, Kctgs, Kcv). Subsequently, the client establishes connections with
both the Authentication Server (AS) and the Combined Ticket Granting Server and Target Server (TGS/V) using dedicated sockets. In the first step, the client initiates contact with
the Authentication Server (AS). It composes a message encapsulating its identity (IDc), the identity of the Ticket Granting Server (IDtgs), and a timestamp (TS1). The message is
encrypted using its own encryption key (Kc) and is dispatched to the AS for authentication and ticket issuance. The second step encompasses the reception of a response from the AS,
including a message and a Tickettgs. The client decrypts the message employing its encryption key (Kc) to verify the response's integrity. Concurrently, it decrypts the Tickettgs
using the TGS's key (Ktgs). The client further examines the validity of the received Tickettgs, considering its lifetime. Moving on to the third step, the client proceeds to
communicate with the Combined Ticket Granting Server and Target Server (TGS/V). It crafts an Authenticatorc containing its identity (IDc), additional data (ADc), and a new timestamp
(TS3), encrypting it using the shared key for TGS (Kctgs). A message is constructed, incorporating the identity of the target server (IDv), the Tickettgs, and the Authenticatorc.
The message is encrypted using the client's encryption key (Kc) and forwarded to the TGS/V. The fourth step encompasses the reception of a response from the TGS/V, including a
message and a Ticketv. The client decrypts the message using the shared key for TGS (Kctgs) to verify the response's legitimacy. Simultaneously, the Ticketv is decrypted using the
target server's key (Kv). Once more, the client ensures the validity of the received Ticketv based on its designated lifetime. In the fifth step, the client engages in a subsequent
exchange with the TGS/V. A new Authenticatorc is constructed, bearing the client's identity (IDc), additional data (ADc), and a fresh timestamp (TS5), which is encrypted using the
shared key for the target server (Kcv). A message is formed, comprising Ticketv and the Authenticatorc, and is encrypted using the client's encryption key (Kc) prior to transmission
to the TGS/V. The final step encompasses the reception of a response from the TGS/V, which includes TS5+1, a timestamp value. The response is decrypted using the shared key for the
target server (Kcv). To ensure mutual authentication with the TGS/V, the client compares TS5+1 with the expected value (TS5 incremented by 1). A match signifies successful mutual
authentication and, consequently, secure communication. Once the authentication process is successfully completed, the client duly closes the sockets established for communication
with the AS and TGS/V. This comprehensive process adheres to the Kerberos protocol, ensuring secure authentication and messaging between the client and the relevant servers.

**server_as.py** - The Authentication Server (AS) serves as a critical component in the Kerberos-based authentication process. It initiates by defining various constants, such as its own identity (IDtgs), the client's identity (IDc), the target server's identity (IDv), additional data (ADc), and the encryption keys (Kc, Ktgs, Kctgs, Kcv) required for secure
communication. To await incoming connections, the AS establishes a socket on a specific IP address (127.0.0.1) and port (12345), and it enters a listening state. The AS is then
prepared to handle client authentication requests. As clients make connection requests to the AS, the server socket accepts incoming connections and proceeds to the client
communication phase. In the first step of the authentication process, the AS receives a request from the client, encapsulated in a ciphertext. It decrypts this message using the
client's encryption key (Kc) to reveal the content, including the client's identity (IDc) and the target server's identity (IDtgs). The AS validates the identity of the client
(IDc) to ensure the request's legitimacy. To maintain a robust security framework, the AS is responsible for generating a Tickettgs (Ticket to Ticket Granting Server) in step two.
It starts by calculating the current timestamp (TS2), followed by packing this timestamp alongside the designated lifetime (lifetime2) into binary form. Subsequently, it assembles
the Tickettgs content, incorporating the shared key between the client and TGS (Kctgs), the client's identity (IDc), additional data (ADc), the TGS's identity (IDtgs), and the
timestamp-lifetime binary data. The Tickettgs is encrypted using the TGS's encryption key (Ktgs). Following the generation of the Tickettgs, the AS formulates a response to the
client. It encrypts the Tickettgs with the shared key between the client and the TGS (Kctgs) to construct the message. This message, along with the Tickettgs, is then encrypted
using the client's encryption key (Kc). The client is sent both the message and the Tickettgs. With this response, the AS effectively completes the initial two steps of the Kerberos
authentication process, facilitating secure communication between the client and the TGS. Any failure in the client's identity verification results in the AS rejecting the request.
Upon the completion of each client interaction, the AS ensures that the corresponding socket is appropriately closed to maintain system integrity and resource efficiency.

**server_tgsv.py** - The Combined TGS/V Server plays a pivotal role in the Kerberos authentication protocol by serving as a single entry point for client authentication and facilitating
secure communication between clients and the target server. The server begins its operation by defining various constants, including its identity (IDv), the client's identity (IDc),
the encryption keys (Kc, Kcv, Kv, Kctgs, Ktgs) required for secure communication, and the validity period for tickets (lifetime4). To facilitate client communication, the Combined
TGS/V Server establishes a socket bound to a specific IP address (127.0.0.1) and port (23456). It enters a listening state, awaiting incoming client connections. When a client
initiates a connection request, the server socket accepts the connection, enabling the server to engage in client interactions. In the first step of the authentication process
(Step 3), the server receives a message from the client, encrypted using the client's encryption key (Kc). It decrypts the message to reveal its content, including the target
server's identity (IDv), the Tickettgs, the client's identity (IDc), and additional data (ADc). The server verifies the authenticity of the client message by checking the validity
of the Tickettgs against the specified lifetime (lifetime4). Upon successful verification of the Tickettgs, the Combined TGS/V Server generates a Ticketv. It starts by determining
the current timestamp (TS4) and assembles the Ticketv's content, incorporating the shared key between the client and the target server (Kcv), the client's identity (IDc), additional
data (ADc), the target server's identity (IDv), TS4, and the specified lifetime. The Ticketv is encrypted using the target server's encryption key (Kv). The server constructs a
response message, incorporating the Ticketv, the target server's identity (IDv), TS4, and the Ticketv itself. This message is encrypted using the shared key between the client and
the TGS (Kctgs) and subsequently sent to the client. Upon successful completion of Step 3, the Combined TGS/V Server proceeds to Step 5. In this step, the server receives a new
message from the client, which includes the Ticketv and an authenticator (Authenticatorc) encrypted with the client's encryption key (Kc). The server decrypts this message to
retrieve the Ticketv and the authenticator, revealing the client's identity (IDc) and additional data (ADc). After validating the Ticketv for its lifetime and integrity, the server
initiates mutual authentication by sending a response, E(Kc,v' [TS5 + 1]), to the client. This response is encrypted using the shared key between the client and the target server
(Kcv) and consists of TS5 + 1 to ensure both parties share a synchronized timestamp. This mutual authentication finalizes the secure communication between the client and the target
server. The Combined TGS/V Server ensures the graceful termination of client interactions and the appropriate closing of sockets after each communication. This client-server model
efficiently secures the authentication and communication between clients and the target server, ensuring the confidentiality, integrity, and authenticity of data exchanged during
the process.

**des.py** - An implementation of DES using pycryptodome.

**lifetime2=60&lifetime4=86400.JPG** - testing results for lifetime2=60 and lifetime4=86400 like the name of the file suggests.

**lifetime2=10&lifetime4=60200.JPG** - testing results for lifetime2=10 and lifetime4=60200 like the name of the file suggests.

**lifetime2=70&lifetime4=90600.JPG** - testing results for lifetime2=70 and lifetime4=90600 like the name of the file suggests.

**programdesign.txt** - The file you're looking at right now and the documentation for my project.

## How to test project
1. Open up three terminals
2. Run server_as.py on one terminal, then run server_tgsv.py on another terminal, and finally, run client.py on the final terminal
3. Everything else is taken care of by the client and two servers after you do this. You don't have to do anything. Just sit back and watch.
4. If you get an invalid ticket, just keep running the client over and over until it works. When I was testing my project, I would sometimes get invalid tickets so I just kept
   running the client over and over until it worked. The servers won't close if you get an invalid ticket by the way.

Note: If you want to test my project using different numbers for lifetime, you can change them yourself just by changing the values of the lifetime variables in the constants
section of client.py, server_as.py, and server_tgsv.py.
