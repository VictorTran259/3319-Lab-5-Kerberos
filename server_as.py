import socket
from des import des_decrypt, des_encrypt
import struct
import time

# Constants
IDc = "CIS3319USERID"
IDtgs = "CIS3319TGSID"
IDv = "CIS3319SERVERID"
ADc = "AdditionalData"
Kc = b'SecretKe'
Ktgs = b'TGSSecre'
Kv = b'ServerSe'
Kctgs = b'SharedTG'
Kcv = b'VSharedK'
lifetime2 = 60

# Create a socket and listen for incoming connections
AS_address = ('127.0.0.1', 12345)
server_socket_as = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket_as.bind(AS_address)
server_socket_as.listen(1)

print("Authentication Server (AS) is waiting for connections...")

while True:
    client_socket, client_address = server_socket_as.accept()

    try:
        # Receive the client's request (Step 1)
        request_step1 = client_socket.recv(1024)

        # Decrypt the received data using the client's key
        data_step1 = des_decrypt(Kc, request_step1)

        print("Step 1: Received message from client:", data_step1)

        IDc_received = data_step1[:13].decode('utf-8')
        IDtgs_received = data_step1[13:25].decode('utf-8')
        print("Received IDc from client:", IDc_received)
        print("IDtgs_received:", IDtgs_received)

        # Search for "CIS3319TGSID" in the received data
        tgs_id_index = data_step1.find(b"CIS3319TGSID")

        if tgs_id_index != -1:
            # Extract the numeric part following "CIS3319TGSID"
            numeric_part = data_step1[tgs_id_index + len(b"CIS3319TGSID"):]

            try:
                TS1_received = int(numeric_part)
                print("TS1_received:", TS1_received)
            except ValueError as e:
                print("An error occurred when converting to int:", str(e))
        else:
            print("No 'CIS3319TGSID' found in received data.")

        # Verify the client's identity
        if IDc_received == IDc:
            print("This message is valid.")
            # Generate the Tickettgs and send it to the client
            TS2 = int(time.time())
            ts2_lifetime2_data = struct.pack('>II', TS2, lifetime2)  # Pack TS2 and lifetime2
            tickettgs_data = Kctgs + IDc.encode('utf-8') + ADc.encode('utf-8') + IDtgs.encode('utf-8') + ts2_lifetime2_data
            tickettgs = des_encrypt(Ktgs, tickettgs_data)
            message_data = Kctgs + IDtgs.encode('utf-8') + ts2_lifetime2_data + tickettgs
            message = des_encrypt(Kc, message_data)


            client_socket.send(message)
            client_socket.send(tickettgs)
            print("\nStep 2: Sent message and tickettgs to the client.")
            print("AS -> C (message): E(Kc' [Kc,tgs || IDtgs || TS2 || Lifetime2 || Tickettgs])\n")

        else:
            print("Step 1: Client identity verification failed. Invalid IDc received.")

    except Exception as e:
        print("An error occurred:", str(e))

    finally:
        client_socket.close()

# Close the server socket outside the loop
server_socket_as.close()
