import socket
import time
import struct
from des import des_decrypt, des_encrypt

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
lifetime4 = 86400

# Function to check the validity of tickets
def is_ticket_valid(ticket, lifetime):
    ts2, _ = struct.unpack('>II', ticket[-12:-4])
    current_time = int(time.time())
    return (current_time - ts2) < lifetime

# Create a socket and listen for incoming connections
TGSV_address = ('127.0.0.1', 23456)
server_socket_tgsv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket_tgsv.bind(TGSV_address)
server_socket_tgsv.listen(1)

print("Combined TGS/V Server is waiting for connections...")

while True:
    client_socket, client_address = server_socket_tgsv.accept()

    try:
        # Receive the client's message (Step 3)
        message1 = client_socket.recv(1024)

        # Decrypt the received data using the client's key
        decrypted_data1 = des_decrypt(Kc, message1)

        print("Step 3: Received message from client:", decrypted_data1)

        # Receive the authenticatorc
        authenticatorc_1 = client_socket.recv(1024)

        # Decrypt the authenticatorc
        decrypted_authenticatorc_1 = des_decrypt(Kctgs, authenticatorc_1)

        # Parse message and authenticatorc
        IDv_received = decrypted_data1[:15].decode('utf-8')
        tickettgs_received = decrypted_data1[15:71]
        IDc_received = decrypted_authenticatorc_1[:13].decode('utf-8')
        ADc_received = decrypted_authenticatorc_1[13:27].decode('utf-8')
        print("Received IDv:", IDv_received)
        print("tickettgs:", tickettgs_received)
        print("IDc:", IDc_received)
        print("ADc:", ADc_received)

        # Search for "AdditionalData" in the received data
        ADc_index1 = decrypted_authenticatorc_1.find(b"AdditionalData")

        if ADc_index1 != -1:
            # Extract the numeric part following "AdditionalData"
            numeric_part1 = decrypted_authenticatorc_1[ADc_index1 + len(b"AdditionalData"):]

            try:
                TS3_received = int(numeric_part1)
                print("TS3_received:", TS3_received)
            except ValueError as e:
                print("An error occurred when converting to int:", str(e))
        else:
            print("No 'AdditionalData' found in received data.")

        if is_ticket_valid(tickettgs_received, lifetime4): # Step 3: Client -> TGS
            print("This message is valid.")
            # Generate the Ticketv and send it to the client
            TS4 = int(time.time())
            ticketv_data = Kcv + IDc.encode('utf-8') + ADc_received.encode('utf-8') + IDv_received.encode('utf-8') + str(TS4).encode('utf-8') + str(lifetime4).encode('utf-8')
            ticketv = des_encrypt(Kv, ticketv_data)
            message1_data = Kcv + IDv_received.encode('utf-8') + str(TS4).encode('utf-8') + ticketv
            send_message1 = des_encrypt(Kctgs, message1_data)

            client_socket.send(send_message1)
            client_socket.send(ticketv)
            print("\nStep 4: Sent Ticketv to the client.")
            print("TGS->C (message): E(Kc,tgs' [Kc,v || IDv || TS4 || Ticketv])\n")
            
        else:
            print("Step 3: Tickettgs verification failed. Invalid IDtgs or expired tickettgs.")

        # Receive the client's request (Step 5)
        request2 = client_socket.recv(1024)

        # Decrypt the received data using the client's key
        decrypted_data2 = des_decrypt(Kc, request2)

        # Receive the authenticatorc
        authenticatorc_2 = client_socket.recv(1024)

        # Decrypt the authenticatorc
        decrypted_authenticatorc_2 = des_decrypt(Kcv, authenticatorc_2)

        print("Step 5: Received Ticketv || Authenticatorc from client:", decrypted_data2)

        # Parse  and authenticatorc
        ticketv_received = decrypted_data2[:72]
        ADc_received2 = decrypted_authenticatorc_2[:13].decode('utf-8')
        IDc_received2 = decrypted_authenticatorc_2[13:27].decode('utf-8')
        print("ticketv:", ticketv_received)
        print("ADc:", ADc_received2)
        print("IDc:", IDc_received2)

        # Search for "AdditionalData" in the received data
        ADc_index2 = decrypted_authenticatorc_2.find(b"AdditionalData")

        if ADc_index2 != -1:
            # Extract the numeric part following "AdditionalData"
            numeric_part2 = decrypted_authenticatorc_2[ADc_index2 + len(b"AdditionalData"):]

            try:
                TS5_received = int(numeric_part2)
                print("TS5_received:", TS5_received)
            except ValueError as e:
                print("An error occurred when converting to int:", str(e))
        else:
            print("No 'AdditionalData' found in received data.")

        if is_ticket_valid(ticketv_received, lifetime4):  # Step 5: Client -> TGS (for mutual authentication)
            print("This message is valid.")
            ts6_plus_1 = str(TS5_received + 1)
            print("ts6_plus_1 value:", ts6_plus_1)

            # Perform mutual authentication with the client
            response_step5 = des_encrypt(Kcv, ts6_plus_1.encode('utf-8'))
            client_socket.send(response_step5)
            print("\nStep 6: Send ts6_plus_1 to client to perform mutual authentication.")
            print("V->C: E(Kc,v' [TS5 + 1])\n")

        else:
            print("Received an unknown request. Ignoring.")

    except Exception as e:
        print("An error occurred:", str(e))

    finally:
        client_socket.close()

# Close the server socket outside the loop
server_socket_tgsv.close()
