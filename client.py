import socket
import time
import struct
from des import des_encrypt, des_decrypt

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
lifetime4 = 86400

# Function to check the validity of tickets
def is_ticket_valid(ticket, lifetime):
    ts2, _ = struct.unpack('>II', ticket[-12:-4])
    current_time = int(time.time())
    return (current_time - ts2) < lifetime

# Create a socket and connect to the AS
AS_address = ('127.0.0.1', 12345)
client_socket_as = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket_as.connect(AS_address)

# Create a socket and connect to the combined TGS and V server
TGSV_address = ('127.0.0.1', 23456)
client_socket_tgsv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket_tgsv.connect(TGSV_address)

# Step 1: Client -> AS
print("Step 1: Sending message to AS")
print("C -> AS: IDc || IDtgs ||TS1\n")
ts1 = int(time.time())

# Construct and encrypt message
data_step1 = IDc + IDtgs + str(ts1)
ciphertext_step1 = des_encrypt(Kc, data_step1.encode('utf-8'))

# Send message to AS
client_socket_as.send(ciphertext_step1)

# Receive the message from AS
print("Step 2: Received message and tickettgs from AS.")
retrieve_AS_message = client_socket_as.recv(1024)
decrypt_AS_message = des_decrypt(Kc, retrieve_AS_message)
print("Message from AS:", decrypt_AS_message)

# Receive the tickettgs from AS
retrieve_tickettgs = client_socket_as.recv(1024)
decrypt_tickettgs = des_decrypt(Ktgs, retrieve_tickettgs)
print("tickettgs:", decrypt_tickettgs)

tickettgs = retrieve_tickettgs[8:]
print("Received ticket length:", len(tickettgs))

if not is_ticket_valid(tickettgs, lifetime2):
    print("Tickettgs is invalid. Aborting.")
    client_socket_as.close()
    client_socket_tgsv.close()
    exit(1)

# Step 3: Client -> TGS/V (Combined Server)
print("\nStep 3: Sending message to TGS")
print("C->TGS: IDv || Tickettgs || Authenticatorc")
ts3 = int(time.time())

# Construct and encrypt authenticatorc
authenticatorc_1_data = IDc.encode('utf-8') + ADc.encode('utf-8') + str(ts3).encode('utf-8')
authenticatorc_1 = des_encrypt(Kctgs, authenticatorc_1_data)

# Construct and encrypt message
message_step_3 = IDv.encode('utf-8') + tickettgs + authenticatorc_1
ciphertext_step3 = des_encrypt(Kc, message_step_3)

# Send message and authenticatorc to TGS
client_socket_tgsv.send(ciphertext_step3)
client_socket_tgsv.send(authenticatorc_1)

# Receive the message from TGS
print("\nStep 4: Received message and ticketv from TGS")
retrieve_TGS_message = client_socket_tgsv.recv(1024)
decrypt_TGS_message = des_decrypt(Kctgs, retrieve_TGS_message)
print("Message from AS:", decrypt_AS_message)

# Receive the ticketv from TGS
retrieve_ticketv = client_socket_tgsv.recv(1024)
decrypt_ticketv = des_decrypt(Kv, retrieve_ticketv)
print("ticketv:", decrypt_ticketv)

ticketv = retrieve_ticketv[8:]
print("Received ticket length:", len(ticketv))

if not is_ticket_valid(ticketv, lifetime4):
    print("Ticketv is invalid. Aborting.")
    client_socket_as.close()
    client_socket_tgsv.close()
    exit(1)

# Step 5: Client -> TGS/V (Combined Server)
print("\nStep 5: Sending message to V")
print("C->V: Ticketv || Authenticatorc")
ts5 = int(time.time())

# Construct and encrypt authenticatorc
authenticatorc_2_data = IDc.encode('utf-8') + ADc.encode('utf-8') + str(ts5).encode('utf-8')
authenticatorc_2 = des_encrypt(Kcv, authenticatorc_2_data)

# Construct and encrypt message
message_step5 = ticketv + authenticatorc_2
ciphertext_step5 = des_encrypt(Kc, message_step5)

# Send message and authenticator to V
client_socket_tgsv.send(ciphertext_step5)
client_socket_tgsv.send(authenticatorc_2)

# Receive the response from V
response_step5 = client_socket_tgsv.recv(1024)

# Decrypt the received data using the client's key
ts6_plus_1 = int(des_decrypt(Kcv, response_step5).decode('utf-8'))

print("\nStep 6: Received TS5+1 from V.")

ts5_plus_1 = ts5 + 1

print("ts5_plus_1 value:", ts5_plus_1)
print("ts6_plus_1 value:", ts6_plus_1)

if ts5_plus_1 == ts6_plus_1:
    print("Mutual authentication with TGS/V successful. Communication is secure.")
else:
    print("Mutual authentication with TGS/V failed. Communication is not secure.")

# Close the client sockets
client_socket_as.close()
client_socket_tgsv.close()
