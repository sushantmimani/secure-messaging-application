import argparse, socket, json, sys, time, binascii, os, pickle, getpass, ast
import threading
import math

from select import select
from CryptoUtils import create_hash, keygen, generate_key_from_password, load_public_key, \
                        symmetric_encryption, asymmetric_encryption, generate_password_hash, symmetric_decryption,\
                        serialize_public_key, sign_message, serialize_private_key, get_diffie_hellman_params, generate_key_from_password_no_salt


class ChatClient:
    def __init__(self, args):
        self.BUFFER_SIZE = 65507
        self.permitted_size = self.BUFFER_SIZE-32
        self.username = raw_input("Please enter username: ")
        self.password = getpass.getpass("Please enter password: ")
        self.sIP = args.sIP
        self.UDP_PORT = int(args.sp)
        self.private_key, self.public_key = keygen()
        serialize_private_key(self.private_key, "sushant")
        self.password_hash = generate_password_hash(self.username, self.password)
        self.salt = os.urandom(16)
        self.derived_key = generate_key_from_password(self.password_hash, self.salt)
        # Initialize a socket for the client
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_shared_keys = {}
        self.client_addresses = {}
        self.sender_addresses = {}
        self.message_for_client = ""
        self.dh_session_keys = {}

    def start_client_prompt(self):
        # Parameters to allow server to register a user on sign-in
        params = {
            "command": "login",
            "username": self.username
        }
        self.sock.sendto(pickle.dumps(params), (self.sIP, self.UDP_PORT))
        data, address = self.sock.recvfrom(self.BUFFER_SIZE)
        if data == "Already logged in":
            print "Already logged in. Terminating this session"
            sys.exit()
        if data == "User not registered":
            print "User not registered. Terminating session"
            sys.exit()
        challenge = data.split()
        h1 = create_hash(challenge[0])
        h2 = create_hash(challenge[1])
        answer = str(int(binascii.hexlify(h1), 16) & int(binascii.hexlify(h2), 16))
        nonce_1 = str(time.time())
        self.server_pub_key = load_public_key("server_public.pem")
        message = answer + "\n"+self.username+"\n"+self.password_hash+"\n"+self.salt+"\n"+nonce_1
        encrypted_message = asymmetric_encryption(self.server_pub_key, message)
        self.sock.sendto(encrypted_message, (self.sIP, self.UDP_PORT))
        data, address = self.sock.recvfrom(self.BUFFER_SIZE)
        if data == "Authentication failed!":
            print "Authentication failed!Terminating session"
            sys.exit()
        data = pickle.loads(data)
        n1, n2 = symmetric_decryption(self.derived_key, data["iv"], data["tag"], data["message"]).split("\n")
        if n1 == nonce_1:
            nonce_3 = str(time.time())
            message = n2+"\n"+nonce_3+"\n"+serialize_public_key(self.public_key)
            enc_msg, iv, tag = symmetric_encryption(self.derived_key, message)
            payload = {
                "message": str(enc_msg),
                "iv": str(iv),
                "tag": str(tag)
                }
            self.sock.sendto(pickle.dumps(payload), (self.sIP, self.UDP_PORT))
            data, address = self.sock.recvfrom(self.BUFFER_SIZE)
            data = pickle.loads(data)
            n3, n4 = symmetric_decryption(self.derived_key, data["iv"], data["tag"], data["message"]).split("\n")
            if n3 == nonce_3:
                print "Server authenticated and registered with server"
                print("Client Starting...")
                print("start receiving messages from client")
                # threading.Thread(target=self.start_listening()).start()
                self.start()
            else:
                print "Authentication failed!Terminating"
                sys.exit()
        else:
            print "Authentication failed!Terminating"
            sys.exit()

    # Display messages received from other signed-in users
    def print_received_message(self):
        self.start_listening()
        # data, address = self.sock.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
        # print("<-- <From {0}:{1}:{2}>  " + json.loads(data)["message"]).format(address[0],
        #                                                                        address[1],
        #                                                                        json.loads(data)["user"])

    def print_user_list(self, input_array):
        if len(input_array) > 1:  # List followed by anything is an invalid command and will not be processed
            print("Invalid Input!")
        else:
            nonce_l = str(time.time())
            message = nonce_l
            ct, iv, tag = symmetric_encryption(self.derived_key, message)
            signature = sign_message(self.private_key, ct)
            new_message = {
                "ciphertext": str(ct),
                "user": self.username,
                "command": "list",
                "iv": iv,
                "tag": tag,
                "signature": signature
            }

            # self.sock.sendto(json.dumps({"command": "list"}), (self.sIP, self.UDP_PORT))
            self.sock.sendto(pickle.dumps(new_message), (self.sIP, self.UDP_PORT))
            data, address = self.sock.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
            data = pickle.loads(data)
            users, ni,ni1 = symmetric_decryption(self.derived_key,data["iv"], data["tag"],data["ciphertext"]).split("\n")
            temp = ast.literal_eval(users)
            user_list = []
            for x in temp:
                if x != self.username:
                    user_list.append(x)
            if len(user_list) == 0:
                print "<-- No other users online"
            else:
                print("<-- Signed In Users: {0}").format(','.join(user_list)) # Print user list


    def is_user_address_available(self, user):
        final = self.sender_addresses.update(self.client_addresses)
        if final:
            for u in final:
                if u[0] == user:
                    return u
        return False


    # This function handles the overall working of the client
    def start(self):
        try:
            inp = [sys.stdin, self.sock]
            while 1:
                print('--> Enter command:')
                input_list, output_list, exception_list = select(inp, [], [])
                for s in input_list:
                    if s == self.sock:
                        self.print_received_message()
                    elif s == sys.stdin:
                        input = raw_input()
                        input_array = input.split(" ")
                        # Perform different actions based on the command
                        if input_array[0] == "list":
                            self.print_user_list(input_array)
                        #     user is trying to send message to the receiver
                        elif input_array[0] == "send":
                            if len(input_array) < 3:
                                print("Invalid Input!")
                            else:
                                chat_with_user = input_array[1]
                                self.message_for_client = input_array[2]
                                user_address = self.is_user_address_available(chat_with_user)
                                if (chat_with_user in self.dh_session_keys.keys()) and user_address:
                                    print("sending message to client")
                                    self.send_message_to_client(self.message_for_client, self.dh_session_keys[chat_with_user], chat_with_user)
                                #     do something
                                else:
                                    nonce_l = str(time.time())
                                    message = nonce_l
                                    ct, iv, tag = symmetric_encryption(self.derived_key, message)
                                    signature = sign_message(self.private_key, ct)

                                    if(chat_with_user == self.username):
                                        print('Sender and receiver are the same.')
                                        continue
                                    new_message = {
                                        "ciphertext": ct,
                                        "user": self.username,
                                        "chat_with": chat_with_user,
                                        "command": "talk-to",
                                        "iv": iv,
                                        "tag": tag,
                                        "nounce": nonce_l,
                                        "signature": signature
                                    }

                                    self.sock.sendto(pickle.dumps(new_message), (self.sIP, self.UDP_PORT))
                                    # receive message from server with ticket-to-client etc
                                    data, address = self.sock.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
                                    if data == "null":
                                        print("User doesn't exist!")
                                    else:
                                        temp = pickle.loads(data)
                                        if temp["is_valid_user"] == False:
                                            print "user not available to chat. Please try later. Use List command to find list of available users"
                                            continue
                                        server_response_totalk = temp["ciphertext"]
                                        iv1 = temp["iv1"]
                                        tag1 = temp["tag1"]
                                        receiver_iv = temp["iv"]
                                        receiver_tag = temp["tag"]
                                        # decrypt response from server to get keys and ticket_to data for communicating to receiver
                                        decrypted_response = symmetric_decryption(self.derived_key, iv1, tag1, server_response_totalk)
                                        decrypted_response_dict = pickle.loads(decrypted_response)
                                        # get the ticket_to_Receiver
                                        server_generated_shared_key = decrypted_response_dict["shared_key"]
                                        self.client_shared_keys[chat_with_user] = server_generated_shared_key
                                        receiver_address = decrypted_response_dict["receiver"][0]
                                        receiver_address_port = decrypted_response_dict["receiver"][1]
                                        self.client_addresses[chat_with_user] = (receiver_address, receiver_address_port)
                                        nounce_response_from_server = decrypted_response_dict["nonce"]
                                        # uncomment below lines later
                                        # if nonce_response_from_server != int(nonce_l) + 1:
                                        #     print "invalid response from server, nonce did not match"
                                        #     continue
                                        ticket_to_receiver = decrypted_response_dict["ticket_to"]
                                        # send the ticket_to_receiver to the receiver client, the receiver client can decrypt the message using its
                                        # key(password) and respond back with nounce encrptd by the shared key
                                        payload = {
                                            "ticket_to_receiver": ticket_to_receiver,
                                            "message": "chat_request",
                                            "iv": receiver_iv,
                                            "tag": receiver_tag
                                        }

                                        self.sock.sendto(pickle.dumps(payload), (receiver_address, receiver_address_port))

                                        # self.sock.sendto(pickle.dumps(new_message), (self.sIP, self.UDP_PORT))
                                        # message = ' '.join(input_array[2:])
                                        # if len(message.encode('utf-8')) > self.permitted_size:
                                        #     while len(message.encode('utf-8'))>self.permitted_size:
                                        #         toSend=message[0:self.permitted_size]
                                        #         self.sock.sendto(json.dumps({
                                        #             "user": self.username, "message": toSend}),
                                        #             (temp[0], int(temp[1])))
                                        #         message = message[self.permitted_size:]
                                        #     self.sock.sendto(json.dumps({
                                        #         "user": self.username, "message": message}),
                                        #         (temp[0], int(temp[1])))
                                        # else:
                                        #     self.sock.sendto(json.dumps({
                                        #         "user":self.username,"message":' '.join(input_array[2:])}),
                                        #         (temp[0], int(temp[1])))
                        else:
                            print("Invalid Input!")
        except KeyboardInterrupt:
            self.sock.sendto(json.dumps({"command": "terminate", "username": self.username}), (self.sIP, self.UDP_PORT))
            self.sock.close()

    def start_listening(self):
        print "started receiving ...."
        data, address = self.sock.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
        data_dict = pickle.loads(data)
        if "message" in data_dict.keys():
            message = data_dict["message"]
            # this message is received by client(client B) for a chat request initiated bycleint B for A->B comm
            if message == "chat_request":
                ticket_to_receiver = data_dict["ticket_to_receiver"]
                iv = data_dict["iv"]
                tag = data_dict["tag"]
                # this would get the decrypted ticket-to-receiver part, which contains the key, sender's identity, and
                # nonce
                # ATM I do not know where to get the iv and tag from
                decrypted_message = symmetric_decryption(self.derived_key, iv, tag, ticket_to_receiver)
                decrypted_message_dict = pickle.loads(decrypted_message)
                shared_key = decrypted_message_dict["shared_key"]
                sender_name = decrypted_message_dict["sender_name"]
                sender_address = decrypted_message_dict["sender_addr"][0]
                sender_address_port = decrypted_message_dict["sender_addr"][1]
                self.sender_addresses[sender_name] = (sender_address, sender_address_port)
                self.client_shared_keys[sender_name] = shared_key
                nonce = decrypted_message_dict["nonce"]

                nonceN2 = str(time.time())
                nonceN3 = str(time.time())

                reply_message = {
                        "N2": nonceN2,
                        "N3": nonceN3
                }
                # encrypted_response, iv, tag = symmetric_encryption(shared_key, pickle.loads(reply_message))
                encrypted_response = "response"

                payload = {
                    "encrypted_response": encrypted_response,
                    "message": "start_dh",
                    "client": self.username
                }

                self.sock.sendto(pickle.dumps(payload), (sender_address, sender_address_port))
                # starting diffie helmann key exchange here now
            if message == "start_dh":
                self.perform_diffie_hellman(data_dict["client"], self.username, data_dict["encrypted_response"])
            #     step1 is A->B with message (g^a mod p), B receives this message
            if message == "diffie-step1":
                params = get_diffie_hellman_params()
                part = data_dict["part"]
                sender_name = data_dict["sender-name"]
                diffie_msg_step1_iv = data_dict["iv"]
                diffie_msg_step1_tag = data_dict["tag"]
                # plaintext is g^a mod p
                plaintext = symmetric_decryption(self.client_shared_keys[sender_name], diffie_msg_step1_iv, diffie_msg_step1_tag, part)
                session_key = generate_key_from_password_no_salt(str((float(plaintext) * params["b"]) % params["p"]))
                self.dh_session_keys[sender_name] = session_key
                g = params["g"]
                b = params["b"]
                gPowBModP = math.pow(g, b) % params["p"]
                powPart = gPowBModP
                shard_key = self.client_shared_keys[sender_name]
                part, iv, tag = symmetric_encryption(shard_key, str(powPart))
                payload = {
                    "sender-name": self.username,
                    "message": "diffie-step2",
                    "part": part,
                    "iv": iv,
                    "tag": tag
                }

                self.sock.sendto(pickle.dumps(payload), self.sender_addresses[sender_name])

            if message == "diffie-step2":
                params = get_diffie_hellman_params()
                sender_name = data_dict["sender-name"]
                # plaintext is g^b mod p
                diffie_msg_iv = data_dict["iv"]
                diffie_msg_tag = data_dict["tag"]
                part = data_dict["part"]
                plaintext = symmetric_decryption(self.client_shared_keys[sender_name], diffie_msg_iv, diffie_msg_tag, part)
                session_key = generate_key_from_password_no_salt(str((float(plaintext) * params["b"]) % params["p"]))
                self.dh_session_keys[sender_name] = session_key
                self.send_message_to_client(self.message_for_client, self.dh_session_keys[sender_name], self.client_addresses[sender_name])
            if message == "chat_message":
                data = data_dict["data"]
                message_iv = data_dict["iv"]
                message_tag = data_dict["tag"]
                sender_name = data_dict["sender_name"]
                # received_message = symmetric_decryption(self.dh_session_keys[sender_name], message_iv, message_tag, data)
                print("received message from: " + sender_name + "message is :" + data)
                # print("received message from: " + sender_name + "message is :" + received_message)

    def send_message_to_client(self, message, session_key, address):
        # ciphertext, iv, tag = symmetric_encryption(session_key, message)
        payload = {
            "message": "chat_message",
            "iv": "iv",
            "tag": "tag",
            "data": self.message_for_client,
            "sender_name": self.username
        }

        self.sock.sendto(pickle.dumps(payload), address)

    def perform_diffie_hellman(self, client, sender, nonce_message):
        shared_key = self.client_shared_keys[client]
        dh_params = get_diffie_hellman_params()
        a = dh_params["a"]
        g = dh_params["g"]
        p = dh_params["p"]

        gPowAModP = math.pow(g, a) % p
        powPart = gPowAModP

        part, iv, tag = symmetric_encryption(shared_key, str(powPart))
        payload = {
            "sender-name": sender,
            "message": "diffie-step1",
            "part": part,
            "iv": iv,
            "tag": tag
        }
        self.sock.sendto(pickle.dumps(payload), self.client_addresses[client])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-sip", "--sIP")
    parser.add_argument("-sp", "--sp")
    args = parser.parse_args()
    cs = ChatClient(args)
    cs.start_client_prompt()

