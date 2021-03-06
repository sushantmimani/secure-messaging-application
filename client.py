import socket, sys, time, binascii, os, pickle, getpass, ast, ConfigParser, threading, math

from select import select


from CryptoUtils import create_hash, keygen, generate_key_from_password, load_public_key, \
    symmetric_encryption, asymmetric_encryption, generate_password_hash, symmetric_decryption, \
    serialize_public_key, sign_message, serialize_private_key, get_diffie_hellman_params, \
    generate_key_from_password_no_salt


class ChatClient:
    def __init__(self, port, ip, pub_key):
        self.exit_from_server_nonce = ""
        self.MAX_RETRIES = 3
        self.logged_in = False
        self.terminate_nonce = ""
        self.nonceN2 = ""
        self.nonceN3 = ""
        self.nonce = ""
        self.disconnect = "disconnect"
        self.exit = "exit"
        self.BUFFER_SIZE = 65507
        self.server_pub_key = load_public_key(pub_key)
        self.username = ""
        self.password = ""
        self.sIP = ip
        self.UDP_PORT = port

        self.salt = os.urandom(16)

        # Initialize a socket for the client
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_shared_keys = {}
        self.client_addresses = {}
        self.sender_addresses = {}
        self.message_for_client = ""
        self.dh_session_keys = {}
        try:
            self.sock.connect((self.sIP, self.UDP_PORT))
        except:
            print "Server unavailable. Please try again later"
            os._exit(0)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.start_recv_sock()

    def start_send_thread(self):
        threading.Thread(target=self.start).start()

    def start_recv_sock(self):
        try:
            self.recv_socket.bind((self.sIP, 0))
            threading.Thread(target=self.start_listening).start()
        except socket.error:
            print 'Failed to start the socket for receiving messages'

    def login(self):
        count = 1
        while count <= self.MAX_RETRIES and self.logged_in == False:

            self.username = raw_input("Please enter username: ")
            self.password = getpass.getpass("Please enter password: ")
            self.password_hash = generate_password_hash(self.username, self.password)
            self.derived_key = generate_key_from_password(self.password_hash, self.salt)
            # Parameters to allow server to register a user on sign-in
            params = {
                "command": "login",
                "username": self.username,
            }

            self.sock.send(pickle.dumps(params))
            data = self.sock.recv(self.BUFFER_SIZE)
            if data == "Already logged in":
                print "Already logged in. Terminating this session"
                os._exit(0)
            if data == "User not registered":
                print "User not registered. Please retry"
                count += 1
                continue
            challenge = data.split()
            h1 = create_hash(challenge[0])
            h2 = create_hash(challenge[1])
            answer = str(int(binascii.hexlify(h1), 16) & int(binascii.hexlify(h2), 16))
            nonce_1 = str(time.time())
            message = answer + "\n" + self.username + "\n" + self.password_hash + "\n" + self.salt + "\n" + nonce_1
            encrypted_message = asymmetric_encryption(self.server_pub_key, message)
            self.sock.send(encrypted_message)
            data = self.sock.recv(self.BUFFER_SIZE)
            if data == "Authentication failed!":
                print "Authentication failed!Please retry"
                count += 1
                continue
            data = pickle.loads(data)
            n1, n2 = symmetric_decryption(self.derived_key, data["iv"], data["tag"], data["message"]).split("\n")
            if n1 == nonce_1:
                self.private_key, self.public_key = keygen()
                serialize_private_key(self.private_key, self.username)
                nonce_3 = str(time.time())
                message = n2 + "\n" + nonce_3 + "\n" + serialize_public_key(self.public_key)
                enc_msg, iv, tag = symmetric_encryption(self.derived_key, message)
                payload = {
                    "message": str(enc_msg),
                    "iv": str(iv),
                    "tag": str(tag),
                    "client_port": self.recv_socket.getsockname()
                }
                self.sock.send(pickle.dumps(payload))
                data_1 = self.sock.recv(self.BUFFER_SIZE)
                data = pickle.loads(data_1)
                n3, n4 = symmetric_decryption(self.derived_key, data["iv"], data["tag"], data["message"]).split("\n")
                if n3 == nonce_3:
                    print "Server authenticated and registered with server"
                    print("Client Starting...")
                    self.logged_in = True
                    self.start_send_thread()
                else:
                    print "Authentication failed!Please retry"
                    count += 1
                    continue
            else:
                print "Authentication failed!Please retry"
                count += 1
                continue
        if count > self.MAX_RETRIES and self.logged_in == False:
            print "Maximum retries exceed. Terminating now"
            os._exit(0)

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

            self.sock.send(pickle.dumps(new_message))
            data_1 = self.sock.recv(self.BUFFER_SIZE)
            data = pickle.loads(data_1)
            users, ni, ni1 = symmetric_decryption(self.derived_key, data["iv"], data["tag"], data["ciphertext"]).split(
                "\n")
            temp = ast.literal_eval(users)
            user_list = []
            for x in temp:
                if x != self.username:
                    user_list.append(x)
            if len(user_list) == 0:
                print "<-- No other users online"
            else:
                print("<-- Signed In Users: {0}").format(','.join(user_list))  # Print user list

    def is_user_address_available(self, user):
        final = self.sender_addresses.update(self.client_addresses)
        if self.sender_addresses:
            for u in self.sender_addresses.keys():
                if u == user:
                    return self.sender_addresses[u]

        elif final:
            for u in final.keys():
                if u == user:
                    return final[u]
        else:
            return False

    # This function handles the overall working of the client
    def start(self):
        try:
            print "Command list: list,send < username > < message > and exit. Have fun!"
            inp = [sys.stdin, self.sock]
            while True:

                # valid commands: list, send, terminate
                input_list, output_list, exception_list = select(inp, [], [])
                for s in input_list:
                    if s == sys.stdin:
                        input = raw_input()
                        input_array = input.split(" ")
                        command_val = input_array[0].strip()
                        # Perform different actions based on the command
                        if command_val == "list":
                            self.print_user_list(input_array)
                        elif command_val == self.exit:
                            if len(input_array) != 1:
                                print "Incorrect usage. Correct usage 'exit' to exit from server"
                            for key in self.dh_session_keys:
                                self.perform_client_session_termination(key)
                            self.perform_server_session_termination()

                        elif command_val == self.disconnect:
                            if len(input_array) != 2:
                                print "incorrect usage. Correct usage disconnect <client_name>"
                                continue
                            if (input_array[1] not in self.client_shared_keys.keys()) or (
                                    not self.is_user_address_available(input_array[1])):
                                print "connection to " + input_array[1] + " not established yet."
                            else:
                                self.perform_client_session_termination(input_array[1])
                        # user is trying to send message to the receiver
                        elif command_val == "send":
                            if len(input_array) < 3:
                                print("Invalid Input!")
                            else:
                                chat_with_user = input_array[1]
                                self.message_for_client = " ".join(input_array[2:])
                                user_address = self.is_user_address_available(chat_with_user)
                                if (chat_with_user in self.dh_session_keys.keys()) and user_address:
                                    self.send_message_to_client(self.message_for_client,
                                                                self.dh_session_keys[chat_with_user], user_address)
                                else:
                                    nonce_l = str(time.time())
                                    message = nonce_l
                                    ct, iv, tag = symmetric_encryption(self.derived_key, message)
                                    signature = sign_message(self.private_key, ct)
                                    if (chat_with_user == self.username):
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

                                    self.sock.send(pickle.dumps(new_message))
                                    # receive message from server with ticket-to-client etc
                                    data = self.sock.recv(self.BUFFER_SIZE)  # buffer size is 65507 bytes
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
                                        decrypted_response = symmetric_decryption(self.derived_key, iv1, tag1,
                                                                                  server_response_totalk)
                                        decrypted_response_dict = pickle.loads(decrypted_response)
                                        # get the ticket_to_Receiver
                                        server_generated_shared_key = decrypted_response_dict["shared_key"]
                                        self.client_shared_keys[chat_with_user] = server_generated_shared_key
                                        receiver_address = decrypted_response_dict["receiver"][0]
                                        receiver_address_port = decrypted_response_dict["receiver"][1]
                                        self.client_addresses[chat_with_user] = (
                                            receiver_address, receiver_address_port)

                                        ticket_to_receiver = decrypted_response_dict["ticket_to"]
                                        payload = {
                                            "ticket_to_receiver": ticket_to_receiver,
                                            "message": "chat_request",
                                            "iv": receiver_iv,
                                            "tag": receiver_tag
                                        }

                                        self.send_socket.sendto(pickle.dumps(payload),
                                                                (receiver_address, receiver_address_port))

                        else:
                            if len(command_val) != 0:
                                print("Invalid Input!")
                                print "Command list: list,send < username > < message > and exit. Have fun!"

        except KeyboardInterrupt:
            self.perform_server_session_termination()
            os._exit(0)
        except Exception as error:
            print "Corresponding thread killed", error
            os._exit(0)

    def perform_server_session_termination(self):
        term_nonce = str(time.time())
        self.exit_from_server_nonce = term_nonce
        terminate_encrypted_data, term_iv, term_tag = symmetric_encryption(self.derived_key, term_nonce)
        signature = sign_message(self.private_key, terminate_encrypted_data)
        payload = {
            "command": "exit",
            "ciphertext": terminate_encrypted_data,
            "user": self.username,
            "signature": signature,
            "iv": term_iv,
            "tag": term_tag
        }

        self.sock.send(pickle.dumps(payload))
        os.remove(self.username + "_private.pem")
        os.remove(self.username + "_public.pem")
        self.sock.close()
        os._exit(0)

    def perform_client_session_termination(self, client):
        self.terminate_nonce = str(time.time())
        encrypted_msg, dis_iv, dis_tag = symmetric_encryption(self.client_shared_keys[client], self.terminate_nonce)
        payload_to_send = {
            "message": "disconnect",
            "data": encrypted_msg,
            "user": self.username,
            "iv": dis_iv,
            "tag": dis_tag
        }
        self.send_socket.sendto(pickle.dumps(payload_to_send), self.is_user_address_available(client))

    def start_listening(self):
        try:
            while True:
                data, address = self.recv_socket.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
                data_dict = pickle.loads(data)
                if "message" in data_dict.keys():
                    message = data_dict["message"]
                    if message == "deleted_from_server":
                        server_del_iv = data_dict["iv"]
                        server_del_tag = data_dict["tag"]
                        server_delete_message = data_dict["data"]
                        deleted_server_decrypted_message = symmetric_decryption(self.derived_key, server_del_iv,
                                                                                server_del_tag, server_delete_message)
                        if float(self.exit_from_server_nonce) + 1 == float(deleted_server_decrypted_message):
                            self.derived_key = ""
                            print "Deleted derived key for server from client: " + self.username

                    if message == "client_deleted":
                        del_iv = data_dict["iv"]
                        del_tag = data_dict["tag"]
                        deleted_user = data_dict["user"]
                        delete_confirm_nonce = symmetric_decryption(self.client_shared_keys[deleted_user], del_iv,
                                                                    del_tag, data_dict["data"])
                        if float(self.terminate_nonce) == float(delete_confirm_nonce) - 1:
                            print "terminated"
                            del self.client_shared_keys[deleted_user]
                            del self.dh_session_keys[deleted_user]
                            continue

                    if message == "disconnect":
                        sender_user = data_dict["user"]
                        if sender_user in self.client_shared_keys.keys():
                            decrypted_msg_nonce = symmetric_decryption(self.client_shared_keys[sender_user],
                                                                       data_dict["iv"], data_dict["tag"],
                                                                       data_dict["data"])
                            response_nonce = float(decrypted_msg_nonce) + 1
                            encrypted_res, res_iv, res_tag = symmetric_encryption(self.client_shared_keys[sender_user],
                                                                                  str(response_nonce))
                            terminate_valid_payload = {
                                "message": "client_deleted",
                                "data": encrypted_res,
                                "iv": res_iv,
                                "tag": res_tag,
                                "user": self.username
                            }
                            self.send_socket.sendto(pickle.dumps(terminate_valid_payload),
                                                    self.is_user_address_available(sender_user))
                            del self.client_shared_keys[data_dict["user"]]
                            del self.dh_session_keys[data_dict["user"]]

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
                        self.nonce = decrypted_message_dict["nonce"]
                        # receiver here starts to reply for sender's(A) request to start communication.
                        self.nonceN2 = str(time.time())
                        self.nonceN3 = str(time.time())

                        reply_message = {
                            "N1": self.nonceN2,
                            "N2": self.nonceN3
                        }
                        encrypted_response, nonce_iv, nonce_tag = symmetric_encryption(shared_key,
                                                                                       pickle.dumps(reply_message))
                        # encrypted_response = "response"

                        payload = {
                            "encrypted_response": encrypted_response,
                            "message": "start_dh",
                            "client": self.username,
                            "iv": nonce_iv,
                            "tag": nonce_tag,
                            "user": self.username
                        }

                        self.send_socket.sendto(pickle.dumps(payload), (sender_address, sender_address_port))
                        # starting diffie helmann key exchange here now
                    if message == "start_dh":
                        nonce_iv = data_dict["iv"]
                        nonce_tag = data_dict["tag"]
                        nonce_user = data_dict["user"]
                        nonce_values = symmetric_decryption(self.client_shared_keys[nonce_user], nonce_iv, nonce_tag,
                                                            data_dict["encrypted_response"])
                        nonce_values_dict = pickle.loads(nonce_values)

                        self.perform_diffie_hellman(data_dict["client"],
                                                    self.username,
                                                    nonce_values_dict["N2"])
                    # step1 is A->B with message (g^a mod p), B receives this message
                    if message == "diffie-step1":
                        # This will be received by the receiver always. In case for A->B, B will receive this message
                        params = get_diffie_hellman_params()
                        g = params["g"]
                        # The client(B) will only know 'b' of diffie hellman only
                        b = params["b"]
                        p = params["p"]
                        part = data_dict["part"]
                        sender_name = data_dict["sender-name"]
                        diffie_msg_step1_iv = data_dict["iv"]
                        diffie_msg_step1_tag = data_dict["tag"]
                        # plaintext is g^a mod p, plaintest=x in DH algorithm
                        plaintext_data = symmetric_decryption(self.client_shared_keys[sender_name],
                                                              diffie_msg_step1_iv,
                                                              diffie_msg_step1_tag, part)
                        plaintext_data_dict = pickle.loads(plaintext_data)
                        x = plaintext_data_dict["x"]
                        if plaintext_data_dict["nonceN2"] == self.nonceN2:
                            # computing the power(x, b) mod b part
                            session_key_val = math.pow(float(x), b) % p
                            # print session_key_val
                            session_key = generate_key_from_password_no_salt(str(session_key_val))
                            self.dh_session_keys[sender_name] = session_key

                            # this is the creation of y = (g^b mod p) part from side B
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

                            self.send_socket.sendto(pickle.dumps(payload), self.sender_addresses[sender_name])
                        else:
                            print "invalid nonce response from client"
                            continue

                    if message == "diffie-step2":
                        # This will be received by the sender always. In case for A->B, A will receive this message
                        params = get_diffie_hellman_params()
                        a = params["a"]
                        p = params["p"]
                        sender_name = data_dict["sender-name"]
                        # plaintext is g^b mod p
                        diffie_msg_iv = data_dict["iv"]
                        diffie_msg_tag = data_dict["tag"]
                        part = data_dict["part"]
                        # the plaintext is (g^b mod p) part. This is y in diffie hellman algorithm
                        plaintext = symmetric_decryption(self.client_shared_keys[sender_name], diffie_msg_iv,
                                                         diffie_msg_tag, part)
                        # computing the power(y, a) mod p part here.
                        session_key_val_sender = math.pow(float(plaintext), a) % p
                        # print session_key_val_sender
                        session_key = generate_key_from_password_no_salt(str(session_key_val_sender))
                        # sender_name is B in communication from A->B
                        self.dh_session_keys[sender_name] = session_key
                        # sender_name is the name of sender who sent this message
                        self.send_message_to_client(self.message_for_client, self.dh_session_keys[sender_name],
                                                    self.client_addresses[sender_name])
                    # this is message receiving part in diffie helman message exchange. B receives this message in
                    # communication  A->B
                    if message == "chat_message":
                        message_iv = data_dict["iv"]
                        message_tag = data_dict["tag"]
                        sender_name = data_dict["sender_name"]
                        res = symmetric_decryption(self.dh_session_keys[sender_name][:32], message_iv, message_tag, data_dict["cipher_message"])
                        print(sender_name + ":>" + res)
        except KeyboardInterrupt:
            self.perform_server_session_termination()
            os._exit(0)

    def send_message_to_client(self, message, session_key, address):
        text_data, clien_iv, clien_tag = symmetric_encryption(session_key[:32], self.message_for_client)
        payload = {
            "message": "chat_message",
            "iv": clien_iv,
            "tag": clien_tag,
            "cipher_message": text_data,
            "data": self.message_for_client,
            "sender_name": self.username
        }

        self.send_socket.sendto(pickle.dumps(payload), address)

    # A starts this communication, send (g^a mod p) to B
    def perform_diffie_hellman(self, client, sender, nonce_message):
        self.nonceN2 = nonce_message
        self.nonceN3 = str(time.time())
        shared_key = self.client_shared_keys[client]
        dh_params = get_diffie_hellman_params()
        a = dh_params["a"]
        g = dh_params["g"]
        p = dh_params["p"]

        gPowAModP = math.pow(g, a) % p
        powPart = {"x": gPowAModP, "nonceN2": self.nonceN2, "nonceN3": self.nonceN3}

        part, iv, tag = symmetric_encryption(shared_key, pickle.dumps(powPart))
        payload = {
            "sender-name": sender,
            "message": "diffie-step1",
            "part": part,
            "iv": iv,
            "tag": tag,
        }

        self.send_socket.sendto(pickle.dumps(payload), self.client_addresses[client])


if __name__ == "__main__":
    config = ConfigParser.ConfigParser()
    config.read('config/client.ini')
    server_port = config.getint('server_config', 'port')
    server_ip = config.get('server_config', 'ip')
    server_pub_key = config.get('server_config', 'server_pub_key')
    cs = ChatClient(server_port, server_ip, server_pub_key)
    cs.login()
