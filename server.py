import socket, time, random, binascii, pickle, os, ConfigParser
from threading import Thread
from CryptoUtils import create_hash, load_users, load_public_key, symmetric_encryption, asymmetric_decryption, \
    load_private_key, generate_key_from_password, keygen, symmetric_decryption, verify_signature


class ChatServer:
    def __init__(self, port, ip, pub_key, priv_key):
        self.server_pub_key = load_public_key(pub_key)
        self.server_pvt_key = load_private_key(priv_key)
        self.BUFFER_SIZE = 65507
        self.UDP_IP = ip
        """initialize the chatServer on the UDP port."""
        self.PORT = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("", self.PORT))
        self.sock.listen(20)
        self.users = {}
        self.users_pubkeys = {}
        self.users_derivedkeys = {}
        self.registered_users = load_users()
        self.client_port = {}
        self.start_thread()

    def start_thread(self):
        while True:
            connection_socket, (address, port) = self.sock.accept()
            Thread(target=self.receive_messages, args=(connection_socket, (address, port),)).start()

    def receive_messages(self, connection_socket, address):
        try:
            while True:
                data = connection_socket.recv(self.BUFFER_SIZE)
                # if not data:
                #     break
                parsed_data = pickle.loads(data)
                if parsed_data["command"] == "login":
                    if self.registered_users.get(parsed_data["username"]) is None:
                        connection_socket.send("User not registered")
                    if self.users.get(parsed_data["username"]):
                        connection_socket.send("Already logged in")
                    else:
                        cha = str(time.time()) + " " + str(random.random())
                        connection_socket.send(cha)
                        challenge = cha.split()
                        h1 = create_hash(challenge[0])
                        h2 = create_hash(challenge[1])
                        answer = str(int(binascii.hexlify(h1), 16) & int(binascii.hexlify(h2), 16))
                        data = connection_socket.recv(self.BUFFER_SIZE)
                        ans, username, password, salt, nonce_1 = asymmetric_decryption(self.server_pvt_key, data).split("\n")
                        user_derived_key = generate_key_from_password(password, salt)
                        if answer == ans and password == self.registered_users[username]:
                            nonce_2 = str(time.time())
                            message = nonce_1 + "\n" + nonce_2
                            enc_msg, iv, tag = symmetric_encryption(user_derived_key, message)
                            payload = {
                                "message": str(enc_msg),
                                "iv": str(iv),
                                "tag": str(tag)
                            }
                            connection_socket.send(pickle.dumps(payload))
                            data_1 = connection_socket.recv(self.BUFFER_SIZE)
                            data = pickle.loads(data_1)
                            client_port = data["client_port"]
                            data = symmetric_decryption(user_derived_key, data["iv"], data["tag"], data["message"]).split(
                                "\n")
                            n2 = data[0]
                            n3 = data[1]
                            public_pem = '\n'.join([str(x) for x in data[2:]])
                            file = open(username + "_public.pem", "w")
                            file.write(public_pem)
                            file.close()
                            if n2 == nonce_2:
                                self.users[username] = address
                                self.client_port[username] = client_port
                                self.users_pubkeys[username] = username + "_public.pem"
                                self.users_derivedkeys[username] = user_derived_key
                                nonce_4 = str(time.time())
                                message = n3 + "\n" + nonce_4
                                enc_msg, iv, tag = symmetric_encryption(user_derived_key, message)
                                payload = {
                                    "message": str(enc_msg),
                                    "iv": str(iv),
                                    "tag": str(tag)
                                }
                                connection_socket.send(pickle.dumps(payload))
                        else:
                            connection_socket.send("Authentication failed!")
                elif parsed_data["command"] == "list":
                    signature = parsed_data["signature"]
                    user = parsed_data["user"]
                    validity = verify_signature(user + "_public.pem", signature, parsed_data["ciphertext"])
                    if validity == "VERIFIED":
                        nonce_1 = str(time.time())
                        # shared_key part is missing here, need to figure out what should be the public key
                        nonce_l = symmetric_decryption(self.users_derivedkeys.get(user), parsed_data["iv"],
                                                       parsed_data["tag"], parsed_data["ciphertext"])
                        nonce_l1 = str(time.time())
                        response = str(self.users) + "\n" + nonce_l + "\n" + nonce_l1
                        enc_response, iv, tag = symmetric_encryption(self.users_derivedkeys.get(user), response)
                        payload = {
                            "ciphertext": enc_response,
                            "iv": iv,
                            "tag": tag
                        }
                        connection_socket.send(pickle.dumps(payload))
                elif parsed_data["command"] == "exit":
                    signature = parsed_data["signature"]
                    user = parsed_data["user"]
                    validity = verify_signature(user + "_public.pem", signature, parsed_data["ciphertext"])
                    if validity:
                        terminate_request_nonce = symmetric_decryption(self.users_derivedkeys.get(user),
                                                                       parsed_data["iv"],
                                                                       parsed_data["tag"],
                                                                       parsed_data["ciphertext"])
                        response_terminate_nonce = float(terminate_request_nonce) + 1
                        encrypted_response_nonce, res_iv, res_tag = symmetric_encryption(self.users_derivedkeys.get(user),
                                                                                 str(response_terminate_nonce))
                        payload = {
                            "message": "deleted_from_server",
                            "data": encrypted_response_nonce,
                            "iv": res_iv,
                            "tag": res_tag
                        }

                        connection_socket.send(pickle.dumps(payload))
                        # deleting the derived key for the user
                        del self.users_derivedkeys[user]
                        del self.users[user]
                        del self.client_port[user]
                        del self.users_pubkeys[user]
                        print "Deleted all data for : " + user


                elif parsed_data["command"] == "talk-to":
                    signature = parsed_data["signature"]
                    message_iv = parsed_data["iv"]
                    message_tag = parsed_data["tag"]
                    client_user = parsed_data["chat_with"]
                    if client_user not in self.users.keys():
                        payload = {
                            "is_valid_user": False
                        }
                        connection_socket.send(pickle.dumps(payload))
                    else:
                        user = parsed_data["user"]
                        validity = verify_signature(user + "_public.pem", signature, parsed_data["ciphertext"])
                        if validity == "VERIFIED":
                            nonce_1 = str(time.time())
                            private_key, public_key = self.generate_session_key_for()
                            # shared_key part is missing here, need to figure out what should be the public key
                            client_name = parsed_data["chat_with"]
                            # this step encrypts the message ticket-to-client with the derived key of the client
                            salt = os.urandom(16)
                            shared_key_for_client = generate_key_from_password("password", salt)
                            ticket_to = pickle.dumps({"shared_key": shared_key_for_client, "sender_name": user,
                                                      "sender_addr": self.client_port[user],
                                                      "nonce": nonce_1})
                            receiver_res, iv, tag = symmetric_encryption(self.users_derivedkeys.get(client_name),
                                                                         ticket_to)

                            message_to_receiver = pickle.dumps({"shared_key": shared_key_for_client,
                                                                "receiver": self.client_port[client_name],
                                                                "ticket_to": receiver_res,
                                                                "nonce": 3})
                            enc_response, iv1, tag1 = symmetric_encryption(self.users_derivedkeys.get(user),
                                                                           message_to_receiver)
                            payload = {"ciphertext": enc_response,
                                       "iv1": iv1,
                                       "tag1": tag1,
                                       "iv": iv,
                                       "tag": tag,
                                       "is_valid_user": True}
                            connection_socket.send(pickle.dumps(payload))
        except:
            connection_socket.close()
        finally:
            print "Connection terminated for ", address
            connection_socket.close()

    # generate session key Kab for the client
    def generate_session_key_for(self):
        return keygen()


if __name__ == "__main__":
    config = ConfigParser.ConfigParser()
    config.read('config/server.ini')
    server_port = config.getint('server_config','port')
    server_ip = config.get('server_config', 'ip')
    server_pub_key = config.get('server_config','pub_key')
    server_pvt_key = config.get('server_config', 'priv_key')
    print "Server Initialized..."
    cs = ChatServer(server_port, server_ip,server_pub_key, server_pvt_key)
