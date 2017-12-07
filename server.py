import argparse, socket, time, random, binascii, pickle, os
from threading import Thread
from CryptoUtils import create_hash, load_users, load_public_key, symmetric_encryption, asymmetric_decryption, \
    load_private_key, generate_key_from_password, keygen, symmetric_decryption, verify_signature


class ChatServer:
    def __init__(self, port):
        self.server_pub_key = load_public_key("server_public.pem")
        self.server_pvt_key = load_private_key("server_private.pem")
        self.BUFFER_SIZE = 65507
        self.UDP_IP = "127.0.0.1"
        """initialize the chatServer on the UDP port."""
        self.PORT = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("", self.PORT))
        self.sock.listen(20)
        self.users = {}
        self.users_pub_keys = {}
        self.users_derived_keys = {}
        self.registered_users = load_users()
        self.parsed_data = {}
        self.start_thread()

    def start_thread(self):
        while True:
            connection_socket, (address, port) = self.sock.accept()
            Thread(target=self.receive_messages, args=(connection_socket, (address, port),)).start()

    def receive_messages(self, connection_socket, address):
        while True:
            self.client_socket = connection_socket
            self.parsed_data = {}
            data = self.client_socket.recv(self.BUFFER_SIZE)
            try:
                self.parsed_data = pickle.loads(data)
            except ValueError:
                self.parsed_data = pickle.loads(data)
            if self.parsed_data["command"] == "login":
                if self.registered_users.get(self.parsed_data["username"]) is None:
                    self.client_socket.send("User not registered")
                if self.users.get(self.parsed_data["username"]):
                    self.client_socket.send("Already logged in")
                else:
                    cha = str(time.time()) + " " + str(random.random())
                    self.client_socket.send(cha)
                    challenge = cha.split()
                    h1 = create_hash(challenge[0])
                    h2 = create_hash(challenge[1])
                    answer = str(int(binascii.hexlify(h1), 16) & int(binascii.hexlify(h2), 16))
                    data = self.client_socket.recv(self.BUFFER_SIZE)
                    ans, username, password, salt, nonce_1 = asymmetric_decryption(self.server_pvt_key, data).split(
                        "\n")
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
                        self.client_socket.send(pickle.dumps(payload))
                        data_1 = self.client_socket.recv(self.BUFFER_SIZE)
                        data = pickle.loads(data_1)
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
                            self.users_pub_keys[username] = username + "_public.pem"
                            self.users_derived_keys[username] = user_derived_key
                            nonce_4 = str(time.time())
                            message = n3 + "\n" + nonce_4
                            enc_msg, iv, tag = symmetric_encryption(user_derived_key, message)
                            payload = {
                                "message": str(enc_msg),
                                "iv": str(iv),
                                "tag": str(tag)
                            }
                            self.client_socket.send(pickle.dumps(payload))
                    else:
                        self.clntSocketsend("Authentication failed!")
            elif self.parsed_data["command"] == "list":
                signature = self.parsed_data["signature"]
                user = self.parsed_data["user"]
                validity = verify_signature(user + "_public.pem", signature, self.parsed_data["ciphertext"])
                if validity == "VERIFIED":
                    nonce_l = symmetric_decryption(self.users_derivedkeys.get(user), self.parsed_data["iv"],
                                                   self.parsed_data["tag"], self.parsed_data["ciphertext"])
                    nonce_l1 = str(time.time())
                    response = str(self.users) + "\n" + nonce_l + "\n" + nonce_l1
                    enc_response, iv, tag = symmetric_encryption(self.users_derivedkeys.get(user), response)
                    payload = {
                        "ciphertext": enc_response,
                        "iv": iv,
                        "tag": tag
                    }
                    self.client_socket.send(pickle.dumps(payload))
            elif self.parsed_data["command"] == "talk-to":
                signature = self.parsed_data["signature"]
                message_iv = self.parsed_data["iv"]
                message_tag = self.parsed_data["tag"]
                client_user = self.parsed_data["chat_with"]
                if client_user not in self.users.keys():
                    payload = {
                        "is_valid_user": False
                    }
                    self.client_socket.send(pickle.dumps(payload))
                else:
                    user = self.parsed_data["user"]
                    validity = verify_signature(user + "_public.pem", signature, self.parsed_data["ciphertext"])
                    if validity == "VERIFIED":
                        nonce_1 = str(time.time())
                        private_key, public_key = self.generate_session_key_for()
                        # shared_key part is missing here, need to figure out what should be the public key
                        client_name = self.parsed_data["chat_with"]

                        # this step encrypts the message ticket-to-client with the derived key of the client
                        salt = os.urandom(16)
                        shared_key_for_client = generate_key_from_password("password", salt)
                        ticket_to = pickle.dumps({"shared_key": shared_key_for_client, "sender_name": user,
                                                  "sender_addr": (self.users[user][0], self.users[user][1]),
                                                  "nonce": nonce_1})
                        receiver_res, iv, tag = symmetric_encryption(self.users_derivedkeys.get(client_name),
                                                                     ticket_to)
                        # not sure about the shared_key part here. It is supposed to be the key, which will be used to communicate between A & B

                        message_to_receiver = pickle.dumps({"shared_key": shared_key_for_client,
                                                            "receiver": (
                                                            self.users[client_name][0], self.users[client_name][1]),
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
                        self.client_socket.send(pickle.dumps(payload))

    # generate session key Kab for the client
    def generate_session_key_for(self):
        return keygen()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-sp", "--sp")
    args = parser.parse_args()
    print "Server Initialized..."
    cs = ChatServer(args.sp)
