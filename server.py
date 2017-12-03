import argparse, socket, json, time, random, binascii, pickle, sys
from CryptoUtils import hashFunc, load_users, load_public_key, symmetric_encryption, asymmetric_decryption, \
    load_private_key, generate_key_from_password, symmetric_decryption


class ChatServer:
    def __init__(self, port):
        self.server_pub_key = load_public_key("server_public.pem")
        self.server_pvt_key = load_private_key("server_private.pem")
        self.BUFFER_SIZE = 65507
        self.UDP_IP = "127.0.0.1"
        """initialize the chatServer on the UDP port."""
        self.PORT = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", self.PORT))
        self.users = {}
        self.users_pubkeys = {}
        self.registered_users = load_users()
        self.receive_messages()

    def receive_messages(self):
        while True:
            data, address = self.sock.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
            parsed_data = json.loads(data)
            if parsed_data["command"] == "list":
                self.send_messages(json.dumps(self.users), address)
            if parsed_data["command"] == "login":
                if self.registered_users.get(parsed_data["username"]) is None:
                    self.send_messages("User not registered", address)
                if self.users.get(parsed_data["username"]):
                    self.send_messages("Already logged in", address)
                else:
                    cha = str(time.time()) + " " + str(random.random())
                    self.send_messages(cha, address)
                    challenge = cha.split()
                    h1 = hashFunc(challenge[0])
                    h2 = hashFunc(challenge[1])
                    answer = str(int(binascii.hexlify(h1), 16) & int(binascii.hexlify(h2), 16))
                    data, address = self.sock.recvfrom(self.BUFFER_SIZE)
                    print asymmetric_decryption(self.server_pvt_key,data).split("\n")
                    ans, username, password, salt, nonce_1 = asymmetric_decryption(self.server_pvt_key,data).split("\n")
                    user_derived_key = generate_key_from_password(password,salt)
                    if answer == ans and password == self.registered_users[username]:
                        nonce_2 = str(time.time())
                        message = nonce_1 + "\n"+nonce_2
                        enc_msg, iv, tag = symmetric_encryption(user_derived_key, message)
                        payload = {
                            "message": str(enc_msg),
                            "iv": str(iv),
                            "tag": str(tag)
                        }
                        self.send_messages(pickle.dumps(payload), address)
                        data, address = self.sock.recvfrom(self.BUFFER_SIZE)
                        data = pickle.loads(data)
                        data = symmetric_decryption(user_derived_key,data["iv"],data["tag"],data["message"]).split("\n")
                        n2 = data[0]
                        n3 = data[1]
                        public_pem = '\n'.join([str(x) for x in data[2:]])
                        file = open(username + "_public.pem", "w")
                        file.write(public_pem)
                        file.close()
                        if n2 == nonce_2:
                            self.users[username] = address
                            self.users_pubkeys[username] = username + "_public.pem"
                            nonce_4 = str(time.time())
                            message = n3+"\n"+nonce_4
                            enc_msg, iv, tag = symmetric_encryption(user_derived_key, message)
                            payload = {
                                "message": str(enc_msg),
                                "iv": str(iv),
                                "tag": str(tag)
                            }
                            self.send_messages(pickle.dumps(payload), address)
                    else:
                        self.send_messages("Authentication failed!", address)
            if parsed_data["command"] == "send":
                self.send_messages(json.dumps(self.users.get(parsed_data["user"])), address)
            if parsed_data["command"] == "terminate":
                if self.users.get(parsed_data["username"]):
                    del self.users[parsed_data["username"]]

    def send_messages(self, message, ip):
        self.sock.sendto(message, ip)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-sp", "--sp")
    args = parser.parse_args()
    print "Server Initialized..."
    cs = ChatServer(args.sp)
