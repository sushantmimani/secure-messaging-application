import argparse, socket, json, time, random, binascii, pickle
from CryptoUtils import hashFunc, load_users, load_public_key, symmetric_encryption, asymmetric_decryption, \
    load_private_key, generate_key_from_password


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
        self.registered_users = load_users()
        self.receive_messages()

    def receive_messages(self):
        while True:
            data, address = self.sock.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
            parsed_data = json.loads(data)
            if parsed_data["command"] == "list":
                self.send_messages(json.dumps(self.users), address)
            if parsed_data["command"] == "login":
                cha = str(time.time()) + " " + str(random.random())
                self.send_messages(cha, address)
                challenge = cha.split()
                h1 = hashFunc(challenge[0])
                h2 = hashFunc(challenge[1])
                answer = str(int(binascii.hexlify(h1), 16) & int(binascii.hexlify(h2), 16))
                data, address = self.sock.recvfrom(self.BUFFER_SIZE)
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
                    print payload
                    self.send_messages(pickle.dumps(payload), address)
                else:
                    print "not match"
                    # if self.users.get(parsed_data["username"]):
                    #     self.send_messages("User exists", address)
                    # else:
                    #     self.users[parsed_data["username"]] = address
                    #     self.send_messages("Success", address)
                    #     self.send_messages("Success1", address)
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
