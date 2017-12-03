import argparse, socket, json, sys, time, binascii, os, pickle, getpass

from select import select
from CryptoUtils import hashFunc, keygen, generate_key_from_password, load_public_key, \
                        symmetric_encryption, asymmetric_encryption, generate_password_hash, symmetric_decryption,\
                        serialize_public_key, sign_message, serialize_private_key


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
        # Parameters to allow server to register a user on sign-in
        params = {
            "command": "login",
            "username": self.username
        }
        self.sock.sendto(json.dumps(params), (self.sIP, self.UDP_PORT))
        data, address = self.sock.recvfrom(self.BUFFER_SIZE)
        if data == "Already logged in":
            print "Already logged in. Terminating this session"
            sys.exit()
        if data == "User not registered":
            print "User not registered. Terminating session"
            sys.exit()
        challenge = data.split()
        h1 = hashFunc(challenge[0])
        h2 = hashFunc(challenge[1])
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
                self.start()
            else:
                print "Authentication failed!Terminating"
                sys.exit()
        else:
            print "Authentication failed!Terminating"
            sys.exit()

    # Display messages received from other signed-in users
    def print_received_message(self):
        data, address = self.sock.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
        print("<-- <From {0}:{1}:{2}>  " + json.loads(data)["message"]).format(address[0],
                                                                               address[1],
                                                                               json.loads(data)["user"])

    def print_user_list(self, input_array):
        if len(input_array) > 1:  # List followed by anything is an invalid command and will not be processed
            print("Invalid Input!")
        else:
            nonce_l = str(time.time())
            message = nonce_l
            ct, iv, tag = symmetric_encryption(self.derived_key, message)
            signature = sign_message(self.private_key, ct)
            new_message = {
                "ciphertext": ct,
                "user": self.username,
                "command": "list",
                "iv": iv,
                "tag": tag,
                "signature": signature
            }
            # self.sock.sendto(json.dumps({"command": "list"}), (self.sIP, self.UDP_PORT))
            self.sock.sendto(pickle.dumps(new_message), (self.sIP, self.UDP_PORT))
            data, address = self.sock.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
            user = []
            parsed_user = json.loads(data)
            del parsed_user[self.username] # Delete current user from list of users returned from the server
            if not parsed_user: # No other users logged in
                print("<-- No other users signed in")
            else:
                for x in parsed_user:
                    user.append(x)
                print("<-- Signed In Users: {0}").format(','.join(user)) # Print user list

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
                        elif input_array[0] == "send":
                            if len(input_array)<3:
                                print("Invalid Input!")
                            else:
                                self.sock.sendto(json.dumps({"command": "send", "user":input_array[1]}),
                                                 (self.sIP, self.UDP_PORT))
                                data, address = self.sock.recvfrom(self.BUFFER_SIZE)  # buffer size is 65507 bytes
                                if data=="null":
                                    print("User doesn't exist!")
                                else:
                                    temp = json.loads(data)
                                    message = ' '.join(input_array[2:])
                                    if len(message.encode('utf-8')) > self.permitted_size:
                                        while len(message.encode('utf-8'))>self.permitted_size:
                                            toSend=message[0:self.permitted_size]
                                            self.sock.sendto(json.dumps({
                                                "user": self.username, "message": toSend}),
                                                (temp[0], int(temp[1])))
                                            message = message[self.permitted_size:]
                                        self.sock.sendto(json.dumps({
                                            "user": self.username, "message": message}),
                                            (temp[0], int(temp[1])))
                                    else:
                                        self.sock.sendto(json.dumps({
                                            "user":self.username,"message":' '.join(input_array[2:])}),
                                            (temp[0], int(temp[1])))
                        else:
                            print("Invalid Input!")
        except KeyboardInterrupt:
            self.sock.sendto(json.dumps({"command": "terminate", "username": self.username}), (self.sIP, self.UDP_PORT))
            self.sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-sip", "--sIP")
    parser.add_argument("-sp", "--sp")
    args = parser.parse_args()
    cs = ChatClient(args)
