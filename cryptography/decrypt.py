'''
Cracking the Diffie-Helman Exchange
'''
class DHSolver():
    def __init__(self):
        # The g, p, A, and B values of Alice and Bob's Diffie Helman Exchange
        self.DH_g = 7
        self.DH_p = 61
        self.DH_A = 30
        self.DH_B = 17

        # Temporary values for the solved x, y, and key of Alice and Bob's Diffie Helman Exchange
        self.DH_x = -1
        self.DH_y = -1
        self.DH_key = -1

        # Conduct Diffie-Helman solving process:
        self.DH_solve()
    
    # Determines if an integer would be a possible value of x
    def is_possible_x(self, test_x):
        return (self.DH_g ** test_x) % self.DH_p == self.DH_A

    # Determines if an integer would be a possible value of y
    def is_possible_y(self, test_y):
        return (self.DH_g ** test_y) % self.DH_p == self.DH_B

    # Determines if two integers would be a possible pairing of x and y for the key
    def is_possible_key_pairing(self, test_x, test_y):
        return ((self.DH_B ** test_x) % self.DH_p) == ((self.DH_A ** test_y) % self.DH_p)

    # Solves for Alice and Bob's key
    def DH_solve(self):
        print("Diffie-Helman exchange: ")
        for x in range(self.DH_p):
            for y in range(x):
                if self.is_possible_x(x) and self.is_possible_y(y) and self.is_possible_key_pairing(x, y):
                    self.update_unknowns(x, y)
        print("\n")

    def update_unknowns(self, x, y):
        self.DH_x = x
        self.DH_y = y
        self.DH_key = (self.DH_B ** x) % self.DH_p
        print("X = " + str(self.DH_x) + ", Y = " + str(self.DH_y) + ", Key = " + str(self.DH_key))

'''
Cracking the RSA Exchange
'''
class RSASolver():
    def __init__(self):
        # The public key and message of Alice and Bob's RSA Exchange
        self.RSA_e = 17
        self.RSA_n = 170171
        self.RSA_message = [65426, 79042, 53889, 42039, 49636, 66493, 41225, 58964,
        126715, 67136, 146654, 30668, 159166, 75253, 123703, 138090,
        118085, 120912, 117757, 145306, 10450, 135932, 152073, 141695,
        42039, 137851, 44057, 16497, 100682, 12397, 92727, 127363,
        146760, 5303, 98195, 26070, 110936, 115638, 105827, 152109,
        79912, 74036, 26139, 64501, 71977, 128923, 106333, 126715,
        111017, 165562, 157545, 149327, 60143, 117253, 21997, 135322,
        19408, 36348, 103851, 139973, 35671, 93761, 11423, 41336,
        36348, 41336, 156366, 140818, 156366, 93166, 128570, 19681,
        26139, 39292, 114290, 19681, 149668, 70117, 163780, 73933,
        154421, 156366, 126548, 87726, 41418, 87726, 3486, 151413,
        26421, 99611, 157545, 101582, 100345, 60758, 92790, 13012,
        100704, 107995]

        # Temporary values for the solved p, q, r = (p-1)(q-1), and d of Alice and Bob's RSA Exchange
        self.RSA_p = -1
        self.RSA_q = -1
        self.RSA_r = -1
        self.RSA_d = -1

        # Conduct RSA solving process:
        self.RSA_solve()

    # Calculates Alice's determined p and q and r = (p-1)(q-1)
    def calculate_p_and_q(self):
        for p in range(2, self.RSA_n):
            if(self.RSA_n % p == 0):
                self.RSA_p = p
                self.RSA_q = self.RSA_n//p
                self.RSA_r = (self.RSA_p - 1)*(self.RSA_q - 1)
                print("p = " + str(self.RSA_p) + ", q = " + str(self.RSA_q) + ", (p-1)(q-1) = " + str(self.RSA_r))
                return

    # Calculates Bob's secret key d
    def calculate_d(self):
        for d in range(self.RSA_r):
            if ((self.RSA_e * d) % self.RSA_r == 1):
                self.RSA_d = d
                print("d = " + str(self.RSA_d))

    # Decrypts blocks with secret key and converts them into binary
    def decrypt_message_to_binary(self):
        for i in range(len(self.RSA_message)):
            self.RSA_message[i] = (self.RSA_message[i] ** self.RSA_d) % self.RSA_n
            self.RSA_message[i] = bin(self.RSA_message[i])

    # Converts blocks from binary to ascii for Alice's original message
    # Binary to ASCII decryption code from: https://blog.finxter.com/python-binary-string-to-ascii-string-and-vice-versa/
    def decrypt_message_to_ascii(self):
        message_string = ""
        for i in range(len(self.RSA_message)):
            conjoined_characters = self.RSA_message[i]
            conjoined_characters = int(conjoined_characters, base=2)
            conjoined_characters = conjoined_characters.to_bytes((conjoined_characters.bit_length() + 7)//8, 'big').decode()
            message_string += conjoined_characters
        self.RSA_message = message_string

    # Encrypts Alice's message to Bob
    def RSA_solve(self):
        print("RSA exchange: ")
        self.calculate_p_and_q()
        self.calculate_d()
        self.decrypt_message_to_binary()
        self.decrypt_message_to_ascii()
        print("Message: \n" + self.RSA_message)
        print("\n")

DH = DHSolver()
RSA = RSASolver()