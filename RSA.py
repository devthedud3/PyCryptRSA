import math
import random
import os

_random = random.SystemRandom()

class RSA:
    def __init__(self, s=64):

        # Initializes the keys.
        self.key = self.keygen(s)

    # Extended Euclidean algorithm.
    def ext_euclidean(self, x, y):

        if (y == 0): return (x, 1, 0)
        d, p, q = self.ext_euclidean(y, x % y)
        s = q
        t = p - q * (x // y)
        return d, s, t

    # Prime factorizations returns in u and k.
    def primeFactorize(self, n):

        # Converts the large prime number into a string and returns n - 1 if the last digit is even.
        n = n - 1 if int(str(n)[-1]) % 2 != 0 else n
        u, k = 1, 0 

        while n % 2 == 0:
            k += 1
            n /= 2

        for i in range(3, int(math.sqrt(n))+1, 2):
            while n % i == 0:
                u *= i
                n /= i
                    
        if n > 2:
            u *= n
        
        return int(u), k

    # Miller-Rabin Primality test
    def miller_rabin(self, n):
        exp, k = self.primeFactorize(n)
        for i in range(1, 40):
            a = _random.randint(2, n - 2)
            res = self.squareMultiply(a, exp, n)
            if res not in [1, n - 1]:
                for _ in range(1, k - 1):
                    res = self.squareMultiply(res, res, n)
                    if res == 1:
                        return False
                if res != n - 1:
                    return False
        return True

    # Power Modulus function, converts the exponent into binary and calculates the value for largers numbers.
    def squareMultiply(self, x, y, mod):
        exp = format(y, 'b')
        value = x
        for i in exp[1:]:
            value = ((value * value) % mod)
            if i == '1':
                value = ((value * x) % mod)
        return value

    # Random Number Generator
    def rng(self, s):
        a = random.getrandbits(s // 2)
        if self.miller_rabin(a):
            return a
        return self.rng(s)

    # Key generator.
    def keygen(self, s):
        p, q = self.rng(s), self.rng(s)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        while True:
            e = _random.randint(1, phi_n - 1)
            gcd, s, d = self.ext_euclidean(phi_n, e)
            if gcd == 1 and d > 0:
                # print(f'\nPublic Key: {hex(n), hex(e)}', f'Private Key: {hex(d)}', sep="\n")
                return [n, e], [d]
    
    # Command to show the Primary and Public key to the console.
    def showKeys(self):
        print( f'\n\tPubilic Key : {hex(self.key[0][0])}\n\tPrivate Key {hex(self.key[1][0])}')
        return [hex(self.key[0][0]), hex(self.key[0][1])], hex(self.key[1][0])

    # The encryption algorithm (text file) => encrypted text file.
    def encrypt(self, textFile):

        assert textFile, "No file found"

        # Grabs the public key from the initialized key generated value.
        pub_key = self.key[0] 

        #  Parses the filename and extension from the inputed file.
        file_name, ext = textFile.split(".") if "." in textFile else (textFile, "txt")

        # Opens the inputed file.
        f = open(textFile).read()

        # Creates the document to create the encrypted version.
        encrypted_f = open(f'{file_name}-encr.{ext}', "w+")

        # Creates the document path folder in the local directory.
        if not os.path.exists(f'encryption-keys/{file_name}/'):
            os.makedirs(os.path.dirname(f'encryption-keys/{file_name}/'))

        # Creates the directories for the keys to local directory in 'encryption-keys/filename' directory.
        encrypted_pub_k = open(f'encryption-keys/{file_name}/{file_name}-pub.key', "w+")
        encrypted_priv_k = open(f'encryption-keys/{file_name}/.{file_name}-priv.key', "w+")

        # Lists each characters encryption number in hex format.
        res = [hex(self.squareMultiply(ord(i), pub_key[1], pub_key[0]))[2:] for i in f]
        # print(bytes.fromhex(self.cache[0]).decode())
        

        # Joins the cache files together and writes them to the new created encrypted file.
        encrypted_f.write(" ".join(res))

        # Writes the keys to the file in the .ssh/filename directory.
        encrypted_pub_k.write(f'{("-" * 15)} Public Key {("-" * 15)} \n{hex(self.key[0][0])}')
        encrypted_priv_k.write(f'{("-" * 15)} Priivate Key {("-" * 15)} \n{hex(self.key[1][0])}')

        # Closes the open files.
        encrypted_f.close()
        encrypted_pub_k.close()
        encrypted_priv_k.close()

        return res

    # The decryption algorithm (text encrypted file) => decrypted text file.
    def decrypt(self, enc_file=None):

        assert enc_file, "No encryption file found"

        #  Parses the filename and extension from the inputed file.
        file_name, ext = enc_file.split(".") if "." in enc_file else (enc_file, "txt")
        file_name = file_name.split("-")[0]


        # Opens the inputed file.
        f = open(enc_file).read()

        # Creates the file for the decrypted file.
        decrypted_f = open(f'{file_name}-decr.{ext}', "w+")

        # Opens the keys from the .ssh directory.
        pub_key = open(f'encryption-keys/{file_name}/{file_name}-pub.key', "r+").readlines()[1]
        priv_key = open(f'encryption-keys/{file_name}/.{file_name}-priv.key', "r+").readlines()[1]

        # Reads the encrypted file and runs the power modular function against the public and private keys.
        res = [chr(self.squareMultiply(eval("0x" + i), eval(priv_key), eval(pub_key))) for i in f.split(" ")]

        # Writes to the decrypted file.
        decrypted_f.write("".join(res))

        # Closes the open files.
        decrypted_f.close()
        
        return res

if __name__ in ["__main__", "__live_coding__"]:

    # 80-bits is the highest my computer is able to run with a reasonable time.
    rsa = RSA(64)

    # Variable created to encrypt this this file before.

    res = input("[1] Encrypt\n[2] Decrypt: ")
    if res == "1":
        text = input("Enter full file name and ext for encryption: ")
        assert os.path.exists(f'{text}'), "No file found!"

        # Run the encryption schema on the text file.
        cipher = rsa.encrypt(text)

    else:
        # variable created to store the the newly created encryption filename.
        
        encr = input("Enter full file name and ext for decryption: ")
        assert os.path.exists(f'{encr}'), "No file found!"
        # Run the decryption on encrypted file.
        plaintext = rsa.decrypt(encr)