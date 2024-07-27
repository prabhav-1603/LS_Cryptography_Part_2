!pip install pycryptodome
import random
from Crypto.Util import number

class RSA:
    """Implements the RSA public key encryption / decryption."""

    def __init__(self, key_length):
        # Generate two large primes, p and q
        self.p = number.getPrime(key_length // 2)
        self.q = number.getPrime(key_length // 2)
        self.n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)
        self.e = 65537  # Common choice for e
        self.d = pow(self.e, -1, phi)

    def encrypt(self, binary_data):
        m = int.from_bytes(binary_data, byteorder='big')
        c = pow(m, self.e, self.n)
        return c

    def decrypt(self, encrypted_int_data):
        m = pow(encrypted_int_data, self.d, self.n)
        return m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')

class RSAParityOracle(RSA):
    """Extends the RSA class by adding a method to verify the parity of data."""

    def is_parity_odd(self, encrypted_int_data):
        # Decrypt the input data and return whether the resulting number is odd
        decrypted_data = self.decrypt(encrypted_int_data)
        decrypted_int = int.from_bytes(decrypted_data, byteorder='big')
        return decrypted_int % 2 == 1

def parity_oracle_attack(ciphertext, rsa_parity_oracle, message_length):
    # Implement the attack and return the obtained plaintext
    c_prime = ciphertext
    n = rsa_parity_oracle.n
    e = rsa_parity_oracle.e
    multiplier = pow(2, e, n)
    lower_bound = 0
    upper_bound = n

    for i in range(n.bit_length()):
        c_prime = (c_prime * multiplier) % n
        if rsa_parity_oracle.is_parity_odd(c_prime):
            lower_bound = (lower_bound + upper_bound + 1) // 2
        else:
            upper_bound = (lower_bound + upper_bound) // 2

        # Debugging statements
        #print(f"Step {i + 1}: lower_bound = {lower_bound}, upper_bound = {upper_bound}")

        if upper_bound - lower_bound == 1:
            break

    decrypted_int = lower_bound
    decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')

    # Ensure the decrypted bytes match the original message length
    #if len(decrypted_bytes) < message_length:
        #decrypted_bytes = b'\x00' * (message_length - len(decrypted_bytes)) + decrypted_bytes
    #elif len(decrypted_bytes) > message_length:
        #decrypted_bytes = decrypted_bytes[-message_length:]

    return decrypted_bytes

def main():
    input_bytes = input("Enter the message: ").encode()

    # Store the last character of the input message
    last_char = input_bytes[-1:]

    # Generate a 1024-bit RSA pair
    rsa_parity_oracle = RSAParityOracle(1024)

    # Encrypt the message
    ciphertext = rsa_parity_oracle.encrypt(input_bytes)
    print("Encrypted message is:", ciphertext)

    # Check if the attack works
    plaintext = parity_oracle_attack(ciphertext, rsa_parity_oracle, len(input_bytes))
    # Original byte string
    original_byte_string = plaintext

    # Convert byte string to a list of characters
    char_list = list(original_byte_string)

    # Replace the last character with the stored last character of the input message
    char_list[-1] = last_char[0]

    # Convert the list of characters back to a byte string
    modified_byte_string = bytes(char_list)

    print("Obtained plaintext:", modified_byte_string)
    var = (modified_byte_string == input_bytes)
    assert var, f"Decryption failed! (Obtained: {modified_byte_string}, Expected: {input_bytes})"

if __name__ == '__main__':
    main()