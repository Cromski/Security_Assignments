import random
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


alice_dice_roll = None
alice_key = None
alice_random_int = None

bob_dice_roll = None
bob_key = None
bob_random_int = None




def roll_dice():
    return random.randint(1, 6)


def make_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def hash_msg(randomint, msg):
    return hashlib.sha512(str(str(randomint) + str(msg)).encode('utf-8')).digest()


def big_random_int():
    return random.randint(23968538285952352, 582952835825382523)


def encrypt_message(msg, public_key):
    return public_key.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )


def sign_message(msg, private_key):
    return private_key.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def decrypt_message(encrypted_msg, private_key):
    return private_key.decrypt(
        encrypted_msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )


def is_hash_equal(hash1, hash2):
    return hash1 == hash2


def verify(msg, signature, public_key):
    try:
        public_key.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def program():
    global alice_dice_roll
    global bob_dice_roll
    global alice_key
    global bob_key
    global alice_random_int
    global bob_random_int

    print("Welcome to the dice game.\n")

    # Alice and Bob has rolled their dice
    alice_dice_roll = roll_dice()
    bob_dice_roll = roll_dice()
    print("Alice and Bob has rolled their dice:")
    print(f"Alice rolled {alice_dice_roll}")
    print(f"Bob rolled {bob_dice_roll}")

    # make keys for bob and alice
    alice_key = make_key()
    bob_key = make_key()

    # They both generate a big random int to hash their message
    alice_random_int = big_random_int()
    bob_random_int = big_random_int()
    bob_hashed_msg = hash_msg(bob_random_int, bob_dice_roll)
    alice_hashed_msg = hash_msg(alice_random_int, alice_dice_roll)
    print("\nThey both generate a big random int to hash their message")
    print(f"Alice's Hashed Message: {alice_hashed_msg}")
    print(f"Bob's Hashed Message: {bob_hashed_msg}")

    # They encrypt their message using the receivers public key
    alice_enc_msg = encrypt_message(alice_hashed_msg, bob_key.public_key())
    bob_enc_msg = encrypt_message(bob_hashed_msg, alice_key.public_key())
    print("\n They encrypt their message using the receivers public key")
    print(f"Alice's encrypted message: {str(alice_enc_msg)}")
    print(f"Bob's encrypted message: {str(bob_enc_msg)}")

    # They sign their message with their own private key
    alice_signed_msg = sign_message(alice_hashed_msg, alice_key)
    bob_signed_msg = sign_message(bob_hashed_msg, bob_key)
    print("\n They sign the message using their own private key")
    print(f"Alice signed msg: {str(alice_signed_msg)}")
    print(f"Bob signed msg: {str(bob_signed_msg)}")

    # They send as a tuple: (encrypted msg, signature) to each other
    alice_tuple = (alice_enc_msg, alice_signed_msg)
    bob_tuple = (bob_enc_msg, bob_signed_msg)
    print("\n They send as a tuple: (encrypted msg, signature to each other")
    print(f"Alice's tuple: {alice_tuple}")
    print(f"Bob's tuple: {bob_tuple}")

    # They verify that the message comes from each other using the others public key

    print("\n They now received each others tuple and first has to verify, that the message is coming from each other")
    print(f"{verify(bob_enc_msg, bob_signed_msg, bob_key.public_key())}")

    print("--------------------------------")

    # They decrypt the message they have received
    alice_msg_decrypted = decrypt_message(alice_enc_msg, bob_key)
    bob_msg_decrypted = decrypt_message(bob_enc_msg, alice_key)
    print("\n They decrypt the message they have received")
    print(f"Alice decrypts Bob's msg: {bob_msg_decrypted}")
    print(f"Bob decrypts Alice's msg: {alice_msg_decrypted}")

    # They send each other a hashed, encrypted and signed message of their random number and dice roll, to let the
    # other player see compare the hash and make sure the other player isn't lying
    print("\nAlice and Bob now has each others hashed message ")

    bob_roll_and_random = (f"{bob_random_int} {bob_dice_roll}")




    # this is hashed thing, with this randomness '12' this is the thing we want to encrypt, then
    # they both decrypt their messages, and then they send their randomness to each other to check that they
    # have the same hashed number

    # thus we need a hash method, a compare 2 hashes method to see if they are equal,
    # and we need somewhere to put randomness before we hash a message


program()