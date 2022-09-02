# Encryption stuff
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from hashlib import sha256
import json
import uuid
from time import time

# Padding for signing
pad_sign = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

# Padding for enc / decr
pad_crypt = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class Block:
    def __init__(self, previous_hash, transactions, nonce):
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.nonce = nonce


    def hash_block(self):
        to_hash = json.dumps(self.__dict__)
        return sha256(to_hash.encode()).hexdigest()


    def __repr__(self):
        return f"<Nonce: {self.nonce}, NTx: {len(self.transactions)}>"


    def __str__(self):
        return str(self.__dict__)


class BlockChain:
    def __init__(self):
        self.prefix_zero_length = 3  # Adds to difficulty of mining
        self.block_mine_reward = 2


    def previous_hash(self):
        return self.chain[-1].hash_block()


    def next_block(self):
        next_block = Block(self.previous_hash(), self.transactions, 0)
        return next_block


    def create_block(self, b):
        if self.validate(b):
            self.chain.append(b)
            self.transactions = []

            print("New block created!")
        else:
            print("Could not validate!")
            print("---", hash_shortened(b.hash_block()))


    def add_transaction(self, fro, to, amount, signature):
        self.transactions.append({"from": fro, "to": to, "amount": amount, "signature": signature})


    def balance_pkey(self, pkey):
        sum = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction["to"] == pkey:
                    sum += transaction["amount"]
                if transaction["from"] == pkey:
                    sum -= transaction["amount"]
        return sum


    def validate(self, b):
        return b.hash_block()[:self.prefix_zero_length] == "0"*self.prefix_zero_length


    @staticmethod
    def validate_signature(msg_str, signature_hex, pkey_hex):
        signature_bytes = bytes.fromhex(signature_hex)
        msg_bytes = msg_str.encode()
        pkey_bytes = bytes.fromhex(pkey_hex)
        pkey = serialization.load_der_public_key(pkey_bytes)
        try:
            pkey.verify(signature_bytes, msg_bytes, pad_sign, hashes.SHA256())
        except InvalidSignature:
            return False

        return True


    def valid_transaction(self, transaction):
        if transaction["from"]=="COINBASE":
            return False
        if self.balance_pkey(transaction["from"])-transaction["amount"]<0:
            return False

        transaction_copy = transaction.copy()
        signature_hex = transaction_copy.pop("signature")
        transaction_copy_str = json.dumps(transaction_copy)
        pkey_hex = transaction_copy["from"]

        if not self.validate_signature(transaction_copy_str, signature_hex, pkey_hex):
            False

        return True


    def mine_block(self, nonceless_block):
        nonce = 0
        while not self.validate(nonceless_block):
            nonce += 1
            nonceless_block.nonce = nonce
        return nonceless_block


"""
Utils:
"""


def hash_shortened(hash):
    return hash[:10] + "..." + hash[-10:]
