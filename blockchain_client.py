from blockchain import *
import requests


class Client(BlockChain):
    def __init__(self, node_url, public_key=None, private_key=None):
        super().__init__()

        self.node_url = node_url
        self.transactions = []

        if public_key == None or private_key == None:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = private_key
            self.public_key = public_key

        self.refresh_chain()
        self.pkey_str = self.pkey_hex


    def refresh_chain(self):
        # Refresh chain
        chain_txt = requests.get(self.node_url+"/chain").text
        chain_json = json.loads(chain_txt)
        self.chain = []

        for i in range(len(chain_json.values())):
            current_block_dict = chain_json[str(i)]
            block_i = Block(current_block_dict["previous_hash"], current_block_dict["transactions"], current_block_dict["nonce"])
            self.chain.append(block_i)


        # Refresh transactions
        trans_txt = requests.get(self.node_url+"/transactions").text
        trans_json = json.loads(trans_txt)
        self.transactions = trans_json


    @property
    def pkey_hex(self):
        pem = self.public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        return pem.hex()


    def filter_block_transactions(self, transactions):
        valid_transactions = []

        for transaction in transactions:
            if self.valid_transaction(transaction):
                valid_transactions.append(transaction)

        return valid_transactions


    def perform_transaction(self, to, amount):
        transaction_data = {"from": self.pkey_str, "to": to, "amount": amount}
        signature = self.private_key.sign(json.dumps(transaction_data).encode(), pad_sign, hashes.SHA256())
        transaction_data["signature"] = signature.hex()

        requests.post(self.node_url+"/transaction", data=json.dumps(transaction_data))
        self.refresh_chain()


    @property
    def balance(self):
        return self.balance_pkey(self.pkey_str)


    def mine_submit_block(self):
        def create_transaction_reward():
            reward_data = {"from": "COINBASE", "to": self.pkey_str, "amount": self.block_mine_reward, "signature": ""}
            return reward_data

        block = self.next_block()
        block.transactions = self.filter_block_transactions(block.transactions)
        block.transactions.append(create_transaction_reward())
        block = self.mine_block(block)

        data = block.__dict__
        requests.post(self.node_url + "/block", data=json.dumps(data))
        self.refresh_chain()

        print("Balance is now", self.balance)


#MyWallet = Client("http://127.0.0.1:5000")

#MyWallet.mine_submit_block()
#print(MyWallet.chain)
#print(MyWallet.balance)
