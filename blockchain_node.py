from blockchain import *
from flask import Flask, request
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)


class BlockChainNode(BlockChain):
    def __init__(self):
        super().__init__()

        self.transactions = []

        # Genesis Block
        print("Setting up genesis block!")
        gb = self.mine_block(Block("", [], 0))
        print("Genesis block found!")
        self.chain = [gb]

BC = BlockChainNode()

@app.route('/chain', methods=["GET"])
def get_chain():
    chain_dict = {}

    for block_index in range(len(BC.chain)):
        chain_dict[block_index] = BC.chain[block_index].__dict__

    return json.dumps(chain_dict)


@app.route('/block', methods = ['POST'])
def add_block_mined():
    data = request.get_json(force=True)

    if 'nonce' in data:
        block = BC.next_block()

        block.transactions = data["transactions"]
        block.nonce = int(data['nonce'])

        BC.create_block(block)

    return "", 200


@app.route('/transaction', methods = ['POST'])
def add_transaction():
    data = request.get_json(force=True)

    if data["from"] != "COINBASE":
        data_verp = data.copy()
        signature = data_verp.pop("signature")
        from_pub_key_hex = data_verp["from"]
        if not BlockChain.validate_signature(json.dumps(data_verp), signature, from_pub_key_hex):
            return "Invalid signature", 400

    BC.add_transaction(data["from"], data["to"], data["amount"], data["signature"])

    return "", 200

@app.route('/transactions', methods = ['GET'])
def get_transactions():
    return json.dumps(BC.transactions)

if __name__ == "__main__":
    app.run()
