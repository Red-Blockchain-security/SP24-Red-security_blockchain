from flask import Flask, request, jsonify, render_template
from time import time
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from flask_cors import CORS
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse


Mining_Sender = "The Blockchain"
Mining_Reward = 1  # reward 1 coin to miner
Mining_Difficulty = 2  # default difficulty


class Blockchain:

    def __init__(self):
        # List of transaction
        self.transactions = []
        # List of block
        self.chain = []
        # List of nodes
        self.nodes = set ()
        # Unique node id
        self.node_id = str(uuid4()).replace('', '')
        # Genesis block
        self.create_block(0, "00")


    ''' 
        ______________________
        REGISTER NODE METHOD
        Add new nodes to the blockchain network
    '''
    def register_node(self, node_url):
        parsed_url = urlparse(node_url) # parse the URL into components
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')



    ''' 
        ______________________
        CREATE A BLOCK METHOD
    '''
    def create_block(self, nonce, previous_hash):
        # Add a block of transactions to the chain
        block = {"block_number": len(self.chain) + 1,
                 "timestamp": time(),
                 "transaction": self.transactions,
                 "nonce": nonce,
                 "previous hash": previous_hash
                 }
        # Add transactions to the block
        self.transactions = []
        self.chain.append(block)
        return block


    ''' 
        _____________________________
        SIGNATURE VERIFICATION METHOD
    '''
    def verify_transaction_signature(self, sender_public_key, signature, transaction):
        # imports the sender’s public key using methods from PyCrypto library
        public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        # hashes the string representation of the transaction details
        # the string is encoded in UTF-8 before hashing
        h = SHA.new(str(transaction).encode('utf8'))
        try:
            # verify the signature of the hash
            # convert the hexadecimal string of the signature back into binary
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False



    '''
        ________________________
        PROOF VALIDATING METHOD
        Part of Proof of Work method
        Validate the proof of work for a block
    '''
    @staticmethod
    def valid_proof(transactions, last_hash, nonce, difficulty=Mining_Difficulty):
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode('utf8')
        # creates a new SHA-256 hash object and updates it with the encoded string to generate a hash
        h = hashlib.sha256()
        h.update(guess)
        guess_hash = h.hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty  # list 2 characters of the hash
    '''
        ______________________
        PROOF OF WORK METHOD
        Part of mining method
    '''
    def proof_of_work(self):
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0 # number used once and incremented in each iteration of the loop
        # invoke Proof Validating method
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1
        return nonce



    ''' 
        ______________________
        HASH THE BLOCK METHOD
    '''
    @staticmethod
    def hash(block):
        # ensure that the dictionary is ordered, otherwise we'll get inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode('utf8')  # convert block into a string
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()



    ''' 
        ___________________
        VALID CHAIN METHOD
        Needs to validate the chain because each node maintain its own blockchain
        This retrieves latest update from the other node
        Consensus protocol remember? This method is a part of it
        The node with longest blockchain wins
    '''
    def valid_chain(self, chain):
        # Get the first block in the chain
        last_block = chain[0]
        current_index = 1

        # Loop through the chain until the end
        while current_index < len(chain):
            block = chain[current_index] # Get the block at the current index

            # Check if the 'previous_hash' of the current block is equal to the hash of the last block
            if block['previous_hash'] != self.hash(last_block):
                return False # If they are not equal, the chain is not valid

            transactions = block['transactions'][:-1] # Get the transactions from the current block (excluding the last transaction)
            transaction_elements = ['sender_public_key', 'recipient_public_key', 'amount']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in
                            transactions] # Create a list of ordered dictionaries for the transactions

            # Check if the proof of work for these transactions, the 'previous_hash' of the block, and the 'nonce' of the block is valid
            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], Mining_Difficulty):
                # If the proof is not valid, the chain is not valid
                return False

            # If the 'previous_hash' and the proof are both valid, set the last block to the current block
            last_block = block
            current_index += 1

        # If the loop completes without finding any invalid 'previous_hash' or proof, the chain is valid
        return True


    ''' 
        _____________________________________
        RESOLVE CONFLICT BETWEEN NODES METHOD
        Part of the Valid Chain method
        Making sure blockchain on all nodes the same
    '''
    def resolve_conflicts(self):
        neighbours = self.nodes # Get the set of nodes in the network
        new_chain = None

        # Get the length of the current chain
        max_length = len(self.chain)
        # Iterate over each node in the network
        for node in neighbours:
            # Send a GET request to the node's /chain endpoint to retrieve its version of the blockchain
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                # Get the length and the chain from the response
                length = response.json()['length']
                chain = response.json()['length']
                # Check if the length of the retrieved chain is greater than max_length and if the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # If new_chain is not None means a longer and valid chain was found
        if new_chain:
            # Set the current chain to new_chain and return True
            self.chain = new_chain
            return True
        # If new_chain is None means no longer and valid chain was found
        return False

    ''' 
        __________________________
        SUBMIT TRANSACTION METHOD
    '''
    def submit_transaction(self, sender_public_key, recipient_public_key, signature, amount):
        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'amount': amount
        })
        # Reward the miner for mining a block
        if sender_public_key == Mining_Sender:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            # Invoke Signature Verification method
            signature_verification = self.verify_transaction_signature(sender_public_key, recipient_public_key,
                                                                       signature, transaction)
            if signature_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False


# Instantiate the Blockchain
blockchain = Blockchain()

# Instantiate the Nodes
app = Flask(__name__)
CORS(app)


@app.route("/")
def index():
    return render_template("./blockchain.html")

@app.route("/configure")
def configure():
    return render_template("./configure.html")


''' 
    _____________________________
    CREATE NEW TRANSACTION METHOD
    Adding current transaction to the block / unmined transaction table
'''
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form
    required = ['confirmation_sender_public_key', 'confirmation_recipient_public_key',
                'transaction_signature', 'confirmation_amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Invoke submit transaction method
    # to add the transaction details from confirmation form to the unmined table list on blockchain.html
    transaction_results = blockchain.submit_transaction(values['confirmation_sender_public_key'],
                                                        values['confirmation_recipient_public_key'],
                                                        values['transaction_signature'],
                                                        values['confirmation_amount'])
    if not transaction_results:
        response = {'message': 'Invalid transaction/signature'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to the block' + str(transaction_results)}
        return jsonify(response), 201


''' 
    ______________________
    GET TRANSACTION METHOD
    Handling the transaction from User Client to Miner Client
    This is UNMINED transactions
'''
@app.route('/transactions/get', methods=['GET'])
def get_transaction():
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200



''' 
    _____________________
    M I N I N G - METHOD
    Finding the nonce
    Solve cryptographic puzzle
'''
@app.route('/mine', methods=['GET'])
def mine():
    # Invoke Proof of Work algorithm
    nonce = blockchain.proof_of_work()

    blockchain.submit_transaction(sender_public_key=Mining_Sender,
                                  recipient_public_key=blockchain.node_id,
                                  signature='',
                                  amount=Mining_Reward)
    last_block = blockchain.chain[-1]  # get the last block
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)  # create new block

    response = {
        'message': 'New block created',
        'block number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200



''' 
    __________________________
    GET THE BLOCKCHAIN METHOD
    get the mined block 
    add the block to the blockchain
'''
@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200




''' 
    _____________________________
    RETRIEVES MINER NODES METHOD
    This resource is to add more miners to the network
    More miners = safer blockchain
'''
@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace('','').split(',')

    if nodes is None:
        return 'Error: Please supply a valid list of nodes', 400
    for node in nodes:
        # Invoke register node method
        blockchain.register_node(node)
    response = {
        'message': 'Node have been added',
        'total_nodes': [node for node in blockchain.nodes]
    }
    return jsonify(response), 200



if __name__ == "__main__":
    # Importing the ArgumentParser class from the argparse module
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    # Running on localhost at the specified port
    app.run(host="127.0.0.1", port=port, debug=True)
