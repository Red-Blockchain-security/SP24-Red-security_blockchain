from flask import Flask, jsonify, request, render_template
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from flask_cors import CORS

class Transaction:
    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount


    def to_dict(self):
        return OrderedDict({
            'sender public key': self.sender_public_key,
            'recipient public key': self.recipient_public_key,
            'amount': self.amount,
        })

    def confirm_transaction(self):
        #takes sender’s private key, decodes it into bytes then imports it as an RSA key
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        #creates signature scheme object that can be used to generate signatures
        signer = PKCS1_v1_5.new(private_key)
        #hashes the string representation of the transaction details
        #the string is encoded in UTF-8 before hashing
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        #signs the hash of the transaction details
        #the signature is then encoded as a hexadecimal and decoded into an ASCII before being returned
        return binascii.hexlify(signer.sign(h)).decode('ascii')


#Install flask_cors to bypass browser CORS policy
app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('./wallet.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template("./make_transaction.html")

@app.route('/view/transaction')
def view_transaction():
    return render_template("./view_transaction.html")


''' 
    __________________________
    WALLET GENERATION METHOD
    RSA Crypto library required - Install PyCryptodome
    This method produces RSA generated numbers for keys
'''
@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read  # new random generated number
    private_key = RSA.generate(1024, random_gen)  # 1024-bit RSA private key
    public_key = private_key.publickey()  # derive the public key from private

    # exporting RSA keys in DER format. Convert binary to HEX then to ASCII
    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }
    # jsonify library required
    # sending the dictionary as a JSON response with HTTP status code 200
    return jsonify(response), 200


'''
    _______________________________
    TRANSACTION GENERATION METHOD
    This method retrieves transaction details user put
'''
@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    # Retrieves the sender’s public & private key, recipient’s public key,
    # and the amount from the form data sent in the POST request
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    # The to_dict method returns an ordered dictionary of the transaction details
    # The confirm_transaction method returns the signature of the transaction
    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)
    response = {'transaction': transaction.to_dict(),
                'signature': transaction.confirm_transaction()}
    return jsonify(response), 200



if __name__ == "__main__":
    # Importing the ArgumentParser class from the argparse module
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port  # Retrieving the value of the "port" argument

    # Running on localhost at the specified port
    app.run(host="127.0.0.1", port=port, debug=True)