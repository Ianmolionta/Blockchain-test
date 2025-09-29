"""
blockchain_secure_demo.py
Simple blockchain demo with security features:
- RSA-based digital signatures (cryptography)
- Transactions signed by sender
- Merkle root (simple) per block
- Proof-of-Work mining
- Chain validation
- Simple Flask REST API for interaction
"""

from flask import Flask, request, jsonify
import json, time, hashlib, threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from typing import List

# -------------------------
# Utilities: keys & signatures
# -------------------------

def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(pub):
    pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem.decode()

def serialize_private_key(priv):
    pem = priv.private_bytes(encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption())
    return pem.decode()

def load_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str.encode())

def load_private_key(pem_str):
    return serialization.load_pem_private_key(pem_str.encode(), password=None)

def sign_message(private_key, message_bytes: bytes) -> bytes:
    sig = private_key.sign(message_bytes,
                           padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                       salt_length=padding.PSS.MAX_LENGTH),
                           hashes.SHA256())
    return sig

def verify_signature(public_key, message_bytes: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature,
                          message_bytes,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
        return True
    except InvalidSignature:
        return False

# -------------------------
# Blockchain data models
# -------------------------

class Transaction:
    def __init__(self, sender_pub_pem: str, recipient_pub_pem: str, amount: float, signature: str = None):
        self.sender = sender_pub_pem      # serialized PEM pubkey or 'NETWORK' for coinbase
        self.recipient = recipient_pub_pem
        self.amount = amount
        self.signature = signature       # base16 hex of signature bytes

    def to_dict(self):
        return {"sender": self.sender, "recipient": self.recipient, "amount": self.amount, "signature": self.signature}

    def hash(self):
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()

class Block:
    def __init__(self, index: int, transactions: List[Transaction], previous_hash: str, nonce=0, timestamp=None):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.timestamp = timestamp or time.time()
        self.merkle_root = self.compute_merkle_root()

    def compute_merkle_root(self):
        # simple merkle root: hash pairs until one remains
        tx_hashes = [tx.hash().encode() for tx in self.transactions]
        if not tx_hashes:
            return hashlib.sha256(b'').hexdigest()
        while len(tx_hashes) > 1:
            if len(tx_hashes) % 2 == 1:
                tx_hashes.append(tx_hashes[-1])  # duplicate last hash
            new_level = []
            for i in range(0, len(tx_hashes), 2):
                new_level.append(hashlib.sha256(tx_hashes[i] + tx_hashes[i+1]).hexdigest().encode())
            tx_hashes = new_level
        return tx_hashes[0].decode()

    def header(self):
        header = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root
        }
        return json.dumps(header, sort_keys=True)

    def hash(self):
        return hashlib.sha256((self.header() + json.dumps([tx.to_dict() for tx in self.transactions], sort_keys=True)).encode()).hexdigest()

# -------------------------
# Blockchain core
# -------------------------

class SimpleSecureBlockchain:
    def __init__(self, difficulty=4):
        self.chain: List[Block] = []
        self.current_transactions: List[Transaction] = []
        self.difficulty = difficulty  # number of leading zeros required in block hash
        self.lock = threading.Lock()
        # genesis block
        genesis = Block(index=0, transactions=[], previous_hash="0")
        self.chain.append(genesis)

    def new_transaction(self, transaction: Transaction):
        # validate signature (unless coinbase / network reward)
        if transaction.sender != "NETWORK":
            sender_pub = load_public_key(transaction.sender)
            if not transaction.signature:
                raise ValueError("Transaction missing signature")
            signature_bytes = bytes.fromhex(transaction.signature)
            # message to verify: sender + recipient + amount (deterministic)
            message = json.dumps({"sender": transaction.sender, "recipient": transaction.recipient, "amount": transaction.amount}, sort_keys=True).encode()
            if not verify_signature(sender_pub, message, signature_bytes):
                raise ValueError("Invalid signature for transaction")
        # append to pool
        self.current_transactions.append(transaction)
        return self.last_block().index + 1

    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, block: Block):
        prefix = "0" * self.difficulty
        block.nonce = 0
        while True:
            h = block.hash()
            if h.startswith(prefix):
                return h
            block.nonce += 1

    def mine(self, miner_address_pub_pem: str):
        # reward for miner
        coinbase = Transaction(sender_pub_pem="NETWORK", recipient_pub_pem=miner_address_pub_pem, amount=1.0, signature=None)
        with self.lock:
            # take current transactions + coinbase
            transactions = self.current_transactions.copy()
            transactions.append(coinbase)
            block = Block(index=self.last_block().index + 1, transactions=transactions, previous_hash=self.last_block().hash())
            proof = self.proof_of_work(block)
            # append
            self.chain.append(block)
            self.current_transactions = []
        return block, proof

    def is_valid_chain(self, chain: List[Block]) -> bool:
        # validate entire chain: hashes, proof-of-work, merkle root, transaction signatures
        if not chain:
            return False
        for i in range(1, len(chain)):
            prev = chain[i-1]
            curr = chain[i]
            # check previous_hash link
            if curr.previous_hash != prev.hash():
                print(f"Invalid previous_hash at index {i}")
                return False
            # check proof-of-work
            if not curr.hash().startswith("0" * self.difficulty):
                print(f"Invalid proof at index {i}")
                return False
            # check merkle root consistency
            if curr.merkle_root != curr.compute_merkle_root():
                print(f"Merkle root mismatch at index {i}")
                return False
            # validate transactions signatures
            for tx in curr.transactions:
                if tx.sender == "NETWORK":
                    continue
                try:
                    sender_pub = load_public_key(tx.sender)
                except Exception as e:
                    print(f"Invalid public key format: {e}")
                    return False
                if not tx.signature:
                    print("Transaction missing signature")
                    return False
                message = json.dumps({"sender": tx.sender, "recipient": tx.recipient, "amount": tx.amount}, sort_keys=True).encode()
                if not verify_signature(sender_pub, message, bytes.fromhex(tx.signature)):
                    print("Invalid transaction signature")
                    return False
        return True

# -------------------------
# Demo API (Flask)
# -------------------------

app = Flask(__name__)
blockchain = SimpleSecureBlockchain(difficulty=4)

@app.route("/wallet/new", methods=["GET"])
def new_wallet():
    priv, pub = generate_rsa_keypair()
    return jsonify({
        "private_key_pem": serialize_private_key(priv),
        "public_key_pem": serialize_public_key(pub)
    })

@app.route("/transaction/new", methods=["POST"])
def new_transaction():
    values = request.get_json()
    required = ["sender_pub", "recipient_pub", "amount", "signature_hex"]
    if not all(k in values for k in required):
        return "Missing fields", 400
    tx = Transaction(sender_pub_pem=values["sender_pub"],
                     recipient_pub_pem=values["recipient_pub"],
                     amount=float(values["amount"]),
                     signature=values["signature_hex"])
    try:
        idx = blockchain.new_transaction(tx)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"message": f"Transaction will be added to Block {idx}"}), 201

@app.route("/mine", methods=["POST"])
def mine():
    values = request.get_json() or {}
    miner_pub = values.get("miner_pub")
    if not miner_pub:
        return "Missing miner_pub", 400
    block, proof = blockchain.mine(miner_pub)
    response = {
        "message": "New Block Forged",
        "index": block.index,
        "transactions_count": len(block.transactions),
        "hash": block.hash(),
        "proof": proof
    }
    return jsonify(response), 200

@app.route("/chain", methods=["GET"])
def full_chain():
    chain_data = []
    for b in blockchain.chain:
        chain_data.append({
            "index": b.index,
            "previous_hash": b.previous_hash,
            "nonce": b.nonce,
            "timestamp": b.timestamp,
            "merkle_root": b.merkle_root,
            "hash": b.hash(),
            "transactions": [tx.to_dict() for tx in b.transactions]
        })
    return jsonify({"chain": chain_data, "length": len(chain_data)}), 200

@app.route("/validate", methods=["GET"])
def validate_chain():
    valid = blockchain.is_valid_chain(blockchain.chain)
    return jsonify({"valid": valid}), 200

# helper endpoint to sign a transaction locally (warning: for demo only)
@app.route("/utils/sign", methods=["POST"])
def util_sign():
    values = request.get_json()
    required = ["private_key_pem", "sender_pub", "recipient_pub", "amount"]
    if not all(k in values for k in required):
        return "Missing fields", 400
    priv = load_private_key(values["private_key_pem"])
    message = json.dumps({"sender": values["sender_pub"], "recipient": values["recipient_pub"], "amount": float(values["amount"])}, sort_keys=True).encode()
    sig = sign_message(priv, message)
    return jsonify({"signature_hex": sig.hex()}), 200

if __name__ == "__main__":
    app.run(debug=True)
