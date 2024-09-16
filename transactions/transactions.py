# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, unicode_literals
from builtins import object
import codecs
import logging
import hashlib
from bitcoinrpc.authproxy import AuthServiceProxy
# Assuming BitcoinDaemonService is located in .services.daemonservice
from .services.daemonservice import BitcoinDaemonService

# Importing necessary modules from python-bitcoinlib
import bitcoin
from bitcoin.core import (
    CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint, lx, CScript, b2x
)
from bitcoin.wallet import CBitcoinAddress, CBitcoinAddressError, CBitcoinSecret
from bitcoin.core.script import (
    OP_RETURN, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, SignatureHash, SIGHASH_ALL
)
import bitcoin.rpc
from bitcoin.base58 import decode as b58decode_check

# Importing from pycoin for BIP32 key management
from pycoin.key.BIP32Node import BIP32Node

# Initialize logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Supported services
SERVICES = ['daemon']

class Transactions(object):
    """
    Transactions: Bitcoin for Humans
    All amounts are in satoshi.
    """

    _min_tx_fee = 10000  # Transaction fee per 1k bytes
    _dust = 600          # Dust amount threshold

    def __init__(self, service='daemon', testnet=True, username='', password='', host='', port='', wallet_filename=''):
        self.testnet = testnet
        self.netcode = 'XTN' if testnet else 'BTC'  # Set network based on testnet flag
        logging.debug(f"Network: {'Testnet' if self.testnet else 'Mainnet'}")

        # Select network parameters
        if self.testnet:
            bitcoin.SelectParams('testnet')
        else:
            bitcoin.SelectParams('mainnet')

        if service not in SERVICES:
            raise Exception(f"Service '{service}' not supported")
        
        if service == 'daemon':
            self._service = BitcoinDaemonService(username, password, host, port, testnet, wallet_filename)
            logging.debug(f"Initialized BitcoinDaemonService with host: {host}, port: {port}")

        self._min_tx_fee = self._service._min_transaction_fee
        self._dust = self._service._min_dust
        logging.debug(f"Transaction fee: {self._min_tx_fee}, Dust threshold: {self._dust}")

   


    def push(self, tx):
        self._service.push_tx(tx)
        logging.debug(f"Pushed transaction: {tx}")
        return bitcoin.txhash(tx)

    def get(self, hash, account="*", max_transactions=100, min_confirmations=6, raw=False):
        logging.debug(f"Fetching transaction data for hash: {hash}")
        if len(hash) < 64:
            txs = self._service.list_transactions(hash, account=account, max_transactions=max_transactions)
            unspents = self._service.list_unspents(hash, min_confirmations=min_confirmations)
            return {'transactions': txs, 'unspents': unspents}
        else:
            return self._service.get_transaction(hash, raw=raw)

    def import_address(self, address, account="", rescan=False):
        logging.debug(f"Importing address: {address} with rescan={rescan}")
        if isinstance(self._service, BitcoinDaemonService):
            self._service.import_address(address, account, rescan=rescan)

    def validate_address(self, address):
        logging.debug(f"Validating address: {address}")
        try:
            CBitcoinAddress(address)
            logging.debug(f"Validated address: {address}")
        except CBitcoinAddressError as e:
            logging.error(f"Invalid address: {address}")
            raise e

    def simple_transaction(self, from_address, to, op_return=None, min_confirmations=6):
        to = [to] if not isinstance(to, list) else to
        amount = sum([amt for _, amt in to])
        n_outputs = len(to) + 1  # One output for change

        if op_return:
            n_outputs += 1

        self.validate_address(from_address)
        for to_address, _ in to:
            self.validate_address(to_address)

        inputs, change = self._select_inputs(from_address, amount, n_outputs, min_confirmations=min_confirmations)
        outputs = [{'address': to_address, 'value': amt} for to_address, amt in to]
        outputs.append({'address': from_address, 'value': change})

        if op_return:
            outputs.append({'script': self._op_return_hex(op_return), 'value': 0})

        logging.debug(f"Simple transaction from {from_address} to {to}: inputs: {inputs}, outputs: {outputs}")
        return self.build_transaction(inputs, outputs)

    def sign_transaction(self, unsigned_tx, master_password, unspents, path=''):
        logging.debug(f"Signing transaction with master_password: {master_password} and unspents: {unspents}")
        
        # Decode master password if it's in bytes
        if isinstance(master_password, bytes):
            master_password = master_password.decode('utf-8')

        try:
            # Derive private key using BIP32 and the given master password
            netcode = 'XTN' if self.testnet else 'BTC'
            bip32_node = BIP32Node.from_master_secret(master_password.encode('utf-8'), netcode=netcode)
            private_key_wif = bip32_node.subkey_for_path(path).wif() if path else bip32_node.wif()
            priv_key = CBitcoinSecret(private_key_wif)
            pub_key = priv_key.pub

            # Ensure each unspent has 'scriptPubKey'
            for unspent in unspents:
                if 'scriptPubKey' not in unspent or not unspent['scriptPubKey']:
                    unspent['scriptPubKey'] = self.fetch_scriptpubkey(unspent['txid'], unspent['vout'])

            # Sign each input
            for i, txin in enumerate(unsigned_tx.vin):
                unspent = unspents[i]
                txin_scriptPubKey = CScript(bytes.fromhex(unspent['scriptPubKey']))
                sighash = SignatureHash(txin_scriptPubKey, unsigned_tx, i, SIGHASH_ALL)
                sig = priv_key.sign(sighash) + bytes([SIGHASH_ALL])
                txin.scriptSig = CScript([sig, pub_key])

            # Serialize signed transaction
            signed_tx_hex = unsigned_tx.serialize().hex()
            logging.debug(f"Signed transaction: {signed_tx_hex}")

            return signed_tx_hex

        except Exception as e:
            logging.error(f"Failed to sign transaction: {e}")
            raise ValueError(f"Failed to sign transaction: {e}")



    def _select_inputs(self, address, amount, n_outputs=2, min_confirmations=6):
        unspents = self.get(address, min_confirmations=min_confirmations)['unspents']
        if not unspents:
            raise Exception("No spendable outputs found")

        unspents = sorted(unspents, key=lambda d: d['amount'])
        balance, inputs = 0, []
        fee = self._service._min_transaction_fee

        while balance < amount + fee:
            unspent = unspents.pop()
            balance += unspent['amount']
            inputs.append(unspent)
            fee = self.estimate_fee(len(inputs), n_outputs)

        change = max(0, balance - amount - fee)
        logging.debug(f"Selected inputs: {inputs}, change: {change}")
        return inputs, change

    def _op_return_hex(self, op_return):
        hex_op_return = codecs.encode(op_return.encode('utf-8'), 'hex')
        return "6a%x%s" % (len(op_return), hex_op_return.decode('utf-8'))

    def estimate_fee(self, n_inputs, n_outputs):
        estimated_size = 10 + 148 * n_inputs + 34 * n_outputs
        return (estimated_size // 1000 + 1) * self._min_tx_fee

    def fetch_scriptpubkey(self, txid, vout):
        response = self._service.rpc_connection.gettxout(txid, vout)
        if response and 'scriptPubKey' in response:
            return response['scriptPubKey']['hex']
        else:
            raise ValueError(f"Failed to retrieve scriptPubKey for {txid}:{vout}")
    

    def build_transaction(self, inputs, outputs):
        """
        Build a transaction using the provided inputs and outputs.
        
        Args:
            inputs (list): A list of dictionaries containing 'txid', 'vout', 'scriptPubKey', and 'amount'.
            outputs (list): A list of dictionaries containing 'address' or 'script' and 'value'.
            
        Returns:
            CMutableTransaction: The constructed Bitcoin transaction.
        """
        # Create the transaction inputs
        txins = []
        for input in inputs:
            outpoint = COutPoint(lx(input['txid']), input['vout'])
            txin = CMutableTxIn(outpoint)
            txins.append(txin)
        
        # Create the transaction outputs
        txouts = []
        for output in outputs:
            if 'script' in output:
                # Handle both hex string and CScript
                if isinstance(output['script'], str):
                    script = CScript(bytes.fromhex(output['script']))
                elif isinstance(output['script'], CScript):
                    script = output['script']
                else:
                    raise TypeError("output['script'] must be a hex string or CScript object")
                txout = CMutableTxOut(output['value'], script)
            else:
                # Standard P2PKH output
                txout = CMutableTxOut(output['value'], CScript([
                    OP_DUP, OP_HASH160, b58decode_check(output['address']),
                    OP_EQUALVERIFY, OP_CHECKSIG
                ]))
            txouts.append(txout)

    # Create the transaction
    tx = CMutableTransaction(txins, txouts)
    logging.debug(f"Built transaction: {b2x(tx.serialize())}")
    return tx

# Main execution
if __name__ == "__main__":
    transactions = Transactions(service='daemon', testnet=True, username='bitcoinrpcuser1337',
                                password='bitcoinrpcpassword1337', host='10.0.0.98', 
                                port='18332', wallet_filename='legacytestnetwallet')

    inputs = [{'txid': 'f219df0756ad72e2a062fa97027f67e86a52864c4de2db2a4c9ed5b6987265dd', 'vout': 0}]
    outputs = {'mpe22RcPPP1qdNgwLJRPWUcNhbgb8SWGRc': 30000}  # Example output

    hex_tx = transactions.build_transaction(inputs, outputs)
    logging.info(f"Serialized transaction: {hex_tx}")
