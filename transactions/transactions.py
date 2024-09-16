# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, unicode_literals
from builtins import object
import codecs
import logging
from bitcoinrpc.authproxy import AuthServiceProxy

# Importing necessary modules from python-bitcoinlib
from bitcoin.core import CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint, lx, CScript, b2x
from bitcoin.wallet import CBitcoinAddress, CBitcoinAddressError, CBitcoinSecret
from bitcoin.core.script import OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
import bitcoin.rpc
from bitcoin.base58 import decode as b58decode_check
import hashlib

from bit import Key
from bit.network import NetworkAPI

# Set network parameters (testnet/mainnet)
#from bitcoin.core import SelectParams
#SelectParams('testnet')  # Use 'mainnet' if needed

# Importing from pycoin for BIP32 key management
from pycoin.key.BIP32Node import BIP32Node

# Importing the `bit` library for transaction handling
from bit.transaction import address_to_scriptpubkey, create_new_transaction, create_new_transaction

# Import your BitcoinDaemonService
from .services.daemonservice import BitcoinDaemonService

# Initialize logging
logging.basicConfig(level=logging.DEBUG)

# Supported services
SERVICES = ['daemon']

class Transactions(object):
    """
    Transactions: Bitcoin for Humans

    All amounts are in satoshi.
    """

    # Transaction fee per 1k bytes and dust amount
    _min_tx_fee = 10000
    _dust = 600

    def __init__(self, service='daemon', testnet=True, username='', password='', host='', port='', wallet_filename=''):
        """
        Args:
            service (str): Service type. Currently supports 'daemon' for bitcoin daemon. Defaults to 'daemon'.
            testnet (bool): Whether to use testnet. Defaults to True.
            username (str): Username for bitcoin daemon RPC.
            password (str): Password for bitcoin daemon RPC.
            host (str): Bitcoin daemon host.
            port (str): Bitcoin daemon port.
            wallet_filename (str): The wallet filename to use with bitcoin daemon.
        """
        self.testnet = testnet
        self.netcode = 'XTN' if testnet else 'BTC'  # Set network based on testnet flag
        # Validate the service
        if service not in SERVICES:
            raise Exception(f"Service '{service}' not supported")

        # Initialize the Bitcoin daemon service
        if service == 'daemon':
            self._service = BitcoinDaemonService(username, password, host, port, testnet, wallet_filename)

        # Set transaction fee and dust limit
        self._min_tx_fee = self._service._min_transaction_fee
        self._dust = self._service._min_dust

    def push(self, tx):
        """
        Pushes a signed transaction to the network.
        
        Args:
            tx (str): Hex of the signed transaction.
        Returns:
            str: Transaction ID.
        """
        self._service.push_tx(tx)
        return bitcoin.txhash(tx)

    def get(self, hash, account="*", max_transactions=100, min_confirmations=6, raw=False):
        """
        Get transaction data.
        
        Args:
            hash (str): A bitcoin address or a transaction ID.
            account (str): Optional account for filtering transactions in bitcoind.
            max_transactions (int): Maximum transactions to retrieve. Defaults to 100.
            min_confirmations (int): Minimum confirmations for UTXOs.
            raw (bool): Return raw transaction data.
        Returns:
            dict: Transaction and UTXO data.
        """
        if len(hash) < 64:
            txs = self._service.list_transactions(hash, account=account, max_transactions=max_transactions)
            unspents = self._service.list_unspents(hash, min_confirmations=min_confirmations)
            return {'transactions': txs, 'unspents': unspents}
        else:
            return self._service.get_transaction(hash, raw=raw)

    def import_address(self, address, account="", rescan=False):
        """
        Imports a bitcoin address into the wallet.
        """
        if isinstance(self._service, BitcoinDaemonService):
            self._service.import_address(address, account, rescan=rescan)

    def validate_address(self, address):
        """
        Validates a Bitcoin address.
        """
        try:
            CBitcoinAddress(address)
            logging.debug(f"Validated address: {address}")
        except CBitcoinAddressError as e:
            logging.error(f"Invalid address {address}: {e}")
            raise e

    def simple_transaction(self, from_address, to, op_return=None, min_confirmations=6):
        """
        Creates a simple transaction.
        """
        to = [to] if not isinstance(to, list) else to
        amount = sum([amount for _, amount in to])
        n_outputs = len(to) + 1  # For change

        if op_return:
            n_outputs += 1

        # Validate addresses
        self.validate_address(from_address)
        for to_address, _ in to:
            self.validate_address(to_address)

        inputs, change = self._select_inputs(from_address, amount, n_outputs, min_confirmations=min_confirmations)
        outputs = [{'address': to_address, 'value': amount} for to_address, amount in to]
        outputs += [{'address': from_address, 'value': change}]

        if op_return:
            outputs += [{'script': self._op_return_hex(op_return), 'value': 0}]

        return self.build_transaction(inputs, outputs)

    def build_transaction(self, inputs, outputs):
        """
        Build and return a CMutableTransaction.
        """
        txins = [CMutableTxIn(COutPoint(lx(input['txid']), input['vout'])) for input in inputs]
        txouts = []
        for output in outputs:
            if 'script' in output:
                txouts.append(CMutableTxOut(output['value'], output['script']))
            else:
                try:
                    script_pubkey = CScript(address_to_scriptpubkey(output['address']))
                    txouts.append(CMutableTxOut(output['value'], script_pubkey))
                except ValueError as e:
                    raise ValueError(f"Invalid Bitcoin address: {output['address']}") from e

        return CMutableTransaction(txins, txouts)





    def sign_transaction(self, unsigned_tx, master_password, unspents, path=''):
        """
        Signs the transaction with the derived private key using the bit library.
        """
        if isinstance(master_password, bytes):
            master_password = master_password.decode('utf-8')

        try:
            # Use the netcode based on whether testnet or mainnet is set in the daemon
            netcode = 'XTN' if self.testnet else 'BTC'
            bip32_node = BIP32Node.from_master_secret(master_password.encode('utf-8'), netcode=netcode)
            private_key_wif = bip32_node.subkey_for_path(path).wif() if path else bip32_node.wif()

            # Create a Key object using the bit library
            private_key = Key(private_key_wif)

            # Ensure that each unspent has a 'scriptPubKey'
            for unspent in unspents:
                if 'scriptPubKey' not in unspent or not unspent['scriptPubKey']:
                    # Fetch scriptPubKey if not present
                    unspent['scriptPubKey'] = self.fetch_scriptpubkey(unspent['txid'], unspent['vout'])

            # Helper function to extract the address from a txout
            def txout_to_address(txout):
                script_pubkey = txout.scriptPubKey

                # Handle P2PKH (Pay-to-PubKey-Hash) scripts
                if (script_pubkey[0] == OP_DUP and
                    script_pubkey[1] == OP_HASH160 and
                    script_pubkey[-2] == OP_EQUALVERIFY and
                    script_pubkey[-1] == OP_CHECKSIG):

                    # Extract the public key hash from the scriptPubKey
                    pubkey_hash = script_pubkey[2]

                    # Convert the pubkey_hash to bytes if it's an int
                    if isinstance(pubkey_hash, int):
                        pubkey_hash = bytes([pubkey_hash])

                    # Add the appropriate prefix for testnet or mainnet
                    prefix = b'\x6f' if self.testnet else b'\x00'

                    # Prepend the prefix to the pubkey_hash
                    pubkey_hash_with_prefix = prefix + pubkey_hash

                    # Perform a double SHA-256 hash on the prefixed pubkey_hash
                    checksum = hashlib.sha256(hashlib.sha256(pubkey_hash_with_prefix).digest()).digest()[:4]

                    # Append the first four bytes of the checksum to the prefixed pubkey_hash
                    binary_address = pubkey_hash_with_prefix + checksum

                    # Convert the binary address to a base58 address
                    address = b2x(binary_address)  # You might need a proper base58 encoder here
                    return str(address)

                # Handle OP_RETURN scripts (embedded data, no address)
                elif script_pubkey[0] == OP_RETURN:
                    return "OP_RETURN"

                # Raise an exception for unsupported script types
                else:
                    raise ValueError(f"Unsupported script type: {script_pubkey}")


            # Prepare inputs and outputs in the format expected by the bit library
            inputs = [(unspent['txid'], unspent['vout'], unspent['scriptPubKey'], unspent['amount']) for unspent in unspents]
            outputs = [{'address': txout_to_address(txout), 'value': txout.nValue} for txout in unsigned_tx.vout]

            # Create a new unsigned transaction
            tx_hex = create_new_transaction(inputs, outputs)

            # Sign the transaction using the private key's sign_transaction method
            signed_tx = private_key.sign_transaction(tx_hex)

            return signed_tx

        except Exception as e:
            raise ValueError(f"Failed to sign transaction using bit library: {e}")




    def _select_inputs(self, address, amount, n_outputs=2, min_confirmations=6):
        """
        Select inputs for the transaction.
        """
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
        return inputs, change

    def _op_return_hex(self, op_return):
        hex_op_return = codecs.encode(op_return.encode('utf-8'), 'hex')
        return "6a%x%s" % (len(op_return), hex_op_return.decode('utf-8'))

    def estimate_fee(self, n_inputs, n_outputs):
        """
        Estimate transaction fee.
        """
        estimated_size = 10 + 148 * n_inputs + 34 * n_outputs
        return (estimated_size // 1000 + 1) * self._min_tx_fee

    def fetch_scriptpubkey(self, txid, vout):
        """
        Fetch the scriptPubKey using the `gettxout` RPC call.
        """
        response = self._service.rpc_connection.gettxout(txid, vout)
        if response and 'scriptPubKey' in response:
            return response['scriptPubKey']['hex']
        else:
            raise ValueError(f"Failed to retrieve scriptPubKey for {txid}:{vout}")

# Main execution
if __name__ == "__main__":
    transactions = Transactions(service='daemon', testnet=True, username='bitcoinrpcuser1337', 
                                password='bitcoinrpcpassword1337', host='10.0.0.98', 
                                port='18332', wallet_filename='legacytestnetwallet')

    # Example use case: Create a transaction
    inputs = [{'txid': 'f219df0756ad72e2a062fa97027f67e86a52864c4de2db2a4c9ed5b6987265dd', 'vout': 0}]
    outputs = {'mpe22RcPPP1qdNgwLJRPWUcNhbgb8SWGRc': 30000}  # Example output

    hex_tx = transactions.build_transaction(inputs, outputs)
    print(f"Serialized transaction: {hex_tx}")
