# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, unicode_literals
from builtins import object
import codecs
import logging
import os
from decimal import Decimal

from bitcoin import SelectParams
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress, CBitcoinAddressError
from bitcoin.core import (
    b2x, lx, COIN, CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint, Hash160, CScript, OP_RETURN
)
from bitcoin.core.script import SignatureHash, SIGHASH_ALL
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.rpc import Proxy

# Initialize logging
logging.basicConfig(level=logging.DEBUG)

SERVICES = ['daemon']

class Transactions(object):
    """
    Transactions: Bitcoin for Humans

    All amounts are in satoshi.
    """

    # Transaction fee per 1k bytes (satoshi)
    _min_tx_fee = 10000
    # dust threshold (satoshi)
    _dust = 600

    def __init__(self, service='daemon', testnet=True, username='', password='', host='', port='', wallet_filename=''):
        """
        Args:
            service (str): currently supports 'daemon' for Bitcoin daemon.
            testnet (bool): use True for testnet, False for mainnet.
            username (str): RPC username for the Bitcoin daemon.
            password (str): RPC password for the Bitcoin daemon.
            host (str): Host address of the Bitcoin daemon.
            port (str): RPC port of the Bitcoin daemon.
            wallet_filename (str): The name of the wallet to use with the Bitcoin daemon.
        """
        self.testnet = testnet

        # Select network parameters
        if self.testnet:
            SelectParams('testnet')
        else:
            SelectParams('mainnet')

        if service not in SERVICES:
            raise Exception(f"Service '{service}' not supported")
        if service == 'daemon':
            self._service = BitcoinDaemonService(username, password, host, port, testnet, wallet_filename)

        self._min_tx_fee = self._service._min_transaction_fee
        self._dust = self._service._min_dust

    def push(self, raw_tx):
        """
        Broadcast a raw signed transaction to the Bitcoin network.

        Args:
            raw_tx (str): Raw transaction in hexadecimal format.

        Returns:
            str: Transaction ID (txid).
        """
        return self._service.push_tx(raw_tx)

    def get(self, identifier, account="*", max_transactions=100, min_confirmations=6, raw=False):
        """
        Retrieve transactions or a specific transaction.

        Args:
            identifier (str): Bitcoin address or transaction ID.
            account (Optional[str]): Account name for RPC calls.
            max_transactions (int): Maximum number of transactions to retrieve.
            min_confirmations (int): Minimum number of confirmations for UTXOs.
            raw (bool): If True, return raw transaction data.

        Returns:
            dict or str: Transaction details or raw transaction hex.
        """
        if len(hash) < 64:
            txs = self._service.list_transactions(hash, account=account, max_transactions=max_transactions)
            unspents = self._service.list_unspents(hash, min_confirmations=min_confirmations)
            return {'transactions': txs, 'unspents': unspents}
        else:
            return self._service.get_transaction(hash, raw=raw)

    def import_address(self, address, account="", rescan=False):
        if isinstance(self._service, BitcoinDaemonService):
            self._service.import_address(address, account, rescan=rescan)
    

    def import_address(self, address, account="", rescan=False):
        """
        Import a Bitcoin address into the wallet.

        Args:
            address (str): Bitcoin address to import.
            account (str): Account name.
            rescan (bool): Whether to rescan the blockchain for transactions.
        """
        if isinstance(self._service, BitcoinDaemonService):
            self._service.import_address(address, account, rescan=rescan)

    def validate_address(self, address):
        """
        Validate a Bitcoin address.

        Args:
            address (str): Bitcoin address to validate.

        Raises:
            CBitcoinAddressError: If the address is invalid.
        """
        try:
            P2PKHBitcoinAddress.from_string(address)
            logging.debug(f"Validated address: {address}")
        except CBitcoinAddressError as e:
            logging.error(f"Invalid address {address}: {e}")
            raise e

    def simple_transaction(self, from_address, to, op_return=None, min_confirmations=6):
        """
        Create a simple Bitcoin transaction.

        Args:
            from_address (str): Bitcoin address sending the funds.
            to (tuple or list of tuples): Recipient address(es) and amount(s) in satoshi.
            op_return (str): Optional data to embed in OP_RETURN.
            min_confirmations (int): Minimum confirmations required for UTXOs.

        Returns:
            CMutableTransaction: Unsigned transaction object.
        """
        to = [to] if not isinstance(to, list) else to
        amount = sum([amount for _, amount in to])
        n_outputs = len(to) + 1  # +1 for change
        if op_return:
            n_outputs += 1

        # Validate addresses
        self.validate_address(from_address)
        for to_address, _ in to:
            self.validate_address(to_address)

        # Select inputs
        inputs, change = self._select_inputs(from_address, amount, n_outputs, min_confirmations=min_confirmations)
        outputs = [CMutableTxOut(amount, P2PKHBitcoinAddress.to_scriptPubKey(to_address)) for to_address, amount in to]
        outputs.append(CMutableTxOut(change, P2PKHBitcoinAddress.to_scriptPubKey(from_address)))

        # Add OP_RETURN output if needed
        if op_return:
            op_return_script = self._op_return_script(op_return)
            outputs.append(CMutableTxOut(0, op_return_script))

        # Build the unsigned transaction
        return CMutableTransaction(inputs, outputs)

    def build_transaction(self, inputs, outputs):
        """
        Build an unsigned transaction.

        Args:
            inputs (list): List of CMutableTxIn objects.
            outputs (list): List of CMutableTxOut objects.

        Returns:
            CMutableTransaction: Unsigned transaction object.
        """
        return CMutableTransaction(inputs, outputs)

    def sign_transaction(self, tx, private_key_wif):
        """
        Sign a Bitcoin transaction.

        Args:
            tx (CMutableTransaction): The transaction to sign.
            private_key_wif (str): Private key in WIF format.

        Returns:
            str: Signed transaction in hexadecimal format.
        """
        secret = CBitcoinSecret(private_key_wif)
        public_key = secret.pub
        address = P2PKHBitcoinAddress.from_pubkey(public_key)

        # Fetch UTXOs for the from_address
        unspents = self._service.list_unspents(address)

        for i, txin in enumerate(tx.vin):
            utxo = unspents[i]
            script_pubkey = utxo['scriptPubKey']
            amount = utxo['amount']
            sighash = SignatureHash(CScript(x(script_pubkey)), tx, i, SIGHASH_ALL)
            sig = secret.sign(sighash) + bytes([SIGHASH_ALL])
            txin.scriptSig = CScript([sig, public_key])

            # Verify the signature
            try:
                VerifyScript(txin.scriptSig, CScript(x(script_pubkey)), tx, i, (SCRIPT_VERIFY_P2SH,))
                logging.debug(f"Input {i} signature verified.")
            except Exception as e:
                logging.error(f"Signature verification failed for input {i}: {e}")
                raise e

        # Serialize the transaction
        signed_tx_hex = b2x(tx.serialize())
        return signed_tx_hex

    def _select_inputs(self, address, amount, n_outputs=2, min_confirmations=6):
        """
        Select UTXOs to cover the amount and estimated fees.

        Args:
            address (str): Bitcoin address to select UTXOs for.
            amount (int): Amount to cover in satoshi.
            n_outputs (int): Number of outputs (including change).
            min_confirmations (int): Minimum confirmations required.

        Returns:
            tuple: Selected inputs (list of CMutableTxIn) and change amount.
        """
        unspents = self._service.list_unspents(address, min_confirmations=min_confirmations)
        if not unspents:
            raise Exception("No spendable outputs found.")

        # Sort UTXOs by amount (ascending)
        unspents = sorted(unspents, key=lambda x: x['amount'])
        selected = []
        total = 0
        fee = self._min_tx_fee

        for utxo in reversed(unspents):  # Start with the largest UTXOs
            selected.append(utxo)
            total += utxo['amount']
            # Estimate fee based on number of inputs and outputs
            estimated_size = 180 * len(selected) + 34 * n_outputs + 10
            fee = int(Decimal(estimated_size / 1000).to_integral_value(rounding='ROUND_UP') * self._min_tx_fee)
            if total >= amount + fee:
                break

        if total < amount + fee:
            raise Exception("Insufficient funds to cover the amount and fee.")

        change = total - amount - fee
        if change < self._dust:
            change = 0  # Avoid creating dust

        # Create CMutableTxIn objects
        inputs = [CMutableTxIn(COutPoint(lx(utxo['txid']), utxo['vout'])) for utxo in selected]

        return inputs, change

    def _op_return_script(self, data):
        """
        Create an OP_RETURN script.

        Args:
            data (str): Data to embed in OP_RETURN.

        Returns:
            CScript: OP_RETURN script.
        """
        return CScript([OP_RETURN, data.encode('utf-8')])

    def estimate_fee(self, n_inputs, n_outputs):
        """
        Estimate transaction fee based on the number of inputs and outputs.

        Args:
            n_inputs (int): Number of inputs.
            n_outputs (int): Number of outputs.

        Returns:
            int: Estimated fee in satoshi.
        """
        estimated_size = 180 * n_inputs + 34 * n_outputs + 10
        return (estimated_size // 1000 + 1) * self._min_tx_fee

    def decode(self, raw_tx):
        """
        Decode a raw transaction.

        Args:
            raw_tx (str): Raw transaction in hexadecimal format.

        Returns:
            dict: Decoded transaction details.
        """
        return self._service.decode(raw_tx)

    def get_block_raw(self, block):
        """
        Retrieve raw block data.

        Args:
            block (str or int): Block hash or number.

        Returns:
            str: Raw block data in hexadecimal format.
        """
        return self._service.get_block_raw(block)

    def get_block_info(self, block):
        """
        Retrieve block information.

        Args:
            block (str or int): Block hash or number.

        Returns:
            dict: Block information.
        """
        return self._service.get_block_info(block)

    # Alias methods
    create = simple_transaction
    sign = sign_transaction

class BitcoinDaemonService:
    """
    Service class to interact with Bitcoin Core via RPC.
    """

    def __init__(self, username, password, host, port, testnet=True, wallet_filename=''):
        """
        Initialize the RPC connection to Bitcoin Core.

        Args:
            username (str): RPC username.
            password (str): RPC password.
            host (str): RPC host.
            port (str): RPC port.
            testnet (bool): Use testnet if True.
            wallet_filename (str): Wallet name to use.
        """
        self.username = username
        self.password = password
        self.host = host or 'localhost'
        self.port = port or ('18332' if testnet else '8332')
        self.wallet_filename = wallet_filename
        self.testnet = testnet

        self.rpc = Proxy(service_url=f'http://{self.username}:{self.password}@{self.host}:{self.port}')

        self._min_transaction_fee = 10000  # Satoshi per kB
        self._min_dust = 600  # Satoshi

    def push_tx(self, raw_tx):
        """
        Broadcast a raw transaction.

        Args:
            raw_tx (str): Raw transaction in hexadecimal format.

        Returns:
            str: Transaction ID.
        """
        return self.rpc.sendrawtransaction(raw_tx)

    def get_transaction(self, txid, raw=False):
        """
        Get transaction details.

        Args:
            txid (str): Transaction ID.
            raw (bool): If True, return raw transaction hex.

        Returns:
            dict or str: Transaction details or raw transaction.
        """
        tx = self.rpc.getrawtransaction(txid, 1)
        if raw:
            return self.rpc.getrawtransaction(txid, 0)
        return tx

    def list_transactions(self, account, max_transactions=100):
        """
        List recent transactions for an account.

        Args:
            account (str): Account name.
            max_transactions (int): Maximum number of transactions to retrieve.

        Returns:
            list: List of transactions.
        """
        return self.rpc.listtransactions(account, max_transactions)

    def list_unspents(self, address, min_confirmations=6):
        """
        List unspent transaction outputs (UTXOs) for an address.

        Args:
            address (str): Bitcoin address.
            min_confirmations (int): Minimum confirmations.

        Returns:
            list: List of unspent outputs.
        """
        return self.rpc.listunspent(min_confirmations, 9999999, [address])

    def import_address(self, address, account, rescan=False):
        """
        Import an address into the wallet.

        Args:
            address (str): Bitcoin address.
            account (str): Account name.
            rescan (bool): Whether to rescan the blockchain.
        """
        self.rpc.importaddress(address, account, rescan)

    def decode(self, raw_tx):
        """
        Decode a raw transaction.

        Args:
            raw_tx (str): Raw transaction in hexadecimal format.

        Returns:
            dict: Decoded transaction.
        """
        return self.rpc.decoderawtransaction(raw_tx)

    def get_block_raw(self, block):
        """
        Get raw block data.

        Args:
            block (str or int): Block hash or number.

        Returns:
            str: Raw block data in hexadecimal format.
        """
        if isinstance(block, int):
            block_hash = self.rpc.getblockhash(block)
        else:
            block_hash = block
        return self.rpc.getblock(block_hash, 0)

    def get_block_info(self, block):
        """
        Get block information.

        Args:
            block (str or int): Block hash or number.

        Returns:
            dict: Block information.
        """
        if isinstance(block, int):
            block_hash = self.rpc.getblockhash(block)
        else:
            block_hash = block
        return self.rpc.getblock(block_hash, 2)

