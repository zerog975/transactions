# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, unicode_literals
from builtins import object
import codecs
import logging
import os

# Importing necessary modules from python-bitcoinlib
from bitcoin.core import CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint, lx, CScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinAddressError
from pycoin.key.BIP32Node import BIP32Node
from pycoin.encoding import EncodingError

from bit.transaction import address_to_scriptpubkey
from bit.transaction import sign_tx
from bit import Key
# Removed import of InvalidAddress
# from bit.exceptions import InvalidAddress

from .services.daemonservice import BitcoinDaemonService

# Initialize logging
logging.basicConfig(level=logging.DEBUG)

SERVICES = ['daemon']

class Transactions(object):
    """
    Transactions: Bitcoin for Humans

    All amounts are in satoshi.
    """

    # Transaction fee per 1k bytes
    _min_tx_fee = 10000
    # dust
    _dust = 600

    def __init__(self, service='daemon', testnet=True, username='', password='', host='', port='', wallet_filename=''):
        """
        Args:
            service (str): currently supports _blockr_ for blockr.io and and _daemon_ for bitcoin daemon. Defaults to _blockr_
            testnet (bool): use True if you want to use tesnet. Defaults to False
            username (str): username to connect to the bitcoin daemon
            password (str): password to connect to the bitcoin daemon
            host (str): host of the bitcoin daemon
            port (str): port of the bitcoin daemon
            wallet_filename (str): the name of the wallet to use with the bitcoin daemon
        """
        self.testnet = testnet

        if service not in SERVICES:
            raise Exception(f"Service '{service}' not supported")
        if service == 'daemon':
            self._service = BitcoinDaemonService(username, password, host, port, testnet, wallet_filename)

        self._min_tx_fee = self._service._min_transaction_fee
        self._dust = self._service._min_dust

    def push(self, tx):
        """
        Args:
            tx: hex of signed transaction
        Returns:
            pushed transaction
        """
        self._service.push_tx(tx)
        return bitcoin.txhash(tx)

    def get(self, hash, account="*", max_transactions=100, min_confirmations=6, raw=False):
        """
        Args:
            hash: can be a bitcoin address or a transaction id.
            account (Optional[str]): used when using bitcoind. bitcoind
                does not provide an easy way to retrieve transactions for a
                single address. By using account we can retrieve transactions
                for addresses in a specific account
        Returns:
            transaction
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

    def validate_address(self, address):
        """
        Validates a Bitcoin address.

        Args:
            address (str): Bitcoin address to validate.
        
        Raises:
            CBitcoinAddressError: If the address is invalid.
        """
        try:
            CBitcoinAddress(address)
            logging.debug(f"Validated address: {address}")
        except CBitcoinAddressError as e:
            logging.error(f"Invalid address {address}: {e}")
            raise e

    def simple_transaction(self, from_address, to, op_return=None, min_confirmations=6):
        """
        Args:
            from_address (str): bitcoin address originating the transaction
            to: tuple of ``(to_address, amount)`` or list of tuples ``[(to_addr1, amount1), (to_addr2, amount2)]``. Amounts are in *satoshi*
            op_return (str): ability to set custom ``op_return``
            min_confirmations (int): minimal number of required confirmations

        Returns:
            transaction
        """
        to = [to] if not isinstance(to, list) else to
        amount = sum([amount for _, amount in to])
        n_outputs = len(to) + 1  # change
        if op_return:
            n_outputs += 1

        # Validate the from_address and to addresses
        self.validate_address(from_address)
        for to_address, _ in to:
            self.validate_address(to_address)

        # select inputs
        inputs, change = self._select_inputs(from_address, amount, n_outputs, min_confirmations=min_confirmations)
        outputs = [{'address': to_address, 'value': amount} for to_address, amount in to]
        outputs += [{'address': from_address, 'value': change}]

        # add op_return
        if op_return:
            outputs += [{'script': self._op_return_hex(op_return), 'value': 0}]
        return self.build_transaction(inputs, outputs)

    def build_transaction(self, inputs, outputs):
        """
        Build transaction using python-bitcoinlib

        Args:
            inputs (list): inputs in the form of
                [{'txid': '...', 'vout': 0, 'amount': 10000}, ...]
            outputs (list): outputs in the form of
                [{'address': '...', 'value': 5000}, {'script': CScript([...]), 'value': 0}, ...]
        Returns:
            CMutableTransaction: unsigned transaction object
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




    def sign_transaction(self, tx, master_password, path=''):
        """
        Args:
            tx: the transaction object to sign (in hex format)
            master_password: master password or private key for BIP32 wallets. This should be the private key (WIF format).
            path (Optional[str]): optional path to the leaf address of the BIP32 wallet. 
                This allows us to retrieve the private key for the leaf address if one was used to construct the transaction.

        Returns:
            signed transaction in hex format
        """
        netcode = 'XTN' if self.testnet else 'BTC'

        # Ensure master_password is a string
        if isinstance(master_password, bytes):
            master_password = master_password.decode('utf-8')

        try:
            # Create a Key object from the private key (master_password)
            private_key = Key(master_password)
        
            # If the transaction is unsigned, use the private key to sign it
            signed_tx = sign_tx(tx, private_key)
            return signed_tx
        except Exception as e:
            # Handle possible errors (e.g., invalid key format or transaction errors)
            raise ValueError(f"Failed to sign transaction: {e}")
    def _select_inputs(self, address, amount, n_outputs=2, min_confirmations=6):
        """
        Selects the inputs to fulfill the amount

        Args:
            address (str): bitcoin address to select inputs for
            amount (int): amount to fulfill in satoshi
            n_outputs (int): number of outputs
            min_confirmations (int): minimal number of required confirmations

        Returns:
            tuple: selected inputs and change
        """
        unspents = self.get(address, min_confirmations=min_confirmations)['unspents']
        if not unspents:
            raise Exception("No spendable outputs found")

        # unspents are sorted, with the smallest amounts first
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
        try:
            hex_op_return = codecs.encode(op_return, 'hex')
        except TypeError:
            hex_op_return = codecs.encode(op_return.encode('utf-8'), 'hex')
        return "6a%x%s" % (len(op_return), hex_op_return.decode('utf-8'))

    def estimate_fee(self, n_inputs, n_outputs):
        """
        Estimate transaction fee based on the number of inputs and outputs

        Args:
            n_inputs (int): number of inputs
            n_outputs (int): number of outputs

        Returns:
            int: estimated fee in satoshi
        """
        estimated_size = 10 + 148 * n_inputs + 34 * n_outputs
        return (estimated_size // 1000 + 1) * self._min_tx_fee

    def decode(self, tx):
        """
        Decodes the given transaction.

        Args:
            tx: hex of transaction
        Returns:
            decoded transaction

        .. note:: Only supported for blockr.io at the moment.
        """
        if not isinstance(self._service, BitcoinBlockrService):
            raise NotImplementedError('Currently only supported for "blockr.io"')
        return self._service.decode(tx)

    def get_block_raw(self, block):
        """
        Args:
            block: block hash or number or special keywords like "last", "first"
        Returns:
            raw block data
        """
        return self._service.get_block_raw(block)

    def get_block_info(self, block):
        """
        Args:
            block: block hash or number or special keywords like "last", "first"
        Returns:
            basic block data
        """
        return self._service.get_block_info(block)

    # To simplify method names
    create = simple_transaction
    sign = sign_transaction
