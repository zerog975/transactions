# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, unicode_literals
from builtins import object
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
    # Dust threshold (satoshi)
    _dust = 600

    def __init__(self, service='daemon', testnet=True, username='', password='', host='', port='', wallet_filename=''):
        """
        Args:
            service (str): Currently supports 'daemon' for Bitcoin daemon.
            testnet (bool): Use True for testnet, False for mainnet.
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

    def get(self, identifier, max_transactions=100, min_confirmations=6, raw=False):
        """
        Retrieve transactions or a specific transaction.

        Args:
            identifier (str): Bitcoin address or transaction ID.
            max_transactions (int): Maximum number of transactions to retrieve.
            min_confirmations (int): Minimum number of confirmations for UTXOs.
            raw (bool): If True, return raw transaction data.

        Returns:
            dict or str: Transaction details or raw transaction hex.
        """
        logging.debug(f"Transactions.get called with identifier={identifier}, "
                      f"max_transactions={max_transactions}, min_confirmations={min_confirmations}, raw={raw}")

        if len(identifier) < 64:
            # Assume it's a Bitcoin address
            try:
                received = self._service.list_received_by_address(minconf=min_confirmations, include_empty=False)
                # Filter for the specific address
                filtered = [r for r in received if r.get('address') == identifier]
                logging.debug(f"Retrieved {len(filtered)} received transactions for address '{identifier}'.")
                
                unspents = self._service.list_unspents(address=identifier, min_confirmations=min_confirmations)
                return {'transactions': filtered, 'unspents': unspents}
            except Exception as e:
                logging.error(f"Error retrieving transactions for address {identifier}: {e}")
                raise
        else:
            # Assume it's a transaction ID
            try:
                transaction = self._service.get_transaction(txid=identifier, raw=raw)
                if raw:
                    return {'transactions': transaction}
                else:
                    return {'transactions': transaction}
            except Exception as e:
                logging.error(f"Error retrieving transaction {identifier}: {e}")
                raise

    def import_address(self, address, account="", rescan=False):
        """
        Import a Bitcoin address into the wallet.

        Args:
            address (str): Bitcoin address to import.
            account (str): Account name.
            rescan (bool): Whether to rescan the blockchain for transactions.
        """
        if isinstance(self._service, BitcoinDaemonService):
            try:
                self._service.import_address(address, account, rescan=rescan)
                logging.debug(f"Imported address {address} with account '{account}' and rescan={rescan}.")
            except Exception as e:
                logging.error(f"Error importing address {address}: {e}")
                raise

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
        tx = CMutableTransaction(inputs, outputs)
        logging.debug(f"Created unsigned transaction with {len(inputs)} inputs and {len(outputs)} outputs.")
        return tx

    def build_transaction(self, inputs, outputs):
        """
        Build an unsigned transaction.

        Args:
            inputs (list): List of CMutableTxIn objects.
            outputs (list): List of CMutableTxOut objects.

        Returns:
            CMutableTransaction: Unsigned transaction object.
        """
        tx = CMutableTransaction(inputs, outputs)
        logging.debug(f"Built unsigned transaction with {len(inputs)} inputs and {len(outputs)} outputs.")
        return tx

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
        try:
            unspents = self._service.list_unspents(address=address, min_confirmations=6)
        except Exception as e:
            logging.error(f"Error fetching UTXOs for address {address}: {e}")
            raise

        for i, txin in enumerate(tx.vin):
            if i >= len(unspents):
                logging.error(f"Not enough unspent outputs to sign input {i}.")
                raise Exception(f"Not enough unspent outputs to sign input {i}.")

            utxo = unspents[i]
            script_pubkey = utxo['scriptPubKey']
            amount = utxo['amount']
            sighash = SignatureHash(CScript(bytes.fromhex(script_pubkey)), tx, i, SIGHASH_ALL)
            sig = secret.sign(sighash) + bytes([SIGHASH_ALL])
            txin.scriptSig = CScript([sig, public_key])

            # Verify the signature
            try:
                VerifyScript(txin.scriptSig, CScript(bytes.fromhex(script_pubkey)), tx, i, (SCRIPT_VERIFY_P2SH,))
                logging.debug(f"Input {i} signature verified.")
            except Exception as e:
                logging.error(f"Signature verification failed for input {i}: {e}")
                raise e

        # Serialize the transaction
        signed_tx_hex = b2x(tx.serialize())
        logging.debug(f"Signed transaction: {signed_tx_hex}")
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
        try:
            unspents = self._service.list_unspents(address=address, min_confirmations=min_confirmations)
        except Exception as e:
            logging.error(f"Error listing unspents for address {address}: {e}")
            raise

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

        logging.debug(f"Selected {len(selected)} UTXOs totaling {total} satoshis with change {change} satoshis.")
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
        fee = (estimated_size // 1000 + 1) * self._min_tx_fee
        logging.debug(f"Estimated fee for {n_inputs} inputs and {n_outputs} outputs: {fee} satoshis.")
        return fee

    def decode(self, raw_tx):
        """
        Decode a raw transaction.

        Args:
            raw_tx (str): Raw transaction in hexadecimal format.

        Returns:
            dict: Decoded transaction details.
        """
        try:
            decoded = self._service.decode(raw_tx)
            logging.debug(f"Decoded transaction: {decoded}")
            return decoded
        except Exception as e:
            logging.error(f"Error decoding transaction {raw_tx}: {e}")
            raise e

    def get_block_raw(self, block):
        """
        Retrieve raw block data.

        Args:
            block (str or int): Block hash or number.

        Returns:
            str: Raw block data in hexadecimal format.
        """
        try:
            raw_block = self._service.get_block_raw(block)
            logging.debug(f"Retrieved raw block data for block {block}: {raw_block}")
            return raw_block
        except Exception as e:
            logging.error(f"Error retrieving raw block data for block {block}: {e}")
            raise e

    def get_block_info(self, block):
        """
        Retrieve block information.

        Args:
            block (str or int): Block hash or number.

        Returns:
            dict: Block information.
        """
        try:
            block_info = self._service.get_block_info(block)
            logging.debug(f"Retrieved block info for block {block}: {block_info}")
            return block_info
        except Exception as e:
            logging.error(f"Error retrieving block info for block {block}: {e}")
            raise e

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

        # Initialize the RPC connection
        if self.wallet_filename:
            service_url = f'http://{self.username}:{self.password}@{self.host}:{self.port}/wallet/{self.wallet_filename}'
        else:
            service_url = f'http://{self.username}:{self.password}@{self.host}:{self.port}'
        
        try:
            self.rpc = Proxy(service_url=service_url)
            logging.debug(f"Initialized RPC Proxy with URL: {service_url}")
        except Exception as e:
            logging.error(f"Failed to initialize RPC Proxy: {e}")
            raise e

        self._min_transaction_fee = 10000  # Satoshi per kB
        self._min_dust = 600  # Satoshi

        logging.debug(f"Initialized BitcoinDaemonService with wallet '{self.wallet_filename}' on {self.host}:{self.port}.")

    def push_tx(self, raw_tx):
        """
        Broadcast a raw transaction.

        Args:
            raw_tx (str): Raw transaction in hexadecimal format.

        Returns:
            str: Transaction ID.
        """
        try:
            txid = self.rpc.sendrawtransaction(raw_tx)
            logging.debug(f"Broadcasted transaction {txid}.")
            return txid
        except Exception as e:
            logging.error(f"Error broadcasting transaction: {e}")
            raise e

    def get_transaction(self, txid, raw=False):
        """
        Get transaction details.

        Args:
            txid (str): Transaction ID.
            raw (bool): If True, return raw transaction hex.

        Returns:
            dict or str: Transaction details or raw transaction.
        """
        try:
            tx = self.rpc.getrawtransaction(txid, 1)
            if raw:
                raw_tx = self.rpc.getrawtransaction(txid, 0)
                logging.debug(f"Retrieved raw transaction {txid}: {raw_tx}")
                return raw_tx
            logging.debug(f"Retrieved transaction details for {txid}: {tx}")
            return tx
        except Exception as e:
            logging.error(f"Error retrieving transaction {txid}: {e}")
            raise e

    def list_transactions(self, account, max_transactions=100):
        """
        List recent transactions for an account.

        Args:
            account (str): Account name.
            max_transactions (int): Maximum number of transactions to retrieve.

        Returns:
            list: List of transactions.
        """
        try:
            transactions = self.rpc.listtransactions(account, max_transactions)
            logging.debug(f"Retrieved {len(transactions)} transactions for account '{account}'.")
            return transactions
        except Exception as e:
            logging.error(f"Error listing transactions for account '{account}': {e}")
            raise e

    def list_received_by_address(self, minconf=1, include_empty=False):
        """
        List received transactions by address.

        Args:
            minconf (int): Minimum confirmations.
            include_empty (bool): Include addresses with zero received.

        Returns:
            list: List of received transactions.
        """
        try:
            received = self.rpc.listreceivedbyaddress(minconf, include_empty, False)
            logging.debug(f"Retrieved {len(received)} received transactions.")
            return received
        except Exception as e:
            logging.error(f"Error listing received transactions: {e}")
            raise e

    def list_unspents(self, address, min_confirmations=6):
        """
        List unspent transaction outputs (UTXOs) for an address.

        Args:
            address (str): Bitcoin address.
            min_confirmations (int): Minimum confirmations.

        Returns:
            list: List of unspent outputs.
        """
        try:
            unspents = self.rpc.listunspent(min_confirmations, 9999999, [address])
            logging.debug(f"Retrieved {len(unspents)} unspent outputs for address '{address}'.")
            return unspents
        except Exception as e:
            logging.error(f"Error listing unspents for address '{address}': {e}")
            raise e

    def import_address(self, address, account, rescan=False):
        """
        Import an address into the wallet.

        Args:
            address (str): Bitcoin address.
            account (str): Account name.
            rescan (bool): Whether to rescan the blockchain.
        """
        try:
            self.rpc.importaddress(address, account, rescan)
            logging.debug(f"Imported address '{address}' with account '{account}' and rescan={rescan}.")
        except Exception as e:
            logging.error(f"Error importing address '{address}': {e}")
            raise e

    def decode(self, raw_tx):
        """
        Decode a raw transaction.

        Args:
            raw_tx (str): Raw transaction in hexadecimal format.

        Returns:
            dict: Decoded transaction.
        """
        try:
            decoded = self.rpc.decoderawtransaction(raw_tx)
            logging.debug(f"Decoded transaction: {decoded}")
            return decoded
        except Exception as e:
            logging.error(f"Error decoding transaction {raw_tx}: {e}")
            raise e

    def get_block_raw(self, block):
        """
        Get raw block data.

        Args:
            block (str or int): Block hash or number.

        Returns:
            str: Raw block data in hexadecimal format.
        """
        try:
            if isinstance(block, int):
                block_hash = self.rpc.getblockhash(block)
                logging.debug(f"Retrieved block hash for block number {block}: {block_hash}")
            else:
                block_hash = block
            raw_block = self.rpc.getblock(block_hash, 0)
            logging.debug(f"Retrieved raw block data for block '{block_hash}'.")
            return raw_block
        except Exception as e:
            logging.error(f"Error retrieving raw block data for block '{block}': {e}")
            raise e

    def get_block_info(self, block):
        """
        Get block information.

        Args:
            block (str or int): Block hash or number.

        Returns:
            dict: Block information.
        """
        try:
            if isinstance(block, int):
                block_hash = self.rpc.getblockhash(block)
                logging.debug(f"Retrieved block hash for block number {block}: {block_hash}")
            else:
                block_hash = block
            block_info = self.rpc.getblock(block_hash, 2)
            logging.debug(f"Retrieved block info for block '{block_hash}': {block_info}")
            return block_info
        except Exception as e:
            logging.error(f"Error retrieving block info for block '{block}': {e}")
            raise e
