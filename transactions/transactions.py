# -*- coding: utf-8 -*-

from __future__ import annotations

import codecs
from typing import Union, List, Dict, Any

from bit import PrivateKey, PrivateKeyTestnet
from bit.network import NetworkAPI
from bit.transaction import calc_txid
from pycoin.key.BIP32Node import BIP32Node
from pycoin.encoding import EncodingError

from .services.daemonservice import BitcoinDaemonService, RegtestDaemonService
from .services.blockrservice import BitcoinBlockrService


SERVICES = ['daemon', 'blockr', 'regtest']


class Transactions:
    """
    Transactions: Bitcoin for Humans

    All amounts are in satoshi
    """

    def __init__(self, service: str = 'daemon', testnet: bool = True, username: str = '', password: str = '', host: str = '', port: str = '', wallet_filename: str = ''):
        """
        Args:
            service: currently supports _blockr_ for blockr.io and and _daemon_ for bitcoin daemon. Defaults to _blockr_
            testnet: use True if you want to use testnet. Defaults to False
            username: username to connect to the bitcoin daemon
            password: password to connect to the bitcoin daemon
            host: host of the bitcoin daemon
            port: port of the bitcoin daemon
            wallet_filename: the name of the wallet to use with the bitcoin daemon
        """
        self.testnet = testnet

        if service not in SERVICES:
            raise ValueError(f"Service '{service}' not supported")
        
        if service == 'daemon':
            self._service = BitcoinDaemonService(username, password, host, port, testnet, wallet_filename)
        elif service == 'blockr':
            self._service = BitcoinBlockrService(testnet)
        elif service == 'regtest':
            self.testnet = True
            self._service = RegtestDaemonService(username, password, host, port, testnet, wallet_filename)

        self._min_tx_fee = self._service._min_transaction_fee
        self._dust = self._service._min_dust

    def push(self, tx: str) -> str:
        """
        Args:
            tx: hex of signed transaction
        Returns:
            pushed transaction
        """
        self._service.push_tx(tx)
        return calc_txid(tx)

    def get(self, address: str, account: str = "*", max_transactions: int = 100, min_confirmations: int = 6, raw: bool = False) -> Dict[str, Any]:
        """
        Args:
            address: bitcoin address or a transaction id. If it's a
                bitcoin address it will return a list of transactions up to
                ``max_transactions`` a list of unspents with confirmed
                transactions greater or equal to ``min_confirmations``
            account: used when using the bitcoind. bitcoind
                does not provide an easy way to retrieve transactions for a
                single address. By using account we can retrieve transactions
                for addresses in a specific account
        Returns:
            transaction
        """
        if len(address) < 64:
            txs = self._service.list_transactions(address, account=account, max_transactions=max_transactions)
            unspents = self._service.list_unspents(address, min_confirmations=min_confirmations)
            return {'transactions': txs, 'unspents': unspents}
        else:
            return self._service.get_transaction(address, raw=raw)

    def import_address(self, address: str, account: str = "", rescan: bool = False):
        if self._service.name.startswith('BitcoinDaemonService') or \
                self._service.name.startswith('RegtestDaemonService'):
            self._service.import_address(address, account, rescan=rescan)

    def simple_transaction(self, from_address: str, to: Union[tuple, List[tuple]], op_return: str = None, min_confirmations: int = 6) -> str:
        """
        Args:
            from_address: bitcoin address originating the transaction
            to: tuple of ``(to_address, amount)`` or list of tuples ``[(to_addr1, amount1), (to_addr2, amount2)]``. Amounts are in *satoshi*
            op_return: ability to set custom ``op_return``
            min_confirmations: minimal number of required confirmations

        Returns:
            transaction
        """
        to = [to] if not isinstance(to, list) else to
        amount = sum(amount for _, amount in to)
        n_outputs = len(to) + 1  # change
        if op_return:
            n_outputs += 1

        # select inputs
        inputs, change = self._select_inputs(from_address, amount, n_outputs, min_confirmations=min_confirmations)
        outputs = [(to_address, amount, 'satoshi') for to_address, amount in to]
        if change > 0:
            outputs.append((from_address, change, 'satoshi'))

        # add op_return
        if op_return:
            outputs.append((op_return, 0, 'satoshi'))

        key = PrivateKeyTestnet(from_address) if self.testnet else PrivateKey(from_address)
        tx = key.create_transaction(outputs, fee=self._min_tx_fee, absolute_fee=True, combine=False, unspents=inputs)
        return tx

    def sign_transaction(self, tx: str, master_password: str, path: str = '') -> str:
        """
        Args:
            tx: hex transaction to sign
            master_password: master password for BIP32 wallets. Can be either a
                master_secret or a wif
            path: optional path to the leaf address of the
                BIP32 wallet. This allows us to retrieve private key for the
                leaf address if one was used to construct the transaction.
        Returns:
            signed transaction

        .. note:: Only BIP32 hierarchical deterministic wallets are currently
            supported.
        """
        netcode = 'XTN' if self.testnet else 'BTC'

        try:
            key = BIP32Node.from_text(master_password)
        except (AttributeError, EncodingError):
            # if it's not get the wif from the master secret
            key = BIP32Node.from_master_secret(master_password.encode(), netcode=netcode).subkey_for_path(path)
        
        private_key = PrivateKeyTestnet(key.wif()) if self.testnet else PrivateKey(key.wif())
        return private_key.sign_transaction(tx)

    def _select_inputs(self, address: str, amount: int, n_outputs: int = 2, min_confirmations: int = 6) -> tuple:
        # selects the inputs to fulfill the amount
        # returns a list of inputs and the change
        unspents = self.get(address, min_confirmations=min_confirmations)['unspents']
        if not unspents:
            raise ValueError("No spendable outputs found")

        unspents = sorted(unspents, key=lambda d: d['amount'])
        balance = 0
        inputs = []
        fee = self._service._min_transaction_fee
        try:
            # get coins to fulfill the amount
            while balance < amount + fee:
                unspent = unspents.pop()
                balance += unspent['amount']
                inputs.append(unspent)
                # update estimated fee
                fee = self.estimate_fee(len(inputs), n_outputs)
        except IndexError:
            raise ValueError("Not enough balance in the wallet")

        change = balance - amount - fee
        change = change if change > self._dust else 0

        return inputs, change

    def _op_return_hex(self, op_return: str) -> str:
        hex_op_return = codecs.encode(op_return.encode('utf-8'), 'hex')
        return f"6a{len(op_return):x}{hex_op_return.decode('utf-8')}"

    def estimate_fee(self, n_inputs: int, n_outputs: int) -> int:
        # estimates transaction fee based on number of inputs and outputs
        estimated_size = 10 + 148 * n_inputs + 34 * n_outputs
        return (estimated_size // 1000 + 1) * self._min_tx_fee

    def decode(self, tx: str) -> Dict[str, Any]:
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

    def get_block_raw(self, block: Union[str, int]) -> Dict[str, Any]:
        """
        Args:
            block: block hash (eg: 0000000000000000210b10d620600dc1cc2380bb58eb2408f9767eb792ed31fa)
                block number (eg: 223212) - only for blockr
                word "last" - this will always return the latest block - only
                    for blockr
                word "first" - this will always return the first block - only
                    for blockr
        Returns:
            raw block data
        """
        return self._service.get_block_raw(block)

    def get_block_info(self, block: Union[str, int]) -> Dict[str, Any]:
        """
        Args:
            block: block hash (eg: 0000000000000000210b10d620600dc1cc2380bb58eb2408f9767eb792ed31fa)
                block number (eg: 223212) - only for blockr
                word "last" - this will always return the latest block - only
                    for blockr
                word "first" - this will always return the first block - only
                    for blockr
        Returns:
            basic block data
        """
        return self._service.get_block_info(block)

    # To simplify a bit the method names
    create = simple_transaction
    sign = sign_transaction
