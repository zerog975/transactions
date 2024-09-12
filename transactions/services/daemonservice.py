# -*- coding: utf-8 -*-
"""
Bitcoin Daemon Service

"""
from __future__ import absolute_import, division, unicode_literals

import json
import requests
import logging
import os
from .service import BitcoinService
from transactions.utils import bitcoin_to_satoshi

# Configure logging
logging.basicConfig(level=logging.DEBUG)


class BitcoinDaemonService:
    def __init__(self, username=None, password=None, host=None, port=None, testnet=False, wallet_filename=None):
        """
        Initialize the BitcoinDaemonService with the given parameters.
        If any parameters are not provided, they are fetched from environment variables.
        
        Args:
            username (str): Bitcoin RPC username.
            password (str): Bitcoin RPC password.
            host (str): Bitcoin node host.
            port (int): Bitcoin RPC port.
            testnet (bool): Whether to use the testnet or mainnet.
            wallet_filename (str): Bitcoin wallet filename.
        """
        
        # If arguments are provided, they take priority; otherwise, fall back to environment variables
        self._username = username or os.getenv('BITCOIN_RPCUSER')
        self._password = password or os.getenv('BITCOIN_RPCPASSWORD')
        self._host = host or os.getenv('BITCOIN_HOST')
        self._port = port or int(os.getenv('BITCOIN_PORT'))
        self.wallet_filename = wallet_filename or os.getenv('WALLET_FILENAME')

        # Retrieve the network (mainnet or testnet) from environment variables or arguments
        self.network = 'testnet' if testnet else 'mainnet'
        
        # Define a default minimum transaction fee (in satoshi) or retrieve it dynamically
        ###
        ###   Need to update
        self._min_transaction_fee = 10000  # This is just a placeholder value, adjust as needed
        self._min_dust = 600  # Set this to your desired dust limit (in satoshis)
        
        logging.debug(f"Initializing BitcoinDaemonService with wallet_filename={self.wallet_filename} on network={self.network}")
        
        # Set up session for making requests with retry support
        self._session = requests.Session()
        self._session.mount('http://', requests.adapters.HTTPAdapter(max_retries=3))

    @property
    def _url(self):
        """
        Construct the Bitcoin RPC URL.
        """
        # Use the wallet_filename to create the URL if provided, otherwise use the base URL
        if self.wallet_filename:
            return f'http://{self._username}:{self._password}@{self._host}:{self._port}/wallet/{self.wallet_filename}'
        else:
            return f'http://{self._username}:{self._password}@{self._host}:{self._port}'

    def make_request(self, method, params=None):
        """
        Make a request to the Bitcoin daemon.
        
        Args:
            method (str): The RPC method name.
            params (list): The parameters to pass to the method.
        
        Returns:
            dict: The parsed JSON response from the daemon.
        """
        if params is None:
            params = []
        
        # Prepare the data for the request
        data = {
            "jsonrpc": "1.0",
            "method": method,
            "params": params,
            "id": ""
        }

        logging.debug(f"Making RPC request: {method} with params: {params}")
        try:
            response = self._session.post(
                self._url,
                json=data,
                headers={'Content-type': 'application/json'},
                timeout=30
            )
            
            logging.debug(f"Response status code: {response.status_code}")
            logging.debug(f"Response content: {response.text}")
            
            # Raise an error if the response is not successful
            response.raise_for_status()
            
            return response.json()

        except requests.exceptions.RequestException as e:
            logging.error(f"Error during RPC request: {e}")
            raise

    def get_block_raw(self, block_hash):
        return self.make_request('getblock', (block_hash,))

    def get_block_info(self, block_hash):
        return self.make_request('getblockheader', (block_hash,))

    def getinfo(self):
        return self.make_request('getinfo')

    def generate(self, numblocks):
        """
        As per bitcoin-cli docs:

        Mine blocks immediately (before the RPC call returns)

        .. note:: this function can only be used on the regtest network

        Args:
            numblocks (int): How many blocks are generated immediately.

        Returns:
            blockhashes (List[str]): hashes of blocks generated

        Examples:

            Generate 11 blocks
                >>> generate(11)
        """
        return self.make_request('generate', (numblocks,))

    def getbalance(self):
        return self.make_request('getbalance')

    def get_new_address(self):
        return self.make_request('getnewaddress')

    def send_to_address(self, address, amount):
        return self.make_request('sendtoaddress', params=(address, amount))

    def push_tx(self, tx):
        """
        :param tx: signed tx hash
        :return: if successful, returns info on the transaction; otherwise, raises an exception
        """
        response = self.make_request("sendrawtransaction", [tx, True])
        error = response.get('error')
        if error is not None:
            raise Exception(error)

        return response

    def import_address(self, address, account="*", rescan=False):
        """
        :param address: address to import
        :param account: account name to use
        :param rescan: whether to rescan the blockchain for the address's transactions
        """
        response = self.make_request("importaddress", [address, account, rescan])
        error = response.get('error')
        if error is not None:
            raise Exception(error)
        return response

    def list_transactions(self, address, account="*", max_transactions=200):
        response = self.make_request("listtransactions", [account, max_transactions, 0, True])
        error = response.get('error')
        if error is not None:
            raise Exception(error)

        results = response.get('result', [])
        results = [tx for tx in results if tx.get('address', '') == address and tx.get('category', '') == 'receive']

        out = []
        for tx in results:
            out.append({'txid': tx['txid'],
                        'amount': bitcoin_to_satoshi(tx['amount']),
                        'confirmations': tx['confirmations'],
                        'time': tx['time']})
        return out

    def list_unspents(self, address, min_confirmations):
        response = self.make_request('listunspent', [min_confirmations, 9999999, [address]])
        error = response.get('error')
        if error is not None:
            raise Exception(error)

        results = response.get('result', [])
        out = []
        for unspent in results:
            out.append({'txid': unspent['txid'],
                        'vout': unspent['vout'],
                        'amount': bitcoin_to_satoshi(unspent['amount']),
                        'confirmations': unspent['confirmations']})
        return out

    def get_raw_transaction(self, txid):
        response = self.make_request('getrawtransaction', [txid, 1])
        error = response.get('error')
        if error:
            raise Exception(error)

        raw_transaction = response.get('result')
        return raw_transaction

    def get_transaction(self, txid, raw=False):
        raw_tx = self.get_raw_transaction(txid)
        if raw:
            return raw_tx
        result = self._construct_transaction(raw_tx)
        return result

    def _get_address_for_vout(self, txid, vout_n):
        try:
            raw_tx = self.get_raw_transaction(txid)
            return [vout['scriptPubKey']['addresses'][0] for vout in raw_tx['vout'] if vout['n'] == vout_n][0]
        except Exception as e:
            if e.args and e.args[0] == {'message': 'No information available about transaction', 'code': -5}:
                return ''
            else:
                raise

    def _get_value_from_vout(self, txid, vout_n):
        try:
            raw_tx = self.get_raw_transaction(txid)
            return [vout['value'] for vout in tx['vout'] if vout['n'] == vout_n][0]
        except Exception as e:
            if e.args and e.args[0] == {'message': 'No information available about transaction', 'code': -5}:
                return 0
            else:
                raise

    def _construct_transaction(self, tx):
        result = {}
        result.update({'confirmations': tx.get('confirmations', ''),
                       'time': tx.get('time', ''),
                       'txid': tx.get('txid', ''),
                       'vins': [{'txid': vin['txid'], 'n': vin['vout'], 'value': bitcoin_to_satoshi(self._get_value_from_vout(vin['txid'], vin['vout'])),
                                 'address': self._get_address_for_vout(vin['txid'], vin['vout'])} for vin in tx.get('vin', [])],
                       'vouts': [{'n': vout['n'], 'value': bitcoin_to_satoshi(vout['value']),
                                  'asm': vout['scriptPubKey']['asm'],
                                  'hex': vout['scriptPubKey']['hex'],
                                  'address': vout['scriptPubKey'].get('addresses', ['NONSTANDARD'])[0]} for vout in tx.get('vout', [])]
                       })
        return result
