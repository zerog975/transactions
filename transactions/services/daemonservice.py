import json
import requests
from transactions.services.service import BitcoinService
from transactions.utils import bitcoin_to_satoshi

#class BitcoinDaemonService(BitcoinService):
#    def __init__(self, username, password, host, port, wallet_filename=None):
#        super(BitcoinDaemonService, self).__init__()
#        self._username = username
#        self._password = password
#        self._host = host
#        self._port = port
#        self.wallet_filename = wallet_filename
#
#    def make_request(self, method, params=None):
#        if params is None:
#            params = []
#        
        # Include wallet path if provided
#        if self.wallet_filename:
#            url = f"http://{self._username}:{self._password}@{self._host}:{self._port}/wallet/{self.wallet_filename}"
#        else:
#            url = f"http://{self._username}:{self._password}@{self._host}:{self._port}"
#
#        try:
#            data = json.dumps({"jsonrpc": "1.0", "params": params, "id": "", "method": method})
#            r = requests.post(url, data=data, headers={'Content-type': 'application/json'}, verify=False)
#            r.raise_for_status()  # Raise an exception if the request was not successful
#            response = r.json()
#            if isinstance(response, dict) and response.get('error'):
#                raise Exception(response['error'])
#            return response
#        except ValueError as e:
#            print("Some parameters were wrong, please check the request")
#            raise e
#        except requests.exceptions.RequestException as e:
#            print("Bitcoin service cannot be accessed. Check username, password, or host")
#            raise e

### Small updates

#    def push_tx(self, tx):
#        """
#        :param tx: signed transaction hash
#        :return: if successful, returns info on the transaction; otherwise, raises an exception
#        """
#        response = self.make_request("sendrawtransaction", [tx, True])
#        error = response.get('error')
#        if error is not None:
#            raise Exception(error)

#        return response

#    def import_address(self, address, label, rescan=True):
#        """
#        Imports an address to the Bitcoin node.
#        :param address: address to import
#        :param label: account name to use
#        :param rescan: whether to rescan the blockchain for the address's transactions
#        """
#        response = self.make_request("importaddress", [address, label, rescan])
#        error = response.get('error')
#        if error is not None:
#            raise Exception(error)
#        return response

#    def list_transactions(self, address, max_transactions=200):
#        response = self.make_request("listtransactions", ["*", max_transactions, 0, True])
#        if not isinstance(response, dict):
#            raise Exception("Unexpected response format, expected a dictionary")
        
#        error = response.get('error')
#        if error is not None:
#            raise Exception(error)

#        results = response.get('result', [])
#        results = [tx for tx in results if tx['address'] == address]

#        out = []
#        for tx in results:
#            out.append({
#                'txid': tx['txid'],
#                'amount': bitcoin_to_satoshi(tx['amount']),
#                'confirmations': tx['confirmations'],
#                'time': tx['time']
#            })
#       return out

#    def list_unspents(self, address, min_confirmations):
#        response = self.make_request('listunspent', [min_confirmations, 9999999, [address]])
#        if not isinstance(response, dict):
#            raise Exception("Unexpected response format, expected a dictionary")
        
#        error = response.get('error')
#        if error is not None:
#            raise Exception(error)

#        results = response.get('result', [])
#        out = []
#        for unspent in results:
#            out.append({
#                'txid': unspent['txid'],
#                'vout': unspent['vout'],
#                'amount': bitcoin_to_satoshi(unspent['amount']),
#                'confirmations': unspent['confirmations']
#            })
#        return out

#    def get_transaction(self, txid):
#        response = self.make_request('gettransaction', [txid])
#        if not isinstance(response, dict):
#            raise Exception("Unexpected response format, expected a dictionary")
        
#        error = response.get('error')
#        if error is not None:
#            raise Exception(error)
#        return response.get('result')

#### Small updates
class BitcoinDaemonService(BitcoinService):
    def __init__(self, username, password, host, port, wallet_filename=None):
        super(BitcoinDaemonService, self).__init__()
        self._username = username
        self._password = password
        self._host = host
        self._port = port
        self.wallet_filename = wallet_filename

    def _handle_response(self, response):
        """ Helper method to handle common response checks """
        if not isinstance(response, dict):
            raise Exception("Unexpected response format, expected a dictionary")
        
        error = response.get('error')
        if error is not None:
            raise Exception(error)
        
        return response.get('result', response)

    def push_tx(self, tx):
        """
        :param tx: signed transaction hash
        :return: if successful, returns info on the transaction; otherwise, raises an exception
        """
        response = self.make_request("sendrawtransaction", [tx, True])
        return self._handle_response(response)

    def import_address(self, address, label, rescan=True):
        """
        Imports an address to the Bitcoin node.
        :param address: address to import
        :param label: account name to use
        :param rescan: whether to rescan the blockchain for the address's transactions
        """
        response = self.make_request("importaddress", [address, label, rescan])
        return self._handle_response(response)

    def list_transactions(self, address, max_transactions=200):
        """
        Lists transactions involving a specific address.
        :param address: Bitcoin address to filter transactions by.
        :param max_transactions: Maximum number of transactions to retrieve.
        :return: A list of transactions involving the specified address.
        """
        response = self.make_request("listtransactions", ["*", max_transactions, 0, True])
        results = self._handle_response(response)

        # Filter transactions by address
        filtered_transactions = [
            {
                'txid': tx['txid'],
                'amount': bitcoin_to_satoshi(tx['amount']),
                'confirmations': tx['confirmations'],
                'time': tx['time']
            }
            for tx in results if tx.get('address') == address
        ]
        return filtered_transactions

    def list_unspents(self, address, min_confirmations):
        """
        Lists unspent transaction outputs (UTXOs) for a specific address.
        :param address: Bitcoin address to filter UTXOs by.
        :param min_confirmations: Minimum number of confirmations required.
        :return: A list of UTXOs involving the specified address.
        """
        response = self.make_request('listunspent', [min_confirmations, 9999999, [address]])
        results = self._handle_response(response)

        unspents = [
            {
                'txid': unspent['txid'],
                'vout': unspent['vout'],
                'amount': bitcoin_to_satoshi(unspent['amount']),
                'confirmations': unspent['confirmations']
            }
            for unspent in results
        ]
        return unspents

    def get_transaction(self, txid):
        """
        Retrieves detailed information about a specific transaction.
        :param txid: The transaction ID to retrieve information for.
        :return: The transaction details.
        """
        response = self.make_request('gettransaction', [txid])
        return self._handle_response(response)


