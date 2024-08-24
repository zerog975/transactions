"""
Bitcoin Daemon Service
"""
import json
import requests

from transactions.services.service import BitcoinService
from transactions.utils import bitcoin_to_satoshi

#from transactions.services.service import BitcoinService
#from transactions.utils import bitcoin_to_satoshi

#class BitcoinDaemonService(BitcoinService):
#    def __init__(self, username, password, host, port, wallet_filename=None):
#        super(BitcoinDaemonService, self).__init__()
#        self._username = username
#        self._password = password
#        self._host = host
#        self._port = port
#        self.wallet_filename = wallet_filename

#    @property
#    def _url(self):
#        return 'https://%s:%s@%s:%s' % (self._username, self._password,
#                                        self._host, self._port)

#    def make_request(self, method, params=None):
#        if params is None:
#            params = []
###     #Include wallet path if provided
#        if self.wallet_filename:
#            url = f"http://{self._username}:{self._password}@{self._host}:{self._port}/wallet/{self.wallet_filename}"
#        else:
#            url = f"http://{self._username}:{self._password}@{self._host}:{self._port}"    
####
#        try:
#            data = json.dumps({"jsonrpc": "1.0", "params": params, "id": "", "method": method})
#            r = requests.post(self._url, data=data, headers={'Content-type': 'application/json'}, verify=False)
#            return json.loads(r.content)
#        except ValueError as e:
#            print "Some parameters were wrong, please check the request"
#            raise e
#        except requests.exceptions.RequestException as e:
#            print "Bitcoin service can not be accessed. Check username, password or host"
#            raise e


### Updated to pass wallet in the path
class BitcoinDaemonService(BitcoinService):
    def __init__(self, username, password, host, port, wallet_filename=None):
        super(BitcoinDaemonService, self).__init__()
        self._username = username
        self._password = password
        self._host = host
        self._port = port
        self.wallet_filename = wallet_filename

    def make_request(self, method, params=None):
        if params is None:
            params = []
        
        # Include wallet path if provided
        if self.wallet_filename:
            url = f"http://{self._username}:{self._password}@{self._host}:{self._port}/wallet/{self.wallet_filename}"
        else:
            url = f"http://{self._username}:{self._password}@{self._host}:{self._port}"

        try:
            data = json.dumps({"jsonrpc": "1.0", "params": params, "id": "", "method": method})
            r = requests.post(url, data=data, headers={'Content-type': 'application/json'}, verify=False)
            r.raise_for_status()  # Raise an exception if the request was not successful
            response = r.json()
            if response.get('error'):
                raise Exception(response['error'])
            return response['result']
        except ValueError as e:
            print("Some parameters were wrong, please check the request")
            raise e
        except requests.exceptions.RequestException as e:
            print("Bitcoin service cannot be accessed. Check username, password, or host")
            raise e





    def push_tx(self, tx):
        """

        :param tx = signed tx hash:
        :return: if successful info on tx, else error tx wasn't pushed
        """
        response = self.make_request("sendrawtransaction", [tx, True])
        error = response.get('error')
        if error is not None:
            raise Exception(error)

        return response

    def import_address(self, address, label, rescan=False):
        """
        param address = address to import
        param label= account name to use
        """
        response = self.make_request("importaddress", [address, label, rescan])
        error = response.get('error')
        if error is not None:
            raise Exception(error)
        return response

    def list_transactions(self, address, max_transactions=200):
        response = self.make_request("listtransactions", ["*", max_transactions, 0, True])
        error = response.get('error')
        if error is not None:
            raise Exception(error)

        results = response.get('result', [])
        results = [tx for tx in results if tx['address'] == address]

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

    def get_transaction(self, txid):
        response = self.make_request('gettransaction', [txid])
        error = response.get('error')
        if error is not None:
            raise Exception(error)
        return response.get('result')
