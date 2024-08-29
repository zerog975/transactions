import bitcoin
from bitcoin.core import CMutableTransaction, CMutableTxOut, CMutableTxIn, COutPoint, CScript, OP_RETURN, lx
from bitcoin.wallet import CBitcoinSecret, CBitcoinAddress
from transactions.services.daemonservice import BitcoinDaemonService
from transactions.services.blockrservice import BitcoinBlockrService


SERVICES = ['daemon', 'blockr']

class Transactions:
    """
    Transactions: Bitcoin for Humans
    All amounts are in satoshi.
    """

    # Transaction fee per 1k bytes
    _min_tx_fee = 10000
    # dust
    _dust = 600

    def __init__(self, service='daemon', testnet=False, username='', password='', host='', port='', wallet_filename=None):
        if service not in SERVICES:
            raise Exception(f"Service '{service}' not supported")
        
        if service == 'daemon':
            self._service = BitcoinDaemonService(username, password, host, port, wallet_filename=wallet_filename)
        elif service == 'blockr':
            self._service = BitcoinBlockrService(testnet)
        
        self._min_tx_fee = self._service._min_transaction_fee
        self._dust = self._service._min_dust

    def push(self, tx):
        self._service.push_tx(tx)
        return tx.GetHash()

    def get(self, hash, max_transactions=100, min_confirmations=6):
        # hash can be an address or txid of a transaction
        if len(hash) < 64:
            txs = self._service.list_transactions(hash, max_transactions=max_transactions)
            unspents = self._service.list_unspents(hash, min_confirmations=min_confirmations)
            return {'transactions': txs, 'unspents': unspents}
        else:
            return self._service.get_transaction(hash)

    def _import_address(self, address, label="", rescan=False):
        if self._service.name == 'BitcoinDaemonService':
            self._service.import_address(address, label, rescan=rescan)

    def simple_transaction(self, from_address, to, op_return=None, min_confirmations=6):
        # amount in satoshi
        # to is a tuple of (to_address, amount)
        # or a list of tuples [(to_addr1, amount1), (to_addr2, amount2)]

        to = [to] if not isinstance(to, list) else to
        amount = sum([amount for addr, amount in to])
        n_outputs = len(to) + 1  # change
        if op_return:
            n_outputs += 1

        # select inputs
        inputs, change = self._select_inputs(from_address, amount, n_outputs, min_confirmations=min_confirmations)
        outputs = [{'address': to_address, 'value': amount} for to_address, amount in to]
        outputs += [{'address': from_address, 'value': change}]

        # add op_return
        if op_return:
            # Create OP_RETURN script using python-bitcoinlib
            op_return_script = CScript([OP_RETURN, op_return.encode('utf-8')])
            outputs.append({'script': op_return_script, 'value': 0})
        
        tx = self.build_transaction(inputs, outputs)
        return tx

    def build_transaction(self, inputs, outputs):
        # Build transaction using python-bitcoinlib
        txins = []

        # Assuming inputs is a list of dictionaries with keys 'txid' and 'vout'
        for input in inputs:
            prevout = COutPoint(lx(input['txid']), input['vout'])
            txins.append(CMutableTxIn(prevout))

        txouts = []
        for output in outputs:
            if 'script' in output:
                txouts.append(CMutableTxOut(output['value'], CScript(output['script'])))
            else:
                txouts.append(CMutableTxOut(output['value'], CBitcoinAddress(output['address']).to_scriptPubKey()))

        tx = CMutableTransaction(txins, txouts)
        return tx

    def sign_transaction(self, tx, master_password, path=''):
        secret = CBitcoinSecret(master_password)
        for i, txin in enumerate(tx.vin):
            txin.scriptSig = secret.sign(tx, i)
        return tx

    def _select_inputs(self, address, amount, n_outputs=2, min_confirmations=6):
        # selects the inputs to fulfill the amount
        # returns a list of inputs and the change
        unspents = self.get(address, min_confirmations=min_confirmations)['unspents']
        if not unspents:
            raise Exception("No spendable outputs found")

        unspents = sorted(unspents, key=lambda d: d['amount'])
        balance = 0
        inputs = []
        fee = self._service._min_transaction_fee
        try:
            # get coins to fulfill the amount
            while balance < amount + fee:
                unspent = unspents.pop()
                balance += unspent['amount']
                inputs.append({'txid': unspent['txid'], 'vout': unspent['vout'], 'amount': unspent['amount']})
                # update estimated fee
                fee = self.estimate_fee(len(inputs), n_outputs)
        except IndexError:
            raise Exception("Not enough balance in the wallet")

        change = balance - amount - fee
        change = change if change > self._dust else 0

        return inputs, change

    def estimate_fee(self, n_inputs, n_outputs):
        # estimates transaction fee based on number of inputs and outputs
        estimated_size = 10 + 148 * n_inputs + 34 * n_outputs
        return ((estimated_size // 1000) + 1) * self._min_tx_fee
