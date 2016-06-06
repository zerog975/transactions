# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import pytest


def test_bitcoin_service_attributes():
    from transactions.services.service import BitcoinService
    assert BitcoinService._min_dust == 3000
    assert BitcoinService.maxTransactionFee == 50000
    assert BitcoinService._min_transaction_fee == 30000


def test_bitcoin_service_default_init():
    from transactions.services.service import BitcoinService
    bitcoin_service = BitcoinService()
    assert bitcoin_service.testnet is False
    assert bitcoin_service.name == BitcoinService.__name__


def test_bitcoin_service_init_testnet():
    from transactions.services.service import BitcoinService
    bitcoin_service = BitcoinService(testnet=True)
    assert bitcoin_service.testnet is True
    assert bitcoin_service.name == BitcoinService.__name__ + 'Testnet'


def test_make_request(bitcoin_daemon_service):
    response = bitcoin_daemon_service.make_request('getinfo')
    assert 'id' in response
    assert 'error' in response
    assert 'result' in response


def test_getinfo(bitcoin_daemon_service):
    response = bitcoin_daemon_service.getinfo()
    assert 'id' in response
    assert 'error' in response
    assert 'result' in response


def test_getbalance(bitcoin_daemon_service):
    response = bitcoin_daemon_service.getbalance()
    assert 'id' in response
    assert 'error' in response
    assert 'result' in response


def test_generate(bitcoin_daemon_service):
    response = bitcoin_daemon_service.generate(1)
    assert 'id' in response
    assert 'error' in response
    assert 'result' in response


def test_get_new_address(bitcoin_daemon_service):
    response = bitcoin_daemon_service.get_new_address()
    assert 'id' in response
    assert 'error' in response
    assert 'result' in response


@pytest.mark.usefixtures('init_blockchain')
def test_send_to_address(bitcoin_daemon_service, rpcconn):
    addr = rpcconn.getnewaddress()
    response = bitcoin_daemon_service.send_to_address(addr, 1)
    assert 'id' in response
    assert 'error' in response
    assert 'result' in response
    txid = response['result']
    raw_tx = rpcconn.getrawtransaction(txid)
    decoded_raw_tx = rpcconn.decoderawtransaction(raw_tx)
    assert decoded_raw_tx['txid'] == txid


def test_push_tx_with_invalid_value(bitcoin_daemon_service):
    with pytest.raises(Exception) as exc:
        bitcoin_daemon_service.push_tx('dummy-tx')
    assert exc.value.message['message'] == 'TX decode failed'
    assert exc.value.message['code'] == -22


def test_import_address_with_invalid_value(bitcoin_daemon_service):
    with pytest.raises(Exception) as exc:
        bitcoin_daemon_service.import_address('dummy-addr')
    assert exc.value.message['message'] == 'Invalid Bitcoin address or script'
    assert exc.value.message['code'] == -5


def test_list_transactions_for_invalid_account(bitcoin_daemon_service):
    with pytest.raises(Exception) as exc:
        bitcoin_daemon_service.list_transactions('dummy-addr', account=3)
    err = exc.value.message
    assert err['message'] == 'JSON value is not a string as expected'
    assert err['code'] == -1


def test_list_unspents_for_invalid_address(bitcoin_daemon_service):
    with pytest.raises(Exception) as exc:
        bitcoin_daemon_service.list_unspents('dummy-addr', 1)
    err = exc.value.message
    assert err['message'] == 'Invalid Bitcoin address: dummy-addr'
    assert err['code'] == -5


def test_get_raw_transaction_invalid_tx(bitcoin_daemon_service):
    with pytest.raises(Exception) as exc:
        bitcoin_daemon_service.get_raw_transaction('a')
    err = exc.value.message
    assert err['message'] == "parameter 1 must be hexadecimal string (not 'a')"
    assert err['code'] == -8


@pytest.mark.usefixtures('init_blockchain')
def test_get_transaction(bitcoin_daemon_service, rpcconn):
    addr = rpcconn.getnewaddress()
    txid = rpcconn.sendtoaddress(addr, 1)
    rpcconn.generate(1)
    tx = bitcoin_daemon_service.get_transaction(txid)
    assert tx
    assert 'vouts' in tx
    assert 'vins' in tx
    assert 'confirmations' in tx
    assert 'time' in tx
    assert 'txid' in tx
    assert tx['txid'] == txid
    assert tx['confirmations'] == 1
    assert tx['time']
    assert any(vout['address'] == addr and vout['value'] == 100000000
               for vout in tx['vouts'])


def test_get_address_for_vout_for_invalid_tx(bitcoin_daemon_service):
    with pytest.raises(Exception) as exc:
        bitcoin_daemon_service._get_address_for_vout('a', 0)
    err = exc.value.message
    assert err['message'] == "parameter 1 must be hexadecimal string (not 'a')"
    assert err['code'] == -8


def test_get_address_for_vout_for_unknown_tx(bitcoin_daemon_service, rpcconn):
    txid = '0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD'
    assert bitcoin_daemon_service._get_address_for_vout(txid, 0) == ''


def test_get_value_from_vout_for_invalid_tx(bitcoin_daemon_service):
    with pytest.raises(Exception) as exc:
        bitcoin_daemon_service._get_value_from_vout('a', 0)
    err = exc.value.message
    assert err['message'] == "parameter 1 must be hexadecimal string (not 'a')"
    assert err['code'] == -8


def test_get_value_from_vout_for_unknown_tx(bitcoin_daemon_service, rpcconn):
    txid = '0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefABCD'
    assert bitcoin_daemon_service._get_value_from_vout(txid, 0) == 0
