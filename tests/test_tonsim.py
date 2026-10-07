from rugradar import tonsim as t

OWN, JW, POOL = "0:" + "12" * 32, "0:" + "ab" * 32, "0:" + "77" * 32


def test_cells_hash_like_the_ton_reference():
    # golden hash computed once with pytoniq-core for the same v4r2 message
    msg = t.internal_msg(JW, 300_000_000, t.jetton_transfer_body(5, POOL, OWN))
    ext = t.wallet_external("wallet_v4r2", OWN, 698983191, 1, msg, 1700000000)
    assert ext.boc()[:4] == bytes.fromhex("b5ee9c72")
    assert ext.hash().hex() == "bb78a080d6e289d9e560318abbb3be56510db9de79bae671d613a573b9d5008b"


def test_friendly_address_to_raw():
    assert t.raw_address("EQAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM__NOT") == \
        "0:2f956143c461769579baef2e32cc2d7bc18283f40d20bb03e432cd603ac33ffc"
    assert t.raw_address("not an address") is None


def _tx(acct, ok=True, code=0):
    return {"transaction": {"account": {"address": acct}, "success": ok, "aborted": not ok, "compute_phase": {"exit_code": code}}}


def test_classify():
    ok = {**_tx(OWN), "children": [{**_tx(JW), "children": [_tx("0:" + "99" * 32)]}]}
    assert t.classify(ok, OWN, JW)[0] == "ok"
    refused = {**_tx(OWN), "children": [_tx(JW, False, 401)]}
    assert t.classify(refused, OWN, JW) == ("blocked", 401)
    gas = {**_tx(OWN), "children": [_tx(JW, False, -14)]}
    assert t.classify(gas, OWN, JW)[0] == "inconclusive"
    bad_wallet = _tx(OWN, False, 33)  # our seqno was stale: says nothing about the token
    assert t.classify(bad_wallet, OWN, JW)[0] == "inconclusive"
    swallowed = {**_tx(OWN), "children": [_tx(JW)]}
    assert t.classify(swallowed, OWN, JW)[0] == "blocked"
