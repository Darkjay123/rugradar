// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// Placed (by eth_call state override) at a real holder's address, so the token sees that holder as the sender.
// Read-only simulation: nothing is signed or sent.
contract SellProbe {
    function _bal(address t, address a) internal view returns (bool ok, uint256 v) {
        (bool s, bytes memory r) = t.staticcall(abi.encodeWithSelector(0x70a08231, a));
        if (s && r.length >= 32) return (true, abi.decode(r, (uint256)));
        return (false, 0);
    }
    fallback(bytes calldata d) external returns (bytes memory) {
        (address token, address to, uint256 bps) = abi.decode(d, (address, address, uint256));
        (, uint256 mine) = _bal(token, address(this));
        uint256 amt = mine * bps / 10000;
        (, uint256 b0) = _bal(token, to);
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amt));
        uint256 used = g - gasleft();
        bool success = ok && (ret.length == 0 || (ret.length >= 32 && abi.decode(ret, (bool))));
        (, uint256 b1) = _bal(token, to);
        (, uint256 mine1) = _bal(token, address(this));
        return abi.encode(success, mine, amt, b1 > b0 ? b1 - b0 : 0, mine > mine1 ? mine - mine1 : 0, used);
    }
}
