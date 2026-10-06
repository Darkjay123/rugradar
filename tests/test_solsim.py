from rugradar import solsim

TK = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
T22 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
JUP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


def test_clean_sale_is_ok():
    assert solsim.classify(None, []) == "ok"


def test_frozen_account_blocks():
    logs = [f"Program {JUP} invoke [1]", f"Program {TK} invoke [2]", "Program log: Error: Account is frozen",
            f"Program {TK} failed: custom program error: 0x11", f"Program {JUP} failed: custom program error: 0x11"]
    assert solsim.classify({"InstructionError": [2, {"Custom": 17}]}, logs) == "blocked"


def test_transfer_hook_rejection_blocks():
    hook = "HooK1111111111111111111111111111111111111111"
    logs = [f"Program {JUP} invoke [1]", f"Program {T22} invoke [2]", f"Program {hook} invoke [3]",
            "Program log: sells closed", f"Program {hook} failed: custom program error: 0x1",
            f"Program {T22} failed: custom program error: 0x1", f"Program {JUP} failed: custom program error: 0x1"]
    assert solsim.classify({"InstructionError": [2, {"Custom": 1}]}, logs) == "blocked"


def test_out_of_compute_is_not_the_tokens_fault():
    logs = ["Program BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi failed: exceeded CUs meter at BPF instruction",
            f"Program {JUP} failed: Program failed to complete"]
    assert solsim.classify({"InstructionError": [2, "ProgramFailedToComplete"]}, logs) == "inconclusive"


def test_no_sol_for_fees_and_slippage_are_inconclusive():
    assert solsim.classify("InsufficientFundsForFee", []) == "inconclusive"
    assert solsim.classify({"InstructionError": [3, {"Custom": 6001}]},
                           [f"Program {JUP} failed: custom program error: 0x1771"]) == "inconclusive"


def test_dex_error_alone_is_inconclusive():
    amm = "AMM11111111111111111111111111111111111111111"
    assert solsim.classify({"InstructionError": [2, {"Custom": 3}]},
                           [f"Program {JUP} invoke [1]", f"Program {amm} invoke [2]",
                            f"Program {amm} failed: custom program error: 0x3"]) == "inconclusive"


def test_no_candidates_returns_none():
    assert solsim.sell_test("x", {"sell_candidates": []}) is None
    assert solsim.sell_test("x", None) is None
