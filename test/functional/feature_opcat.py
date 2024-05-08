#!/usr/bin/env python3
# Copyright (c) 2015-2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test (OP_CAT)
"""

from test_framework.blocktools import (
    create_coinbase,
    create_block,
    add_witness_commitment,
)
from test_framework.messages import (
    CTransaction,
    CTxOut,
    CTxIn,
    CTxInWitness,
    COutPoint,
    COIN,
    sha256,
)
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    OP_2,
    OP_CAT,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_FROMALTSTACK,
    OP_OVER,
    OP_SHA256,
    OP_SIZE,
    OP_SWAP,
    OP_TOALTSTACK,
    SIGHASH_DEFAULT,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.script_util import script_to_p2sh_script
from test_framework.key import ECKey, H_POINT, compute_xonly_pubkey, sign_schnorr
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet, MiniWalletMode
from decimal import Decimal
import random
from io import BytesIO
from test_framework.address import output_key_to_p2tr, script_to_p2sh

DISCOURAGED_ERROR = (
    "non-mandatory-script-verify-flag (NOPx reserved for soft-fork upgrades)"
)
STACK_TOO_SHORT_ERROR = (
    "non-mandatory-script-verify-flag (Operation not valid with the current stack size)"
)
DISABLED_OP_CODE = (
    "non-mandatory-script-verify-flag (Attempted to use a disabled opcode)"
)
MAX_PUSH_ERROR = (
    "non-mandatory-script-verify-flag (Push value size limit exceeded)"
)

def random_bytes(n):
    return bytes(random.getrandbits(8) for i in range(n))


def random_p2sh():
    return script_to_p2sh_script(random_bytes(20))


def create_transaction_to_script(node, wallet, txid, script, *, amount_sats):
    """Return signed transaction spending the first output of the
    input txid. Note that the node must be able to sign for the
    output that is being spent, and the node must not be running
    multiple wallets.
    """
    random_address = script_to_p2sh(CScript())
    output = wallet.get_utxo(txid=txid)
    rawtx = node.createrawtransaction(
        inputs=[{"txid": output["txid"], "vout": output["vout"]}],
        outputs={random_address: Decimal(amount_sats) / COIN},
    )
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(rawtx)))
    # Replace with our script
    tx.vout[0].scriptPubKey = script
    # Sign
    wallet.sign_tx(tx)
    return tx


class CatTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [
            ["-par=1"]
        ]  # Use only one script thread to get the exact reject reason for testing
        self.setup_clean_chain = True
        self.rpc_timeout = 120

    def get_block(self, txs):
        self.tip = self.nodes[0].getbestblockhash()
        self.height = self.nodes[0].getblockcount()
        self.log.debug(self.height)
        block = create_block(
            int(self.tip, 16), create_coinbase(self.height + 1))
        block.vtx.extend(txs)
        add_witness_commitment(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        return block.serialize(True).hex(), block.hash

    def add_block(self, txs):
        block, h = self.get_block(txs)
        reason = self.nodes[0].submitblock(block)
        if reason:
            self.log.debug("Reject Reason: [%s]", reason)
        assert_equal(self.nodes[0].getbestblockhash(), h)
        return h

    def test_example_faucat(self):
        """PoW-limited faucet using OP_CAT (idea by ajtowns, see
           https://twitter.com/ajtowns/status/1785842090607591712).

           To spend a fauCAT output, provide a signature S together with
           a nonce S, such that sha256(N || S) ends with a certain number
           of zero-bytes. The PoW-hash has to be also provided in two
           parts (non-zeros part HA, zeros part HB).

           Witness stack for spending:
                - P (x-only public key [32 bytes])
                - S (signature [64 bytes, i.e. implicit SIGHASH_ALL])
                - N (nonce string)
                - HA (core part of hash)
                - HB (zero-bytes-postfix-part of hash)

           For demo purposes and to keep the script simple, a fixed-length
           zero-postfix of 2 bytes is required here, and there is no delay on
           when the funds can be spent.
        """
        def build_faucat_script(n):
            # TODO: take use of difficulty n

            # construct taproot script for faucat
            return CScript([
                OP_DUP, b'\x00\x00', OP_EQUALVERIFY,                 # check that HB is all-zeros
                OP_CAT, OP_TOALTSTACK,                               # save H = HA || HB
                OP_OVER, OP_SIZE, bytes([64]), OP_EQUALVERIFY,       # grab signature, check it's 64 bytes, no funny business!
                OP_CAT, OP_SHA256, OP_FROMALTSTACK, OP_EQUALVERIFY,  # check PoW, i.e. sha256(N || S) == H
                OP_SWAP, OP_SIZE, bytes([32]), OP_EQUALVERIFY,       # check pubkey is 32 bytes, no funny business!
                OP_CHECKSIG,                                         # verify signature
            ])
        faucat_script = build_faucat_script(0)
        faucat_tapinfo = taproot_construct(bytes.fromhex(H_POINT), [("only-path", faucat_script)])
        faucat_spk = faucat_tapinfo.scriptPubKey
        faucat_address = output_key_to_p2tr(faucat_tapinfo.output_pubkey)

        # fund faucat
        wallet = MiniWallet(self.nodes[0])
        self.generate(wallet, 200)
        txid, vout = wallet.send_to(from_node=self.nodes[0], scriptPubKey=faucat_spk, amount=500000)

        # drain faucat
        drain_tx = CTransaction()
        drain_tx.vin = [CTxIn(COutPoint(int(txid, 16), vout))]
        drain_tx.vout = [CTxOut(400000, random_p2sh())]

        privkey = ECKey()
        privkey.generate(True)
        pubkey, _ = compute_xonly_pubkey(privkey.get_bytes())
        signature_hash = TaprootSignatureHash(drain_tx, [CTxOut(500000, faucat_spk)], SIGHASH_DEFAULT, 0, True, faucat_script)
        signature = sign_schnorr(privkey.get_bytes(), signature_hash)
        nonce_num = 0
        while True:  # grind nonce
            nonce_bytes = nonce_num.to_bytes(4, 'little')
            pow_hash = sha256(nonce_bytes + signature)
            if pow_hash.endswith(b'\x00\x00'):
                break
            nonce_num += 1

        drain_tx.wit.vtxinwit = [CTxInWitness()]
        drain_tx.wit.vtxinwit[0].scriptWitness.stack = [
            pubkey, signature, nonce_bytes, pow_hash[:-2], pow_hash[-2:],
            faucat_script, bytes([0xc0]) + bytes.fromhex(H_POINT),
        ]
        self.nodes[0].sendrawtransaction(drain_tx.serialize().hex())


    def run_test(self):
        # The goal is to test a number of circumstances and combinations of parameters. Roughly:
        #
        #   - Taproot OP_CAT
        #     - CAT should fail when stack limit is hit
        #     - CAT should fail if there is insuffecient number of element on the stack
        #     - CAT should be able to concatenate two 8 byte payloads and check the resulting 16 byte payload
        #  - Segwit v0 OP_CAT
        #     - Spend should fail due to using disabled opcodes

        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_P2PK)
        self.nodes[0].add_p2p_connection(P2PInterface())

        BLOCKS = 200
        self.log.info("Mining %d blocks for mature coinbases", BLOCKS)
        # Drop the last 100 as they're unspendable!
        coinbase_txids = [
            self.nodes[0].getblock(b)["tx"][0]
            for b in self.generate(wallet, BLOCKS)[:-100]
        ]
        def get_coinbase(): return coinbase_txids.pop()
        self.log.info("Creating setup transactions")

        outputs = [CTxOut(i * 1000, random_p2sh()) for i in range(1, 11)]
        # Add some fee satoshis
        amount_sats = sum(out.nValue for out in outputs) + 200 * 500

        self.log.info(
            "Creating funding txn for 10 random outputs as a Taproot script")
        private_key = ECKey()
        # use simple deterministic private key (k=1)
        private_key.set((1).to_bytes(32, "big"), False)
        assert private_key.is_valid
        public_key, _ = compute_xonly_pubkey(private_key.get_bytes())

        self.log.info(
            "Creating CAT tx with not enough values on the stack")
        not_enough_stack_elements_script = CScript([OP_CAT, OP_EQUAL, OP_2])
        taproot_not_enough_stack_elements = taproot_construct(
            public_key, [("only-path", not_enough_stack_elements_script, 0xC0)])
        taproot_not_enough_stack_elements_funding_tx = create_transaction_to_script(
            self.nodes[0],
            wallet,
            get_coinbase(),
            taproot_not_enough_stack_elements.scriptPubKey,
            amount_sats=amount_sats,
        )

        self.log.info(
            "Creating CAT tx that exceeds the stack element limit size")
        # Convert hex value to bytes
        hex_bytes = bytes.fromhex(('00' * 8))
        stack_limit_script = CScript(
            [
                hex_bytes,
                OP_DUP,
                OP_CAT,
                # 16 bytes on the stack
                OP_DUP,
                OP_CAT,
                # 32 bytes on the stack
                OP_DUP,
                OP_CAT,
                # 64 bytes on the stack
                OP_DUP,
                OP_CAT,
                # 128 bytes on the stack
                OP_DUP,
                OP_CAT,
                # 256 bytes on the stack
                OP_DUP,
                OP_CAT,
                # 512 bytes on the stack
                OP_DUP,
                OP_CAT,
            ])

        taproot_stack_limit = taproot_construct(
            public_key, [("only-path", stack_limit_script, 0xC0)])
        taproot_stack_limit_funding_tx = create_transaction_to_script(
            self.nodes[0],
            wallet,
            get_coinbase(),
            taproot_stack_limit.scriptPubKey,
            amount_sats=amount_sats,
        )
        self.log.info(
            "Creating CAT tx that concatenates to values and verifies")
        hex_value_verify = bytes.fromhex('00' * 16)
        op_cat_verify_script = CScript([
            hex_bytes,
            OP_DUP,
            OP_CAT,
            hex_value_verify,
            OP_EQUAL,
        ])

        taproot_op_cat = taproot_construct(
            public_key, [("only-path", op_cat_verify_script, 0xC0)])
        taproot_op_cat_funding_tx = create_transaction_to_script(
            self.nodes[0],
            wallet,
            get_coinbase(),
            taproot_op_cat.scriptPubKey,
            amount_sats=amount_sats,
        )

        self.log.info("Creating a CAT segwit funding tx")
        segwit_cat_funding_tx = create_transaction_to_script(
            self.nodes[0],
            wallet,
            get_coinbase(),
            CScript([0, sha256(op_cat_verify_script)]),
            amount_sats=amount_sats,
        )

        funding_txs = [
            taproot_not_enough_stack_elements_funding_tx,
            taproot_stack_limit_funding_tx,
            taproot_op_cat_funding_tx,
            segwit_cat_funding_tx,
        ]
        self.log.info("Obtaining TXIDs")
        (
            taproot_not_enough_stack_elements_outpoint,
            taproot_stack_limit_outpoint,
            taproot_op_cat_outpoint,
            segwit_op_cat_outpoint,
        ) = [COutPoint(int(tx.rehash(), 16), 0) for tx in funding_txs]

        self.log.info("Funding all outputs")
        self.add_block(funding_txs)

        self.log.info("Testing Taproot not enough stack elements OP_CAT spend")
        # Test sendrawtransaction
        taproot_op_cat_not_enough_stack_elements_spend = CTransaction()
        taproot_op_cat_not_enough_stack_elements_spend.nVersion = 2
        taproot_op_cat_not_enough_stack_elements_spend.vin = [
            CTxIn(taproot_not_enough_stack_elements_outpoint)]
        taproot_op_cat_not_enough_stack_elements_spend.vout = outputs
        taproot_op_cat_not_enough_stack_elements_spend.wit.vtxinwit += [
            CTxInWitness()]
        taproot_op_cat_not_enough_stack_elements_spend.wit.vtxinwit[0].scriptWitness.stack = [
            not_enough_stack_elements_script,
            bytes([0xC0 + taproot_not_enough_stack_elements.negflag]) +
            taproot_not_enough_stack_elements.internal_pubkey,
        ]

        assert_raises_rpc_error(
            -26,
            STACK_TOO_SHORT_ERROR,
            self.nodes[0].sendrawtransaction,
            taproot_op_cat_not_enough_stack_elements_spend.serialize().hex(),
        )
        self.log.info(
            "OP_CAT with wrong size stack rejected by sendrawtransaction as discouraged"
        )

        self.log.info("Testing Taproot tx with stack element size limit")
        taproot_op_cat_stack_limit_spend = CTransaction()
        taproot_op_cat_stack_limit_spend.nVersion = 2
        taproot_op_cat_stack_limit_spend.vin = [
            CTxIn(taproot_stack_limit_outpoint)]
        taproot_op_cat_stack_limit_spend.vout = outputs
        taproot_op_cat_stack_limit_spend.wit.vtxinwit += [
            CTxInWitness()]
        taproot_op_cat_stack_limit_spend.wit.vtxinwit[0].scriptWitness.stack = [
            stack_limit_script,
            bytes([0xC0 + taproot_stack_limit.negflag]) +
            taproot_stack_limit.internal_pubkey,
        ]

        assert_raises_rpc_error(
            -26,
            MAX_PUSH_ERROR,
            self.nodes[0].sendrawtransaction,
            taproot_op_cat_stack_limit_spend.serialize().hex(),
        )
        self.log.info(
            "OP_CAT with stack size limit rejected by sendrawtransaction as discouraged"
        )

        self.log.info("Testing Taproot OP_CAT usage")
        taproot_op_cat_transaction = CTransaction()
        taproot_op_cat_transaction.nVersion = 2
        taproot_op_cat_transaction.vin = [
            CTxIn(taproot_op_cat_outpoint)]
        taproot_op_cat_transaction.vout = outputs
        taproot_op_cat_transaction.wit.vtxinwit += [
            CTxInWitness()]
        taproot_op_cat_transaction.wit.vtxinwit[0].scriptWitness.stack = [
            op_cat_verify_script,
            bytes([0xC0 + taproot_op_cat.negflag]) +
            taproot_op_cat.internal_pubkey,
        ]

        assert_equal(
            self.nodes[0].sendrawtransaction(
                taproot_op_cat_transaction.serialize().hex()),
            taproot_op_cat_transaction.rehash(),
        )
        self.log.info(
            "Taproot OP_CAT verify spend accepted by sendrawtransaction"
        )
        self.add_block([taproot_op_cat_transaction])

        self.log.info("Testing Segwitv0 CAT usage")
        segwitv0_op_cat_transaction = CTransaction()
        segwitv0_op_cat_transaction.nVersion = 2
        segwitv0_op_cat_transaction.vin = [
            CTxIn(segwit_op_cat_outpoint)]
        segwitv0_op_cat_transaction.vout = outputs
        segwitv0_op_cat_transaction.wit.vtxinwit += [
            CTxInWitness()]
        segwitv0_op_cat_transaction.wit.vtxinwit[0].scriptWitness.stack = [
            op_cat_verify_script,
        ]

        assert_raises_rpc_error(
            -26,
            DISABLED_OP_CODE,
            self.nodes[0].sendrawtransaction,
            segwitv0_op_cat_transaction.serialize().hex(),
        )
        self.log.info(
            "allowed by consensus, disallowed by relay policy"
        )

        self.test_example_faucat()


if __name__ == "__main__":
    CatTest().main()
