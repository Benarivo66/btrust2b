path_to_bitcoin_functional_test = "/Users/mac/documents/bitcoin/test/functional"

import sys

sys.path.insert(0, path_to_bitcoin_functional_test)


from functions import *
import hashlib

# import json

def gen_redeem_script(preimage):
    # compute redeem script for preimage
    # byte encoding for "Btrust Builders" is 427472757374204275696c64657273
    
    lock_hex = hashlib.sha256(preimage.encode("utf-8")).digest().hex()
    
    redeem_script = bytes.fromhex(
        "a8"
        + "20"
        + lock_hex
        + "87"
    )
    print(f"redeem script in hexadecimal: {redeem_script.hex()}\n")
    return redeem_script

# gen_redeem_script("Btrust Builders")

def get_address(preimage):
    # Get address from redeem script
    redeem_script = gen_redeem_script(preimage)
    p2sh_address = script_to_p2sh(redeem_script, "regtest")
    print(f"p2sh_address: {p2sh_address}")
    return p2sh_address


def send_bitcoin(preimage, amount_to_send):
    # send bitcoin to address
    
    node = setup_testshell()
    p2sh_address = get_address(preimage)
    txid_to_spend, index_to_spend = fund_address(node, p2sh_address, amount_to_send)
    
    print(f"txid: {txid_to_spend}, {index_to_spend}\n")
    return txid_to_spend, index_to_spend

    # That we can get txid_to_spend and index_to_spend means the funding was successful
    
# address = get_address("Btrust Builders")   
# send_bitcoin("Btrust Builders", 2.001)

def spend_from_transaction(preimage, scriptPubKey, total_amount, amount_to_spend, change):
    receiver_spk = bytes.fromhex(scriptPubKey)

    change_privkey = bytes.fromhex("4444444444444444444444444444444444444444444444444444444444444444")
    change_pubkey = privkey_to_pubkey(change_privkey)

    output1_value_sat = int(float(amount_to_spend) * 100000000)
    output1_spk = receiver_spk
    output2_value_sat = int(float(change) * 100000000)
    output2_spk = bytes.fromhex("76a914") + hash160(change_pubkey) + bytes.fromhex("88ac")

    version = bytes.fromhex("0200 0000")

    # INPUTS
    txid_to_spend, index_to_spend = send_bitcoin(preimage, total_amount)
    
    input_count = bytes.fromhex("01")
    txid = (bytes.fromhex(txid_to_spend))[::-1]
    index = index_to_spend.to_bytes(4, byteorder="little", signed=False)

    scriptsig = bytes.fromhex("")

    sequence = bytes.fromhex("ffff ffff")

    inputs = (
        txid
        + index
        + varint_len(scriptsig)
        + scriptsig
        + sequence
    )

    # OUTPUTS
    output_count = bytes.fromhex("02")
    output1_value = output1_value_sat.to_bytes(8, byteorder="little", signed=True)

    # OUTPUT 2
    output2_value = output2_value_sat.to_bytes(8, byteorder="little", signed=True)

    outputs = (
        output1_value
        + pushbytes(output1_spk)
        + output2_value
        + pushbytes(output2_spk)
    )


    #Locktime
    locktime = bytes.fromhex("0000 0000")

    unsigned_tx = (
        version
        + input_count
        + inputs
        + output_count
        + outputs
        + locktime
    )
    print(f"unsigned_tx:  {unsigned_tx.hex()}\n")
    
    redeem_script = gen_redeem_script(preimage)
    
    encoded_string = preimage.encode('utf-8')
    
    sig_script_signed = (
        bytes.fromhex("00")
        + pushbytes(encoded_string)
        + pushbytes(redeem_script)
    )

    inputs_signed = (
        txid
        + index
        + varint_len(sig_script_signed)
        + sig_script_signed
        + sequence
    )

    signed_tx = (
        version
        + input_count
        + inputs_signed
        + output_count
        + outputs
        + locktime
    )
    
    # print(f"signed_tx: {signed_tx.hex()}")
    print(f"sig script signed: {sig_script_signed.hex()}\n")
    print(f" signed_tx: {signed_tx.hex()}")
    
spend_from_transaction("Btrust Builders", "76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac", 2.001, 1.5, 0.5) 

            