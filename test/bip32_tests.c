/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <btc/bip32.h>

#include "utest.h"
#include <btc/utils.h>

void test_bip32()
{
    btc_hdnode node, node2, node3, node4;
    char str[112];
    int r;
    uint8_t private_key_master[32];
    uint8_t chain_code_master[32];

    char *xpriv = "xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr";

    btc_hdnode_deserialize(xpriv, &btc_chain_main, &node);

    /* [Chain m] */
    memcpy(private_key_master,
           utils_hex_to_uint8("00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd"),
           32);
    memcpy(chain_code_master,
           utils_hex_to_uint8("9c8a5c863e5941f3d99453e6ba66b328bb17cf0b8dec89ed4fc5ace397a1c089"),
           32);
    u_assert_int_eq(node.fingerprint, 0x00000000);
    u_assert_mem_eq(node.chain_code, chain_code_master, 32);
    u_assert_mem_eq(node.private_key, private_key_master, 32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("02b3e3e297165289611a2387e8089fcaf099926e4d31fdddb50c0ae0dfa36c97e6"),
                    33);
    btc_hdnode_serialize_private(&node, &btc_chain_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr");
    r = btc_hdnode_deserialize(str, &btc_chain_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(btc_hdnode));

    btc_hdnode_get_p2pkh_address(&node, &btc_chain_main, str, sizeof(str));
    u_assert_str_eq(str, "1H2JXH6TD7B5iB9nJoj98R6vG25Pgpshbx");

    btc_hdnode_serialize_public(&node, &btc_chain_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub661MyMwAqRbcG6q1FFDUUHr61LatpoMSZRQpVWR4MHzfGnfUp8GMT5xfKcrt4xB7nJCgXn1NBqgCGGDkJx1ZLRKeM58HZkhV5NjBWK1AyQY");
    r = btc_hdnode_deserialize(str, &btc_chain_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(btc_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(btc_hdnode));

    /* [Chain m/44'/0'/0'/0/0'] */
    char path0[] = "m/44'/0'/0'/0/0'";
    btc_hd_generate_key(&node, path0, private_key_master, chain_code_master, false);
    //TODO u_assert_int_eq(node.fingerprint, -1294457973);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("7a16b2f4ad4cc1069338237f373dabf1fe329a5f3a0d95c4b98d061204676293"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("030e13168e3f9560da5cebca9c91b78280e7ffa221d097c6dac3e98f450355d6f6"),
                    33);
    btc_hdnode_serialize_private(&node, &btc_chain_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprvA2raHwVHoKWFN25agpLN6SbeDAQ2uKiTQxmC6TsWi4xYFuKx7QyfLAfMqgvyXVr6fcDspooYFsas1ngymgmVSPjTCU5JRfwj6w4zukhfucS");
    r = btc_hdnode_deserialize(str, &btc_chain_main, &node2);
    u_assert_int_eq(r, true);
    u_assert_mem_eq(&node, &node2, sizeof(btc_hdnode));

    btc_hdnode_get_p2pkh_address(&node, &btc_chain_main, str, sizeof(str));
    u_assert_str_eq(str, "1HJeCjjMm7qTmx3CCBVVGD9wGqvRuBL4xB");

    btc_hdnode_serialize_public(&node, &btc_chain_main, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub6FqvhT2Bdh4YaWA3nqsNTaYNmCEXJnSJnBgntrH8GQVX8hf6exHusxyqgyd6kKKNTvtbpmNPGEH74VxJaAuo14NS52WBmWG9krq1ESqdR6T");
    r = btc_hdnode_deserialize(str, &btc_chain_main, &node2);
    u_assert_int_eq(r, true);
    memcpy(&node3, &node, sizeof(btc_hdnode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(btc_hdnode));

}
