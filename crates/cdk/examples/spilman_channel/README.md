_Last updated: 2025-12-07_

This is demo code to go along with the Pull Request for
the Spilman Channel NUT: https://github.com/cashubtc/nuts/pull/296/files .
Read that for all the context

The demo code is all in the `crates/cdk/examples/spilman_channel` here:
```
 crates/cdk/examples/spilman_channel/
                                     README.md - this file
                                     main.rs -- an 'example'. See below on how to run it
                                     test_helpers.rs -- some helper functions used in the
                                                        unit tests and also in the example
                                     ... various other files with the code and tests

```

# Quick start with example

```
# To clone this repo:
git clone git@github.com:SatsAndSports/demo_of_spillman_cashu_channel.git

cd demo_of_spillman_cashu_channel

# To go to the correct branch:
git checkout spilman.channel

# to run the 'example' mentioned above, with very verbose messages as it runs:
cargo run --example spilman_channel
```

# Tests

Run tests with `cargo test --example spilman_channel`

# Where should I start reading?

The tests in `sender_and_receiver`, starting with `test_full_flow`, are probably the best
place to start to see the flow of a channel being opened and a payment been made
and also to see the channel being closed.

A typical test does the following:

1. generate private and public keys for Alice (the sender) and Charlie (the receiver)
1. set up the test mint and wallets, with configurable fee rate, and collect the KeysetInfo for the relevant keyset
1. Define all the channel parameters in `SpilmanChannelParameters`
1. Define the `SpilmanChannelExtra`, which contains some extra shared non-mutable data for the channel, such as the ECDH _shared secret_. The `SpilmanChannelParameters` are identical for both parties, as is `SpilmanChannelExtra`.
1. Alice then creates the funding token. She does it via a 'mint' operation in these tests, but in the real world I guess that 'swap' will be more common.
1. The `SpilmanChannelSender` (for Alice) and `SpilmanChannelReceiver` (for Charlie) objects are set up, containing all the channel data and the relevant private key. These provide the easy-to-use methods for both parties
1. Alice calls `sender.create_signed_balance_update(charlie_balance)` to create the `BalanceUpdateMessage` which has all the relevant data (channel_id, new balance, signature) that Alice sends to Charlie to make the payment
1. Charlie then does some asserts based on the payment just made, primarily `receiver.verify_and_sign_balance_update` - which calls `balance_update.verify_sender_signature` to reconstruct the commitment transaction and verify that Alice's signature is correct
1. In most of the tests (currently) Charlie immediately exits by adding his signature and swapping
1. The results of the swap are _unblinded_ using the deterministic blinding factors
1. The resulting 1-of-1 P2PK outputs are swapped for anyone-can-spend outputs and added to the wallets of Alice and Charlie, and there is an assertion to ensure that Charlie received the expected amount

# Mints with non-powers-of-2 keysets

If you look closely at the PR in this repo for this branch, you'll see that it
has some code changes to the CDK along with this new
`crates/cdk/examples/spilman_channel/` folder.
The default CDK mint generates keysets with powers-of-2. The code changes
here allow this base to be configurable.
There are some tests in the `sender_and_receiver.rs` which use powers-of-3.
I'm not expecting those CDK changes to be merged, as that code is a bit hacky.
The goal was just to test the spilman channel code more thoroughly.
Those CDK changes, and the corresponding spilman tests, can be reverted
and deleted; I just like keeping them for now in order to thoroughly test the spilman code.


# TODOs for the code

The following are working, or were working, but just haven't been put into a unit test yet:
 - Alice restoring signatures in the 'happy path', where Charlie exited in the expected way.
 - otherwise, Alice restoring when the balance used by Charlie is unknown.

Other things that should be done:
 - Alice restoring when Charlie uses an unexpected keyset (see _Keyset Malleability_ in the NUT)
 - Using another mint, not just the CDK mint used in the tests. The earliest iterations of the spilman demo code did work with Nutshell, but that was before the SIG_ALL message update and before other changes. So I should make sure that works again. A `--mint` option can be passed to the example already, and it might still be fully working, but I should test it again and also with any public (test) mints that have the SIG_ALL update.
 - I'd like to try a `unit=millisat` mint too
 - And make a fun realistic example, like paying for a streaming video within WebSockets
 - a text for the maximum_output thing, as I'm worried my recent refactoring might have broken it
