This is a guide for servers, i.e. service providers, to integrate this into their systems so that they can collect Cashu payments with a channel.

This assumes you have some familiarity with Cashu, the Chaumian e-cash which is a private and fast way to make Bitcoin payments.

... structure of this ... focusses on the practicalities and the code interface ..

# what is a channel?

We often say that Cashu is a "bearer asset", but Cashu allows tokens to be locked such that they can be spent only with signatures

In the channel system here, the client (who will pay for your service) prepares a token which is locked such that it can only be spents with sigs from both the client and the server.

The client can prepare a token with a capacity of 1,000 satoshis. ... initial payment 5 satoshis ... server can exit at any time with just 5. so even though the the client spent 1k sats initially, the remainder 1000-995 still belongs to the client

... server can close at any time, collecting only what they are due, and freeing the remainder ...

to make a payment, the client signs a new transaction which increase the balance in favour of the server. If the last signature was for a (5,995) split and the client sends a signature fo (7,993), then the client has made a payment for +2 sats

# Trust

... the two parties must trust the mint, but don't have to trust each other. Clients will be willing to fund larger channels with untrusted servers, only realeasing tiny amounts in return for service

# state

... ascii art diagram showing FUNDED OPEN CLOSING CLOSED

as the server operator, you decide how to store the state. For each channel, referenced by a `channel_id`, you specify  - via implementing the .... interface - how to update your database of the state of each channel


... track usage of each channel ... each signature from teh client should provide enough balance to cover the current request and also all the historical activity on the channel

... role of the Bridge, and the languages available, and the role of the Host ...
 
# expiry

 ... if the server doesn't close, then the client can reclaim everything

# Compat

... works with any mint that follows the lsatest standards
