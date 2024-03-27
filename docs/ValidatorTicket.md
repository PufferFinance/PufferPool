# Validator Ticket

You can think of validator tickets as validator time at a discounted price. In order to run validators in Puffer, you must lock validator tickets in PufferProtocol. Each validator consumes 1 VT per day. The VT accounting is done off chain on the guardians side. Validator tickets are consumed only after the validator has ben activated on consensus layer, being in the entry queue doesn't consume any validator tickets.

When somebody purchases a validator ticket, the following happens:
- Portion of the funds goes to the treasury
- Portion of the funds goes to the guardians to subsidize their operating costs
- The remainder goes to the PufferVault (this changes the exchange rate in favour of pufETH holders)