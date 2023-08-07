1. Deploy EigenLayer contracts
???

2. `DeployBeacon.s.sol`
- `forge script scripts/DeployBeacon.s.sol:DeployBeacon true --sig "run(bool)" -vvvv --rpc-url=$EPHEMERY_RPC_URL --broadcast`

3. `DeploySafe.s.sol`


4. `DeployPufferPool.s.sol`
- `forge script scripts/DeployPufferPool.s.sol:DeployPuffer $BEACON $SAFE_PROXY_FACTORY $SAFE_IMPLENTATION --sig "run(address,addres,address)" -vvvv --rpc-url=$EPHEMERY_RPC_URL --broadcast`

5. `DeployPuffer.s.sol`:
- `forge script scripts/DeployPuffer.s.sol:DeployPuffer -vvvv --rpc-url=$EPHEMERY_RPC_URL --broadcast`