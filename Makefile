# Function to check if the ENV_FILE is set and exists
check_env_file:
	@if [ -z "$(ENV_FILE)" ] || [ ! -f "$(ENV_FILE)" ]; then \
		echo "Error: No .env file specified or file does not exist."; \
		echo "Usage: ENV_FILE=.env make testnet" \
		exit 1; \
	fi

.PHONY: all testnet deploy set_guardian_measurements add_leaf_x509 deposit_liquidity save_abis check_env_file

testnet: check_env_file deploy set_guardian_measurements add_leaf_x509 deposit_liquidity save_abis

deploy: check_env_file
	@source $(ENV_FILE) && echo "Deploying contracts to RPC_URL=$$RPC_URL, with GUARDIAN_EOA=$$GUARDIAN_EOA"
	@source $(ENV_FILE) && PK=$$PK forge script script/DeployEverything.s.sol:DeployEverything --rpc-url=$$RPC_URL --sig 'run(address[] calldata, uint256)' "[$$GUARDIAN_EOA]" 1 --broadcast

set_guardian_measurements: check_env_file
	@echo "Setting Guardian Enclave Measurements"
	@source $(ENV_FILE) && PK=$$PK forge script script/SetGuardianEnclaveMeasurements.s.sol:SetEnclaveMeasurements --rpc-url=$$RPC_URL --broadcast --sig "run(bytes32,bytes32)" -vvvv "0x$$MR_ENCLAVE" "0x$$MR_SIGNER"

add_leaf_x509: check_env_file
	@echo "Adding Leaf X509"
	@source $(ENV_FILE) && PK=$$PK forge script script/AddLeafX509.s.sol:AddLeaftX509 --rpc-url=$$RPC_URL --broadcast --sig "run(bytes)" -vvvv $$LEAF_X509

deposit_liquidity: check_env_file
	@echo "Depositing initial liquidity for PufferVault"
	@source $(ENV_FILE) && PK=$$PK forge script script/DepositETH.s.sol:DepositETH --rpc-url=$$RPC_URL --broadcast --sig "run(uint256)" $$DEV_WALLET_SEED_ETH_AMOUNT -vvvv --private-key $$PK

save_abis: check_env_file
	@echo "Saving ABIs"
	@source $(ENV_FILE) && mkdir -p $$ABI_DIR
	@source $(ENV_FILE) && cp output/puffer.json $$ABI_DIR/addresses.json
	@source $(ENV_FILE) && forge inspect PufferProtocol abi > $$ABI_DIR/PufferProtocol.json
	@source $(ENV_FILE) && forge inspect GuardianModule abi > $$ABI_DIR/GuardianModule.json
	@source $(ENV_FILE) && forge inspect PufferVaultV2 abi > $$ABI_DIR/PufferVaultV2.json
	@source $(ENV_FILE) && forge inspect ValidatorTicket abi > $$ABI_DIR/ValidatorTicket.json
	@source $(ENV_FILE) && forge inspect PufferOracle abi > $$ABI_DIR/PufferOracle.json
	@source $(ENV_FILE) && cat $$ABI_DIR/addresses.json
