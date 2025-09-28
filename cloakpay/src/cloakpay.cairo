#[starknet::contract]
pub mod cloakpay {
    use core::num::traits::Zero;
    use openzeppelin::access::accesscontrol::AccessControlComponent;
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::storage::{
        Map, MutableVecTrait, StorageMapReadAccess, StoragePathEntry, StoragePointerReadAccess,
        StoragePointerWriteAccess, Vec, VecTrait,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address, get_contract_address};
    use crate::base::errors::{CloakPayErrors, payment_errors};
    use crate::base::events::Events::*;
    use crate::base::types::DepositDetails;
    use crate::interfaces::ICloakpay::ICloakPay;
    const ADMIN_ROLE: felt252 = selector!("ADMIN");
    const OVERALL_ADMIN_ROLE: felt252 = selector!("OVERALL_ADMIN_ROLE");

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: AccessControlComponent, storage: accesscontrol, event: AccessControlEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);


    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl InternalImpl = OwnableComponent::InternalImpl<ContractState>;
    // AccessControl
    #[abi(embed_v0)]
    impl AccessControlImpl =
        AccessControlComponent::AccessControlImpl<ContractState>;
    impl AccessControlInternalImpl = AccessControlComponent::InternalImpl<ContractState>;

    // SRC5
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    #[storage]
    struct Storage {
        deposit: Map<u256, DepositDetails>, // deposit id to deposit details
        commitments: Map<felt252, bool>, // commitment to use status
        commitment_to_deposit_id: Map<felt252, u256>, // commitment to deposit id
        total_deposits: u256,
        supported_tokens: Map<u256, ContractAddress>, // supported token_id to contract address
        supported_tokens_status: Map<ContractAddress, bool>, // token address to supported status
        supported_tokens_list: Vec<ContractAddress>, // list of supported token addresses
        paused: bool, // contract paused status
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        accesscontrol: AccessControlComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        DepositEvent: DepositEvent,
        TokenAdded: TokenAdded,
        TokenRemoved: TokenRemoved,
        Paused: Paused,
        Unpaused: Unpaused,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        AccessControlEvent: AccessControlComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, owner: ContractAddress, default_supported_token: ContractAddress,
    ) {
        assert(!owner.is_zero(), CloakPayErrors::ERROR_ZERO_ADDRESS);
        // initialize owner of contract
        self.ownable.initializer(owner);
        self.accesscontrol.initializer();
        self.accesscontrol.set_role_admin(ADMIN_ROLE, OVERALL_ADMIN_ROLE);
        self.accesscontrol._grant_role(ADMIN_ROLE, owner);
        self.accesscontrol._grant_role(OVERALL_ADMIN_ROLE, owner);
        self.supported_tokens.entry(1_u256).write(default_supported_token);
        self.supported_tokens_status.entry(default_supported_token).write(true);
        self.supported_tokens_list.push(default_supported_token);
        self.total_deposits.write(0_u256);
    }


    #[abi(embed_v0)]
    impl CloakPayImpl of ICloakPay<ContractState> {
        fn deposit(
            ref self: ContractState, supported_token: u256, amount: u256, commitment: felt252,
        ) {
            self._assert_not_paused();
            assert(!self.commitments.read(commitment), CloakPayErrors::COMMITMENT_ALREADY_USED);
            let supported_token = self.supported_tokens.read(supported_token);
            assert(!supported_token.is_zero(), CloakPayErrors::UNSUPPORTED_TOKEN);
            self._process_payment(amount, supported_token);
            let deposit_id = self.total_deposits.read() + 1;
            let deposit_details = DepositDetails {
                supported_token, amount, commitment, time_sent: get_block_timestamp(),
            };
            self.deposit.entry(deposit_id).write(deposit_details);
            self.commitment_to_deposit_id.entry(commitment).write(deposit_id);
            self.total_deposits.write(deposit_id);
            self.commitments.entry(commitment).write(true);
            self
                .emit(
                    Event::DepositEvent(
                        DepositEvent { deposit_id: deposit_id, details: deposit_details },
                    ),
                );
        }

        fn get_deposit_details(ref self: ContractState, deposit_id: u256) -> DepositDetails {
            self.deposit.read(deposit_id)
        }

        fn get_total_deposits(ref self: ContractState) -> u256 {
            self.total_deposits.read()
        }

        fn get_commitment_used_status(ref self: ContractState, commitment: felt252) -> bool {
            self.commitments.read(commitment)
        }

        fn get_deposit_id_from_commitment(ref self: ContractState, commitment: felt252) -> u256 {
            self.commitment_to_deposit_id.read(commitment)
        }


        fn pause(ref self: ContractState) {
            self.accesscontrol.assert_only_role(ADMIN_ROLE);
            self.paused.write(true);
            self
                .emit(
                    Event::Paused(
                        Paused { account: get_caller_address(), timestamp: get_block_timestamp() },
                    ),
                );
        }
        fn resume(ref self: ContractState) {
            self.accesscontrol.assert_only_role(ADMIN_ROLE);

            self.paused.write(false);
            self
                .emit(
                    Event::Unpaused(
                        Unpaused {
                            account: get_caller_address(), timestamp: get_block_timestamp(),
                        },
                    ),
                );
        }
        fn get_paused_status(ref self: ContractState) -> bool {
            self.paused.read()
        }

        fn add_supported_token(ref self: ContractState, token_address: ContractAddress) {
            self.accesscontrol.assert_only_role(ADMIN_ROLE);
            assert(!token_address.is_zero(), CloakPayErrors::ERROR_ZERO_ADDRESS);
            self._assert_not_paused();

            assert(!self.supported_tokens_status.read(token_address), 'Token already supported');

            self.supported_tokens_status.entry(token_address).write(true);
            self.supported_tokens_list.push(token_address);
            self.emit(Event::TokenAdded(TokenAdded { token_address }));
        }

        fn remove_supported_token(ref self: ContractState, token_address: ContractAddress) {
            self.accesscontrol.assert_only_role(ADMIN_ROLE);
            assert(!token_address.is_zero(), CloakPayErrors::ERROR_ZERO_ADDRESS);
            self._assert_not_paused();

            assert(self.supported_tokens_status.read(token_address), 'Token not supported');

            self.supported_tokens_status.entry(token_address).write(false);
            self._remove_token_from_list(token_address);
            self.emit(Event::TokenRemoved(TokenRemoved { token_address }));
        }

        fn is_token_supported(ref self: ContractState, token_address: ContractAddress) -> bool {
            self.supported_tokens_status.read(token_address)
        }

        fn get_supported_tokens(ref self: ContractState) -> Array<ContractAddress> {
            self._get_supported_tokens_array()
        }
    }

    #[generate_trait]
    impl Internal of InternalTrait {
        /// @notice Processes a payment for a deposit
        fn _process_payment(ref self: ContractState, amount: u256, token: ContractAddress) {
            let strk_token = IERC20Dispatcher { contract_address: token };
            let caller = get_caller_address();
            let contract_address = get_contract_address();
            self._check_token_allowance(caller, amount, token);
            self._check_token_balance(caller, amount, token);
            strk_token.transfer_from(caller, contract_address, amount);
        }

        /// @notice Checks if the caller has sufficient token allowance.
        fn _check_token_allowance(
            ref self: ContractState, spender: ContractAddress, amount: u256, token: ContractAddress,
        ) {
            let token = IERC20Dispatcher { contract_address: token };
            let allowance = token.allowance(spender, starknet::get_contract_address());
            assert(allowance >= amount, payment_errors::INSUFFICIENT_ALLOWANCE);
        }

        /// @notice Checks if the caller has sufficient token balance.
        fn _check_token_balance(
            ref self: ContractState, caller: ContractAddress, amount: u256, token: ContractAddress,
        ) {
            let token = IERC20Dispatcher { contract_address: token };
            let balance = token.balance_of(caller);
            assert(balance >= amount, payment_errors::INSUFFICIENT_BALANCE);
        }

        /// @notice Asserts that the contract is not paused.
        fn _assert_not_paused(ref self: ContractState) {
            assert(!self.paused.read(), 'CONTRACT IS PAUSED');
        }

        /// @notice Gets all supported tokens as an array
        fn _get_supported_tokens_array(self: @ContractState) -> Array<ContractAddress> {
            let mut tokens = ArrayTrait::<ContractAddress>::new();
            let list_length = self.supported_tokens_list.len();
            for i in 0..list_length {
                let token_address = self.supported_tokens_list.at(i).read();
                if self.supported_tokens_status.read(token_address) {
                    tokens.append(token_address);
                }
            }
            tokens
        }

        /// @notice Removes a token from the supported tokens list
        fn _remove_token_from_list(ref self: ContractState, token_address: ContractAddress) {
            let mut temp_list = ArrayTrait::<ContractAddress>::new();
            let list_length = self.supported_tokens_list.len();

            for i in 0..list_length {
                let current_token = self.supported_tokens_list.at(i).read();
                if current_token != token_address {
                    temp_list.append(current_token);
                }
            }

            for _ in 0..list_length {
                let _ = self.supported_tokens_list.pop();
            }

            let temp_length = temp_list.len();
            for i in 0..temp_length {
                self.supported_tokens_list.push(*temp_list.at(i));
            }
        }
    }
}
