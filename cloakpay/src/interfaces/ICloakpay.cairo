use starknet::ContractAddress;
use crate::base::types::DepositDetails;
#[starknet::interface]
pub trait ICloakPay<TContractState> {
    fn deposit(ref self: TContractState, supported_token: u256, amount: u256, commitment: felt252);
    fn get_deposit_details(ref self: TContractState, deposit_id: u256) -> DepositDetails;
    fn get_total_deposits(ref self: TContractState) -> u256;
    fn get_commitment_used_status(ref self: TContractState, commitment: felt252) -> bool;
    fn get_deposit_id_from_commitment(ref self: TContractState, commitment: felt252) -> u256;
    fn pause(ref self: TContractState);
    fn resume(ref self: TContractState);
    fn get_paused_status(ref self: TContractState) -> bool;
    fn add_supported_token(ref self: TContractState, token_address: ContractAddress);
    fn remove_supported_token(ref self: TContractState, token_address: ContractAddress);
    fn is_token_supported(ref self: TContractState, token_address: ContractAddress) -> bool;
    fn get_supported_tokens(ref self: TContractState) -> Array<ContractAddress>;
}
