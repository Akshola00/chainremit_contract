use starknet::ContractAddress;
use crate::base::types::DepositDetails;

pub mod Events {
    use super::*;
    #[derive(Drop, starknet::Event)]
    pub struct DepositEvent {
        #[key]
        pub deposit_id: u256,
        pub details: DepositDetails,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenAdded {
        pub token_address: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenRemoved {
        pub token_address: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Paused {
        pub account: ContractAddress,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Unpaused {
        pub account: ContractAddress,
        pub timestamp: u64,
    }
}
