extern crate bigint;
extern crate core;
extern crate digest;
extern crate nibble;
extern crate num;
extern crate sha3;

mod trie;

use core::clone::Clone;
use core::ops::*;
use std::cmp::max;
use bigint::uint::U256;
use num::BigUint;
// use sha3::{Digest, Keccak256};

const homestead: u32 = 1150000;

type Instruction = u16;

#[derive(PartialEq, Clone)]
pub struct K256(U256);

#[derive(PartialEq, Clone)]
pub struct Address([u8; 20]);

#[derive(PartialEq, Clone)]
pub enum VMResult {
    VmFailure,
    VmSuccess,
}

#[derive(PartialEq, Clone)]
pub struct FrameState {
    // contract
    //     codeContract
    gas_available: U256,
    pc:            U256,
    memory:        Vec<u8>,
    active_words:  U256,
    stack:         Vec<U256>,
    //     memory
    //     memorySize
    //     calldata
    //     callvalue
    //     caller
}

#[derive(PartialEq, Clone)]
pub struct AccountState {
    nonce: u32,
    balance: u32,
    storage_root: K256,
    code_hash: K256,
}

#[derive(PartialEq, Clone)]
pub struct TransactionCommon {
    nonce: u64,
    gas_price: BigUint,
    gas_limit: BigUint,
    to: Address,
    value: BigUint,
    v: BigUint,
    r: BigUint,
    s: BigUint,
}

#[derive(PartialEq, Clone)]
pub enum Transaction {
    CreationTransaction { common: TransactionCommon, init: Option<Vec<u8>> },
    CallTransaction { common: TransactionCommon, data: Vec<u8> },
}

struct Bloom([u8; 256]);

impl PartialEq for Bloom {
    fn eq(&self, &Bloom(other): &Bloom) -> bool {
        // https://stackoverflow.com/a/23149538/383958
        self.0.iter().zip(other.iter()).all(|(a,b)| a == b)
    }
}

impl Clone for Bloom {
    fn clone(&self) -> Bloom { Bloom(self.0) }
}

#[derive(PartialEq, Clone)]
pub struct Block {
    parent_hash: K256,
    ommers_hash: K256,
    beneficiary: Address,
    state_root: K256,
    transactions_root: K256,
    receipts_root: K256,
    logs_bloom: Bloom,
    difficulty: BigUint,
    number: BigUint,
    gas_limit: BigUint,
    gas_used: BigUint,
    timestamp: BigUint,
    extra_data: Vec<u8>,
    mix_hash: K256,
    nonce: u64,
}

#[derive(PartialEq, Clone)]
pub struct Log {
    address: Address,
    topics: Vec<K256>,
    data: Vec<u8>,
    block_number: u64,
    tx_hash: K256,
    tx_index: u32,
    block_hash: K256,
    index: u32,
    removed: bool,
}

#[derive(PartialEq, Clone)]
pub struct TransactionReceipt {
    // state:
    gas_used: u32,
    logs: Vec<Log>,
    bloom: Bloom,
}

#[derive(PartialEq, Clone)]
pub struct Contract {
    // callerAddress: Address,
    // caller
}

#[derive(PartialEq, Clone)]
pub struct Header {}

#[derive(PartialEq, Clone)]
pub struct Env {
    /// I_a, the address of the account which owns the code that is executing
    owner: Address,

    /// I_o, the sender address of the transaction that originated this execution
    origin: Address,

    /// I_p: the price of gas in the transaction that originated this execution
    gas_price: U256, // XXX also in TransactionCommon

    /// I_d: the byte array that is the input data to this execution; if the execution agent is a
    /// transaction, this would be the transaction data
    data: Vec<u8>,

    /// I_s: the address of the account which caused the code to be executing; if the execution
    /// agent is a transaction this would be the transaction sender
    caller: Address,

    /// I_v, the value, in Wei, passed to this account as part of the same procedure as execution;
    /// if the execution agent is a transaction, this would be the transaction value
    transaction_value: U256,

    /// I_b, the byte array that is the machine code to be executed
    code: Vec<u8>,

    /// I_H, the block header of the present block
    header: Header,

    /// I_e: the depth of the present message-call or contract-creation (ie the number of CALLs of
    /// CREATEs being executed at present)
    depth: u16,
}

#[derive(PartialEq, Clone)]
pub struct VM {
    result: Option<VMResult>,
    state:  FrameState,
    // frames: Array<Frame>,
    env: Env,
    // block
}

// 0s: stop and arithmetic operations
pub const STOP: u16 = 0x00;
pub const ADD: u16  = 0x01;
pub const MUL: u16  = 0x02;
pub const SUB: u16  = 0x03;
pub const DIV: u16  = 0x04;

// 10s: comparison & bitwise logic operations
pub const LT: u16     = 0x10;
pub const GT: u16     = 0x11;
pub const SLT: u16    = 0x12;
pub const SGT: u16    = 0x13;
pub const EQ: u16     = 0x14;
pub const ISZERO: u16 = 0x15;
pub const AND: u16    = 0x16;
pub const OR: u16     = 0x17;
pub const XOR: u16    = 0x18;
pub const NOT: u16    = 0x19;
pub const BYTE: u16    = 0x1a;

// 20s: sha3
pub const SHA3: u16    = 0x20;

// 30s: environmental information
pub const ADDRESS: u16 = 0x30;

// 40s: block information
// 50s: stack, memory, storage, and flow operations
pub const POP: u16 = 0x50;
pub const PC: u16 = 0x58;
pub const MSIZE: u16 = 0x59;
pub const GAS: u16 = 0x5a;
pub const JUMPDEST: u16 = 0x5b;

// 60s & 70s: push operations
// 80s: duplication operations
pub const DUP1: u16  = 0x80;
pub const DUP2: u16  = 0x81;
pub const DUP3: u16  = 0x82;
pub const DUP4: u16  = 0x83;
pub const DUP5: u16  = 0x84;
pub const DUP6: u16  = 0x85;
pub const DUP7: u16  = 0x86;
pub const DUP8: u16  = 0x87;
pub const DUP9: u16  = 0x88;
pub const DUP10: u16 = 0x89;
pub const DUP11: u16 = 0x8a;
pub const DUP12: u16 = 0x8b;
pub const DUP13: u16 = 0x8c;
pub const DUP14: u16 = 0x8d;
pub const DUP15: u16 = 0x8e;
pub const DUP16: u16 = 0x8f;

// 90s: exchange operations
pub const SWAP1: u16  = 0x90;
pub const SWAP2: u16  = 0x91;
pub const SWAP3: u16  = 0x92;
pub const SWAP4: u16  = 0x93;
pub const SWAP5: u16  = 0x94;
pub const SWAP6: u16  = 0x95;
pub const SWAP7: u16  = 0x96;
pub const SWAP8: u16  = 0x97;
pub const SWAP9: u16  = 0x98;
pub const SWAP10: u16 = 0x99;
pub const SWAP11: u16 = 0x9a;
pub const SWAP12: u16 = 0x9b;
pub const SWAP13: u16 = 0x9c;
pub const SWAP14: u16 = 0x9d;
pub const SWAP15: u16 = 0x9e;
pub const SWAP16: u16 = 0x9f;

// a0s: logging operations

macro_rules! dup {
    ($self: expr, $n: expr) => {{
        let stk = &mut $self.state.stack;
        let val = stk[$n];
        stk.push(val);
    }}
}

macro_rules! swap {
    ($self: expr, $n: expr) => {{
        let stk = &mut $self.state.stack;
        let tmp = stk[$n];
        stk[$n] = stk[0];
        stk[0] = tmp;
    }}
}

fn bool_to_u256(b: bool) -> U256 {
    if b { U256::one() } else { U256::zero() }
}

// Should these be 256 bit or smaller?
fn memory_expansion(s: U256, f: U256, l: U256) -> U256 {
    if l.is_zero() { s } else { max(s, (f + l) / U256::from(32)) }
}

fn addr_to_u256(&Address(bytes): &Address) -> U256 {
    return U256::from_big_endian(&bytes[0..20]);
}

impl VM {
    pub fn step(&mut self, op: Instruction) {
        match op {
            STOP => println!("halt!"),

            ADD => binary_op(&mut self.state.stack, Add::add),

            MUL => binary_op(&mut self.state.stack, Mul::mul),

            SUB => {
                let stk = &mut self.state.stack;
                let result = U256::overflowing_sub(stk[0], stk[1]).0;
                stk.pop();
                stk.pop();
                stk.push(result);
            }

            DIV => binary_op(&mut self.state.stack, |x, y| { x / y }),

            LT => binary_op(
                &mut self.state.stack,
                |x, y| bool_to_u256(x < y)
            ),

            GT => binary_op(
                &mut self.state.stack,
                |x, y| bool_to_u256(x > y)
            ),

            // XXX make signed
            SLT => binary_op(
                &mut self.state.stack,
                |x, y| bool_to_u256(x < y)
            ),

            // XXX make signed
            SGT => binary_op(
                &mut self.state.stack,
                |x, y| bool_to_u256(x < y)
            ),

            EQ => binary_op(
                &mut self.state.stack,
                |x, y| bool_to_u256(x == y)
            ),

            ISZERO => unary_op(
                &mut self.state.stack,
                |x| bool_to_u256(x.is_zero())
            ),

            AND => binary_op(&mut self.state.stack, BitAnd::bitand),

            OR  => binary_op(&mut self.state.stack, BitOr::bitor),

            XOR => binary_op(&mut self.state.stack, BitXor::bitxor),

            NOT => unary_op(&mut self.state.stack, Not::not),

//             BYTE => {
//                 let stt = self.state.borrow_mut();
//                 let mut stk = stt.stack.borrow_mut();
//                 let ix = stk[0].to_usize();
//                 let source = stk[1];
//                 stk.pop();
//                 stk.pop();
//                 stk.push(source.byte(ix));
//             }

//             SHA3 => {
//                 let mut hasher = Keccak256::default();
//                 let     stt = self.state.borrow_mut();
//                 let mut stk = stt.stack.borrow_mut();
//                 let start = stk[0];
//                 let end   = stk[1];
//                 let message = self.get_memory(start, end);
//                 hasher.input(message);
//                 let out = hasher.result();

//                 stk.pop();
//                 stk.pop();
//                 stk.push(out);
//                 stt.active_words = memory_expansion(stt.active_words, start, end);
//             }

            ADDRESS => self.state.stack.push(addr_to_u256(&self.env.owner)),

            // BALANCE

            ORIGIN => self.state.stack.push(addr_to_u256(&self.env.origin)),

            CALLER => self.state.stack.push(addr_to_u256(&self.env.caller)),

            CALLVALUE => self.state.stack.push(self.env.transaction_value),

//             CALLDATALOAD => {
//                 let ix = &mut self.state.stack[0];
//                 let data = self.env.data;
//                 // XXX default to 0 for index out of bounds
//                 let mut slice = data[ix..ix+32];
//                 self.state.stack.pop();
//                 self.state.stack.push(U256::from(slice));
//             }

            CALLDATASIZE =>
                self.state.stack.push(U256::from(self.env.data.len())),

            // CALLDATACOPY => {}

            POP => {
                self.state.stack.pop();
                return ();
            }

            PC => self.state.stack.push(self.state.pc),

            MSIZE => self.state.stack
                .push(U256::from(self.state.memory.len() * 32)),

            GAS => self.state.stack.push(self.state.gas_available),

            JUMPDEST => {}

            DUP1  => dup!(self, 1),
            DUP2  => dup!(self, 2),
            DUP3  => dup!(self, 3),
            DUP4  => dup!(self, 4),
            DUP5  => dup!(self, 5),
            DUP6  => dup!(self, 6),
            DUP7  => dup!(self, 7),
            DUP8  => dup!(self, 8),
            DUP9  => dup!(self, 9),
            DUP10 => dup!(self, 10),
            DUP11 => dup!(self, 11),
            DUP12 => dup!(self, 12),
            DUP13 => dup!(self, 13),
            DUP14 => dup!(self, 14),
            DUP15 => dup!(self, 15),
            DUP16 => dup!(self, 16),

            SWAP1  => swap!(self, 1),
            SWAP2  => swap!(self, 2),
            SWAP3  => swap!(self, 3),
            SWAP4  => swap!(self, 4),
            SWAP5  => swap!(self, 5),
            SWAP6  => swap!(self, 6),
            SWAP7  => swap!(self, 7),
            SWAP8  => swap!(self, 8),
            SWAP9  => swap!(self, 9),
            SWAP10 => swap!(self, 10),
            SWAP11 => swap!(self, 11),
            SWAP12 => swap!(self, 12),
            SWAP13 => swap!(self, 13),
            SWAP14 => swap!(self, 14),
            SWAP15 => swap!(self, 15),
            SWAP16 => swap!(self, 16),

            _    => println!("there"),
        }
    }
}

fn binary_op<F>(stk: &mut Vec<U256>, op: F)
where F: Fn(U256, U256) -> U256,
{
    let result = op(stk[0], stk[1]);
    stk.pop();
    stk.pop();
    stk.push(result);
}

fn unary_op<F>(stk: &mut Vec<U256>, op: F)
where F: Fn(U256) -> U256,
{
    let result = op(stk[0]);
    stk[0] = result;
}

#[cfg(test)]
mod tests {
    use *;

    #[test]
    fn it_works() {
        let g = U256::from(30000);
        let init_vm = VM {
            result: None,
            state: FrameState {
                gas_available: g,
                pc:            U256::zero(),
                memory:        Vec::new(),
                active_words:  U256::zero(),
                stack:         vec![U256::from(1), U256::from(2)],
            },
            env: Env {
                owner: Address([0; 20]),
                origin: Address([0; 20]),
                gas_price: U256::zero(),
                data: Vec::new(),
                caller: Address([0; 20]),
                transaction_value: U256::zero(),
                code: Vec::new(),
                header: Header {},
                depth: 0,
            }
        };

        let mut vm = init_vm.clone();
        vm.step(ADD);
        let stack_result = vm.state.stack[0];
        assert_eq!(stack_result.as_u32(), 3);

        let mut vm = init_vm.clone();
        vm.step(MUL);
        let stack_result = vm.state.stack[0];
        assert_eq!(stack_result.as_u32(), 2);

        let mut vm = init_vm.clone();
        vm.step(SUB);
        let stack_result = vm.state.stack[0];
        assert_eq!(
            stack_result.low_u64(),
            U256::overflowing_sub(U256::one(), U256::from(2)).0.low_u64()
        );

//         let mut vm = init_vm.clone();
//         vm.step(DIV);
//         let state = vm.state.borrow();
//         let stack_result = state.stack.borrow()[0];
//         assert_eq!(stack_result.as_u32(), 2);

        let mut vm = init_vm.clone();
        vm.step(GT);
        let stack_result = vm.state.stack[0];
        assert_eq!(stack_result.as_u32(), 0);

        let mut vm = init_vm.clone();
        vm.step(LT);
        let stack_result = vm.state.stack[0];
        assert_eq!(stack_result.as_u32(), 1);
    }
}
