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

type Instruction = u8;

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
pub struct Stack(Vec<U256>);

impl Stack {
    fn push(&mut self, value: U256) {
        self.0.push(value);
    }

    fn pop(&mut self, times: usize) {
        for i in 0..times {
            self.0.pop();
        }
    }

    fn new() -> Stack {
        return Stack(Vec::new());
    }
}

impl Index<usize> for Stack {
    type Output = U256;

    fn index<'a>(&'a self, index: usize) -> &'a U256 {
        let veclen = self.0.len();
        return &self.0[veclen - index - 1];
    }
}

impl IndexMut<usize> for Stack {
    fn index_mut(&mut self, index: usize) -> &mut U256 {
        let veclen = self.0.len();
        return &mut self.0[veclen - index - 1];
    }
}

// Mostly from 9.4.1: Machine State
#[derive(PartialEq, Clone)]
pub struct FrameState {
    // contract
    code:          Vec<u8>, // XXX is code part of FrameState or Env?
    gas_available: U256,
    pc:            usize, // U256,
    memory:        Vec<u8>,
    active_words:  U256,
    stack:         Stack,
    //     memorySize
    //     calldata
    //     callvalue
    //     caller
}

impl FrameState {
    pub fn m_store(&mut self, loc: usize, word: U256) {
        let mut bytes: [u8; 32] = [0; 32];
        word.to_big_endian(&mut bytes);

        for i in self.memory.len() .. loc + 32 {
            self.memory.push(0);
        }

        for (i, byte) in bytes.iter().enumerate() {
            self.memory[loc + i] = *byte;
        }
        self.active_words = self.active_words.max(U256::from((loc + 32) / 32));
    }

    pub fn m_store8(&mut self, loc: usize, byte: u8) {
        for i in self.memory.len() .. loc + 1 {
            self.memory.push(0);
        }

        self.memory[loc] = byte;
        self.active_words = self.active_words.max(U256::from((loc + 1) / 32));
    }

    pub fn m_load(&mut self, loc: usize) -> U256 {
        if self.memory.len() < loc + 32 {
            self.memory.resize(loc + 32, 0);
        }

        self.active_words = self.active_words.max(U256::from((loc + 32) / 32));
        return U256::from_big_endian(&self.memory[loc..loc+32]);
    }
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

// for now, filter down to only the fields we actually use
#[derive(PartialEq, Clone)]
pub struct Block {
    // parent_hash: K256,
    // ommers_hash: K256,
    beneficiary: Address,
    // state_root: K256,
    // transactions_root: K256,
    // receipts_root: K256,
    // logs_bloom: Bloom,
    difficulty: BigUint,
    number: BigUint,
    gas_limit: BigUint,
    // gas_used: BigUint,
    timestamp: BigUint,
    // extra_data: Vec<u8>,
    // mix_hash: K256,
    // nonce: u64,
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
    block: Block,
}

// 0s: stop and arithmetic operations
pub const STOP: u8 = 0x00;
pub const ADD:  u8 = 0x01;
pub const MUL:  u8 = 0x02;
pub const SUB:  u8 = 0x03;
pub const DIV:  u8 = 0x04;

// 10s: comparison & bitwise logic operations
pub const LT:     u8 = 0x10;
pub const GT:     u8 = 0x11;
pub const SLT:    u8 = 0x12;
pub const SGT:    u8 = 0x13;
pub const EQ:     u8 = 0x14;
pub const ISZERO: u8 = 0x15;
pub const AND:    u8 = 0x16;
pub const OR:     u8 = 0x17;
pub const XOR:    u8 = 0x18;
pub const NOT:    u8 = 0x19;
pub const BYTE:   u8 = 0x1a;

// 20s: sha3
pub const SHA3: u8    = 0x20;

// 30s: environmental information
pub const ADDRESS:      u8 = 0x30;
pub const BALANCE:      u8 = 0x31;
pub const ORIGIN:       u8 = 0x32;
pub const CALLER:       u8 = 0x33;
pub const CALLVALUE:    u8 = 0x34;
pub const CALLDATALOAD: u8 = 0x35;
pub const CALLDATASIZE: u8 = 0x36;
pub const CALLDATACOPY: u8 = 0x37;
pub const CODESIZE:     u8 = 0x38;
pub const CODECOPY:     u8 = 0x39;
pub const GASPRICE:     u8 = 0x3a;
pub const EXTCODESIZE:  u8 = 0x3b;
pub const EXTCODECOPY:  u8 = 0x3c;

// 40s: block information
pub const BLOCKHASH:  u8 = 0x40;
pub const COINBASE:   u8 = 0x41;
pub const TIMESTAMP:  u8 = 0x42;
pub const NUMBER:     u8 = 0x43;
pub const DIFFICULTY: u8 = 0x44;
pub const GASLIMIT:   u8 = 0x45;

// 50s: stack, memory, storage, and flow operations
pub const POP:      u8 = 0x50;
pub const MLOAD:    u8 = 0x51;
pub const MSTORE:   u8 = 0x52;
pub const MSTORE8:  u8 = 0x53;
pub const JUMP:     u8 = 0x54;
pub const JUMPI:    u8 = 0x55;
pub const PC:       u8 = 0x58;
pub const MSIZE:    u8 = 0x59;
pub const GAS:      u8 = 0x5a;
pub const JUMPDEST: u8 = 0x5b;

pub const PUSH1:  u8 = 0x60;
pub const PUSH2:  u8 = 0x61;
pub const PUSH3:  u8 = 0x62;
pub const PUSH4:  u8 = 0x63;
pub const PUSH5:  u8 = 0x64;
pub const PUSH6:  u8 = 0x65;
pub const PUSH7:  u8 = 0x66;
pub const PUSH8:  u8 = 0x67;
pub const PUSH9:  u8 = 0x68;
pub const PUSH10: u8 = 0x69;
pub const PUSH11: u8 = 0x6a;
pub const PUSH12: u8 = 0x6b;
pub const PUSH13: u8 = 0x6c;
pub const PUSH14: u8 = 0x6d;
pub const PUSH15: u8 = 0x6e;
pub const PUSH16: u8 = 0x6f;
pub const PUSH17: u8 = 0x70;
pub const PUSH18: u8 = 0x71;
pub const PUSH19: u8 = 0x72;
pub const PUSH20: u8 = 0x73;
pub const PUSH21: u8 = 0x74;
pub const PUSH22: u8 = 0x75;
pub const PUSH23: u8 = 0x76;
pub const PUSH24: u8 = 0x77;
pub const PUSH25: u8 = 0x78;
pub const PUSH26: u8 = 0x79;
pub const PUSH27: u8 = 0x7a;
pub const PUSH28: u8 = 0x7b;
pub const PUSH29: u8 = 0x7c;
pub const PUSH30: u8 = 0x7d;
pub const PUSH31: u8 = 0x7e;
pub const PUSH32: u8 = 0x7f;

// 60s & 70s: push operations
// 80s: duplication operations
pub const DUP1: u8  = 0x80;
pub const DUP2: u8  = 0x81;
pub const DUP3: u8  = 0x82;
pub const DUP4: u8  = 0x83;
pub const DUP5: u8  = 0x84;
pub const DUP6: u8  = 0x85;
pub const DUP7: u8  = 0x86;
pub const DUP8: u8  = 0x87;
pub const DUP9: u8  = 0x88;
pub const DUP10: u8 = 0x89;
pub const DUP11: u8 = 0x8a;
pub const DUP12: u8 = 0x8b;
pub const DUP13: u8 = 0x8c;
pub const DUP14: u8 = 0x8d;
pub const DUP15: u8 = 0x8e;
pub const DUP16: u8 = 0x8f;

// 90s: exchange operations
pub const SWAP1: u8  = 0x90;
pub const SWAP2: u8  = 0x91;
pub const SWAP3: u8  = 0x92;
pub const SWAP4: u8  = 0x93;
pub const SWAP5: u8  = 0x94;
pub const SWAP6: u8  = 0x95;
pub const SWAP7: u8  = 0x96;
pub const SWAP8: u8  = 0x97;
pub const SWAP9: u8  = 0x98;
pub const SWAP10: u8 = 0x99;
pub const SWAP11: u8 = 0x9a;
pub const SWAP12: u8 = 0x9b;
pub const SWAP13: u8 = 0x9c;
pub const SWAP14: u8 = 0x9d;
pub const SWAP15: u8 = 0x9e;
pub const SWAP16: u8 = 0x9f;

// a0s: logging operations

// Should these be 256 bit or smaller?
fn memory_expansion(s: U256, f: U256, l: U256) -> U256 {
    if l.is_zero() { s } else { max(s, (f + l) / U256::from(32)) }
}

fn bool_to_u256(b: bool) -> U256 {
    if b { U256::one() } else { U256::zero() }
}

fn addr_to_u256(&Address(bytes): &Address) -> U256 {
    return U256::from_big_endian(&bytes[0..20]);
}

fn big_to_u256(big: &BigUint) -> U256 {
    let bytes = big.to_bytes_be();
    return U256::from_big_endian(&bytes);
}

pub enum InstructionResult {
    Normal,
    Halt,
}

impl VM {
    pub fn step(&mut self) -> InstructionResult {
        use InstructionResult::*;

        let pc = self.state.pc;
        let op = self.state.code[pc];

        if op >= PUSH1 && op <= PUSH32 {
            let n     = usize::from(op - PUSH1 + 1);
            let stk   = &mut self.state.stack;
            let pc    = self.state.pc;
            let val1  = &self.state.code[pc+1..pc+n+1];
            let val   = U256::from_big_endian(val1);
            self.state.pc += n; // pc will also be incremented by one
            stk.push(val);
        } else if op >= DUP1 && op <= DUP16 {
            let n   = usize::from(op - DUP1 + 1);
            let stk = &mut self.state.stack;
            let val = stk[n];
            stk.push(val);
        } else if op >= SWAP1 && op <= SWAP16 {
            let n   = usize::from(op - SWAP1 + 1);
            let stk = &mut self.state.stack;
            let tmp = stk[n];
            stk[n]  = stk[0];
            stk[0]  = tmp;
        } else {

        match op {
            STOP => { return Halt; }

            ADD => binary_op(&mut self.state.stack, Add::add),

            MUL => binary_op(&mut self.state.stack, Mul::mul),

            SUB => {
                let stk = &mut self.state.stack;
                let result = U256::overflowing_sub(stk[0], stk[1]).0;
                stk.pop(2);
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
//                 stk.pop(2);
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

//                 stk.pop(2);
//                 stk.push(out);
//                 stt.active_words = memory_expansion(stt.active_words, start, end);
//             }

            ADDRESS => self.state.stack.push(addr_to_u256(&self.env.owner)),

//             BALANCE => {
//                 let addr =
//                 self.state
//             }

            ORIGIN => self.state.stack.push(addr_to_u256(&self.env.origin)),

            CALLER => self.state.stack.push(addr_to_u256(&self.env.caller)),

            CALLVALUE => self.state.stack.push(self.env.transaction_value),

//             CALLDATALOAD => {
//                 let ix = &mut self.state.stack[0];
//                 let data = self.env.data;
//                 // XXX default to 0 for index out of bounds
//                 let mut slice = data[ix..ix+32];
//                 self.state.stack.pop(1);
//                 self.state.stack.push(U256::from(slice));
//             }

            CALLDATASIZE =>
                self.state.stack.push(U256::from(self.env.data.len())),

            // CALLDATACOPY => {}
            // CODESIZE => {}
            // CODECOPY => {}
            // GASPRICE => {}
            // EXTCODESIZE => {}
            // EXTCODECOPY => {}

            BLOCKHASH => println!("unimplemented: BLOCKHASH"),
            COINBASE =>
                self.state.stack.push(addr_to_u256(&self.block.beneficiary)),
            TIMESTAMP =>
                self.state.stack.push(big_to_u256(&self.block.timestamp)),
            NUMBER =>
                self.state.stack.push(big_to_u256(&self.block.number)),
            DIFFICULTY =>
                self.state.stack.push(big_to_u256(&self.block.difficulty)),
            GASLIMIT =>
                self.state.stack.push(big_to_u256(&self.block.gas_limit)),

            POP => {
                self.state.stack.pop(1);
                return Normal;
            }

            MLOAD => {
                let loc = self.state.stack[0].low_u32() as usize;
                self.state.stack[0] = self.state.m_load(loc);
            }

            MSTORE => {
                let loc = self.state.stack[0].low_u32() as usize;
                let val = self.state.stack[1];

                self.state.m_store(loc, val);

                self.state.stack.pop(2);
            }

            MSTORE8 => {
                let loc = self.state.stack[0].low_u32() as usize;
                let val = self.state.stack[1].low_u32() as u8;

                self.state.m_store8(loc, val);

                self.state.stack.pop(2);
            }

            JUMP => {
                let loc = self.state.stack[0];
                self.state.stack.pop(1);
                self.state.pc = loc.low_u64() as usize;
                return Normal;
            },

            JUMPI => {
                let loc = self.state.stack[0];
                let b   = self.state.stack[1];
                self.state.stack.pop(2);

                if b != U256::zero() {
                    self.state.pc = loc.low_u64() as usize;
                    return Normal;
                }
            },

            PC => self.state.stack.push(U256::from(pc)),

            MSIZE => self.state.stack
                .push(U256::from(self.state.memory.len() * 32)),

            GAS => self.state.stack.push(self.state.gas_available),

            JUMPDEST => {}

            _    => println!("unimplemented instruction: {}", op),
        }
        }

        self.state.pc += 1;
        return Normal;
    }

    pub fn run(&mut self) {
        while self.state.pc < self.state.code.len() {
            self.step();
        }
    }
}

fn binary_op<F>(stk: &mut Stack, op: F)
where F: Fn(U256, U256) -> U256,
{
    let result = op(stk[0], stk[1]);
    stk.pop(2);
    stk.push(result);
}

fn unary_op<F>(stk: &mut Stack, op: F)
where F: Fn(U256) -> U256,
{
    let result = op(stk[0]);
    stk[0] = result;
}

fn init_vm(code: &Vec<u8>, gas: u32) -> VM {
    VM {
        result: None,
        state: FrameState {
            code:          code.clone(),
            gas_available: U256::from(gas),
            pc:            0,
            memory:        Vec::new(),
            active_words:  U256::zero(),
            stack:         Stack::new(),
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
        },
        block: Block {
            beneficiary: Address([0; 20]),
            difficulty: BigUint::new(Vec::new()),
            number: BigUint::new(Vec::new()),
            gas_limit: BigUint::new(Vec::new()),
            timestamp: BigUint::new(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use *;

    #[test]
    fn it_works() {
        let mut vm = init_vm(&vec![PUSH1, 1, PUSH1, 2, ADD], 100);
        vm.run();
        assert_eq!(vm.state.stack[0].as_u32(), 3);

        let mut vm = init_vm(&vec![PUSH1, 1, PUSH1, 2, MUL], 100);
        vm.run();
        assert_eq!(vm.state.stack[0].as_u32(), 2);

        let mut vm = init_vm(&vec![PUSH1, 1, PUSH1, 2, SUB], 100);
        vm.run();
        assert_eq!(vm.state.stack[0].as_u32(), 1);

        let mut vm = init_vm(&vec![PUSH1, 1, PUSH1, 2, DIV], 100);
        vm.run();
        assert_eq!(vm.state.stack[0].as_u32(), 2);

        let mut vm = init_vm(&vec![PUSH1, 2, PUSH1, 1, GT], 100);
        vm.run();
        assert_eq!(vm.state.stack[0].as_u32(), 0);

        let mut vm = init_vm(&vec![PUSH1, 2, PUSH1, 1, LT], 100);
        vm.run();
        assert_eq!(vm.state.stack[0].as_u32(), 1);

        // store 123 at 200, then load it back
        // 7 words = 200 / 32
        let mut vm = init_vm(&vec![PUSH1, 123, PUSH1, 200, MSTORE, PUSH1, 200, MLOAD], 100);
        vm.run();
        assert_eq!(vm.state.stack[0].as_u32(), 123);
        assert_eq!(vm.state.active_words.as_u32(), 7);

        let mut vm = init_vm(&vec![PUSH1, 123, PUSH1, 231, MSTORE8, PUSH1, 200, MLOAD], 100);
        vm.run();
        assert_eq!(vm.state.stack[0].as_u32(), 123);
        assert_eq!(vm.state.active_words.as_u32(), 7);

        let mut vm = init_vm(&vec![PUSH1, 20, JUMP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, PUSH1, 123], 100);
        vm.run();
        assert_eq!(vm.state.stack[0].as_u32(), 123);
    }
}
