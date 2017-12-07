extern crate bigint;
extern crate core;
extern crate num;
extern crate sha3;

use core::clone::Clone;
use core::ops::*;
use std::cmp::max;
use bigint::uint::{U128,U256};
use num::BigUint;
use sha3::{Digest, Keccak256};

const homestead: u32 = 1150000;

type w128 = U128;
type w160 = (U128, u32);
type w256 = U256;

type Instruction = u16;

#[derive(PartialEq, Clone)]
struct k256(w256);

#[derive(PartialEq, Clone)]
struct address(w160);

#[derive(PartialEq, Clone)]
enum VMResult {
    vmFailure,
    vmSuccess,
}

#[derive(PartialEq, Clone)]
struct FrameState {
    // contract
    //     codeContract
    gas_available: U256,
    pc:            U256,
    memory:        Vec<u8>,
    active_words:  U256,
    stack:         Vec<w256>,
    //     memory
    //     memorySize
    //     calldata
    //     callvalue
    //     caller
}

#[derive(PartialEq, Clone)]
struct AccountState {
    nonce: u32,
    balance: u32,
    storageRoot: k256,
    codeHash: k256,
}

#[derive(PartialEq, Clone)]
struct TransactionCommon {
    nonce: u64,
    gasPrice: BigUint,
    gasLimit: BigUint,
    to: w160,
    value: BigUint,
    v: BigUint,
    r: BigUint,
    s: BigUint,
}

#[derive(PartialEq, Clone)]
enum Transaction {
    creationTransaction { common: TransactionCommon, init: Option<Vec<u8>> },
    callTransaction { common: TransactionCommon, data: Vec<u8> },
}

struct Bloom([u8; 256]);

impl PartialEq for Bloom {
    fn eq(&self, other: &Bloom) -> bool {
        false
    }
}

// impl Debug for Bloom {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "Bloom")
//     }
// }

impl Clone for Bloom {
    fn clone(&self) -> Bloom { Bloom(self.0) }
}

#[derive(PartialEq, Clone)]
struct Block {
    parentHash: k256,
    ommersHash: k256,
    beneficiary: address,
    stateRoot: k256,
    transactionsRoot: k256,
    receiptsRoot: k256,
    logsBloom: Bloom,
    difficulty: BigUint,
    number: BigUint,
    gasLimit: BigUint,
    gasUsed: BigUint,
    timestamp: BigUint,
    extraData: Vec<u8>,
    mixHash: k256,
    nonce: u64,
}

#[derive(PartialEq, Clone)]
struct Log {
    address: address,
    topics: Vec<k256>,
    data: Vec<u8>,
    blockNumber: u64,
    txHash: k256,
    txIndex: u32,
    blockHash: k256,
    index: u32,
    removed: bool,
}

#[derive(PartialEq, Clone)]
struct TransactionReceipt {
    // state:
    gasUsed: u32,
    logs: Vec<Log>,
    bloom: Bloom,
}

#[derive(PartialEq, Clone)]
struct Contract {
    // callerAddress: address,
    // caller
}

#[derive(PartialEq, Clone)]
struct VM {
    result: Option<VMResult>,
    state:  FrameState,
    // frames: Array<Frame>,
    // env: Env,
    // block
}

const STOP: u16 = 0x00;
const ADD: u16  = 0x01;
const MUL: u16  = 0x02;
const SUB: u16  = 0x03;
const DIV: u16  = 0x04;

const LT: u16     = 0x10;
const GT: u16     = 0x11;
const SLT: u16    = 0x12;
const SGT: u16    = 0x13;
const EQ: u16     = 0x14;
const ISZERO: u16 = 0x15;
const AND: u16    = 0x16;
const OR: u16     = 0x17;
const XOR: u16    = 0x18;
const NOT: u16    = 0x19;
const BYTE: u16    = 0x1a;
const SHA3: u16    = 0x20;

const DUP1: u16  = 0x80;
const DUP2: u16  = 0x81;
const DUP3: u16  = 0x82;
const DUP4: u16  = 0x83;
const DUP5: u16  = 0x84;
const DUP6: u16  = 0x85;
const DUP7: u16  = 0x86;
const DUP8: u16  = 0x87;
const DUP9: u16  = 0x88;
const DUP10: u16 = 0x89;
const DUP11: u16 = 0x8a;
const DUP12: u16 = 0x8b;
const DUP13: u16 = 0x8c;
const DUP14: u16 = 0x8d;
const DUP15: u16 = 0x8e;
const DUP16: u16 = 0x8f;

const SWAP1: u16  = 0x90;
const SWAP2: u16  = 0x91;
const SWAP3: u16  = 0x92;
const SWAP4: u16  = 0x93;
const SWAP5: u16  = 0x94;
const SWAP6: u16  = 0x95;
const SWAP7: u16  = 0x96;
const SWAP8: u16  = 0x97;
const SWAP9: u16  = 0x98;
const SWAP10: u16 = 0x99;
const SWAP11: u16 = 0x9a;
const SWAP12: u16 = 0x9b;
const SWAP13: u16 = 0x9c;
const SWAP14: u16 = 0x9d;
const SWAP15: u16 = 0x9e;
const SWAP16: u16 = 0x9f;

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

impl VM {
    fn step(&mut self, op: Instruction) {
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

fn binary_op<F>(stk: &mut Vec<w256>, op: F)
where F: Fn(w256, w256) -> w256,
{
    let result = op(stk[0], stk[1]);
    stk.pop();
    stk.pop();
    stk.push(result);
}

fn unary_op<F>(stk: &mut Vec<w256>, op: F)
where F: Fn(w256) -> w256,
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
