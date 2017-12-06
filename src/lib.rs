extern crate core;
extern crate num;

use num::BigUint;
use std::fmt;
use std::cell::RefCell;
use std::borrow::BorrowMut;
use core::clone::Clone;
// use core::u32::wrapping_sub;

const homestead: u32 = 1150000;

type w128 = (u64, u64);
type w160 = (u64, u64, u32);
type w256 = (u64, u64, u64, u64);

type Instruction = u16;

#[derive(PartialEq, Debug, Clone)]
struct k256(w256);

#[derive(PartialEq, Debug, Clone)]
struct address(w160);

#[derive(PartialEq, Debug, Clone)]
enum VMResult {
    vmFailure,
    vmSuccess,
}

#[derive(PartialEq, Debug, Clone)]
struct FrameState {
    // contract
    //     codeContract
    //     code
    //     pc
    stack: RefCell<Vec<u32>>,
    //     memory
    //     memorySize
    //     calldata
    //     callvalue
    //     caller
}

#[derive(PartialEq, Debug, Clone)]
struct AccountState {
    nonce: u32,
    balance: u32,
    storageRoot: k256,
    codeHash: k256,
}

#[derive(PartialEq, Debug, Clone)]
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

#[derive(PartialEq, Debug, Clone)]
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

impl fmt::Debug for Bloom {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bloom")
    }
}

impl Clone for Bloom {
    fn clone(&self) -> Bloom { Bloom(self.0) }
}

#[derive(PartialEq, Debug, Clone)]
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

#[derive(PartialEq, Debug, Clone)]
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

#[derive(PartialEq, Debug, Clone)]
struct TransactionReceipt {
    // state:
    gasUsed: u32,
    logs: Vec<Log>,
    bloom: Bloom,
}

#[derive(PartialEq, Debug, Clone)]
struct Contract {
    // callerAddress: address,
    // caller
}

#[derive(PartialEq, Debug, Clone)]
struct VM {
    result: RefCell<Option<VMResult>>,
    state:  RefCell<FrameState>,
    // frames: Array<Frame>,
    // env: Env,
    // block
}

const STOP: u16 = 0x00;
const ADD: u16 = 0x01;
const MUL: u16 = 0x02;
const SUB: u16 = 0x03;
const DIV: u16 = 0x04;

const LT: u16 = 0x10;
const GT: u16 = 0x11;
const SLT: u16 = 0x12;
const SGT: u16 = 0x13;
const EQ: u16 = 0x14;
const ISZERO: u16 = 0x15;
const AND: u16 = 0x16;
const OR: u16 = 0x17;
const XOR: u16 = 0x18;
const NOT: u16 = 0x19;

impl VM {
    fn step(&mut self, op: Instruction) {
        match op {
            STOP => println!("halt!"),

            ADD => {
                let stt = self.state.borrow_mut();
                binary_op(&stt.stack, |x: u32, y: u32| { x + y });
            }

            MUL => {
                let stt = self.state.borrow_mut();
                binary_op(&stt.stack, |x: u32, y: u32| { x * y });
            }

            SUB => {
                let stt = self.state.borrow_mut();
                // TODO: all this arithmetic should be mod 256. also use wrapping for other ops.
                binary_op(&stt.stack, u32::wrapping_sub );
            }

            DIV => {
                let stt = self.state.borrow_mut();
                binary_op(&stt.stack, |x: u32, y: u32| { x / y });
            }

            LT => binary_op(
                &self.state.borrow_mut().stack,
                |x: u32, y: u32| { if x < y { 1 } else { 0 } }
            ),

            GT => binary_op(
                &self.state.borrow_mut().stack,
                |x: u32, y: u32| { if x > y { 1 } else { 0 } }
            ),

//             SLT => binary_op(
//                 &self.state.borrow_mut().stack,
//                 |x: u32, y: u32| { if x < y { 1 } else { 0 } }
//             ),

//             SGT => binary_op(
//                 &self.state.borrow_mut().stack,
//                 |x: u32, y: u32| { if x < y { 1 } else { 0 } }
//             ),

            EQ => binary_op(
                &self.state.borrow_mut().stack,
                |x: u32, y: u32| { if x == y { 1 } else { 0 } }
            ),

            ISZERO => unary_op(
                &self.state.borrow_mut().stack,
                |x: u32| { if x == 0 { 1 } else { 0 } }
            ),

            AND => binary_op(
                &self.state.borrow_mut().stack,
                |x: u32, y: u32| { x & y }
            ),

            OR => binary_op(
                &self.state.borrow_mut().stack,
                |x: u32, y: u32| { x | y }
            ),

            XOR => binary_op(
                &self.state.borrow_mut().stack,
                |x: u32, y: u32| { x ^ y }
            ),

            NOT => unary_op(
                &self.state.borrow_mut().stack,
                |x: u32| { !x }
            ),

            _    => println!("there"),
        }
    }
}

fn binary_op<F>(stk_cell: &RefCell<Vec<u32>>, op: F)
where F: Fn(u32, u32) -> u32,
{
    let mut stk = stk_cell.borrow_mut();
    let result = op(stk[0], stk[1]);
    stk.pop();
    stk.pop();
    stk.push(result);
}

fn unary_op<F>(stk_cell: &RefCell<Vec<u32>>, op: F)
where F: Fn(u32) -> u32,
{
    let mut stk = stk_cell.borrow_mut();
    let result = op(stk[0]);
    stk[0] = result;
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::borrow::Borrow;
    use *;

    #[test]
    fn it_works() {
        let init_vm = VM {
            result: RefCell::new(None),
            state: RefCell::new(FrameState {
                stack: RefCell::new(vec![1,2]),
            }),
        };

        let mut vm = init_vm.clone();
        vm.step(ADD);
        let state = vm.state.borrow();
        let stack_result = state.stack.borrow()[0];
        assert_eq!(stack_result, 3);

        let mut vm = init_vm.clone();
        vm.step(MUL);
        let state = vm.state.borrow();
        let stack_result = state.stack.borrow()[0];
        assert_eq!(stack_result, 2);

        let mut vm = init_vm.clone();
        vm.step(SUB);
        let state = vm.state.borrow();
        let stack_result = state.stack.borrow()[0];
        assert_eq!(stack_result, u32::wrapping_sub(1, 2));

//         let mut vm = init_vm.clone();
//         vm.step(DIV);
//         let state = vm.state.borrow();
//         let stack_result = state.stack.borrow()[0];
//         assert_eq!(stack_result, 2);

        let mut vm = init_vm.clone();
        vm.step(GT);
        let state = vm.state.borrow();
        let stack_result = state.stack.borrow()[0];
        assert_eq!(stack_result, 0);

        let mut vm = init_vm.clone();
        vm.step(LT);
        let state = vm.state.borrow();
        let stack_result = state.stack.borrow()[0];
        assert_eq!(stack_result, 1);
    }
}
