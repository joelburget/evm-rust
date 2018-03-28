
pub mod json {
    use bigint::uint::U256;
    use num::BigUint;
    use Address;
    use K256;
    use Stack;
    use FrameState;
    use VM;
    use Env;
    use Header;
    use Block;
    use std::fs::File;
    use ::serde_json;
    use std::num::ParseIntError;
    use std::str::FromStr;
    use std::io::Read;
    use std::convert::From;
    use std::convert::AsMut;
    

    pub fn load_test(filename: &str) -> (VM,VM) {
        let mut f = File::open(filename).expect("Could not find file");
        let mut test_json = String::new();
        f.read_to_string(&mut test_json).expect("Error reading file");

        let parsed_test: Test = serde_json::from_str(&test_json).unwrap();
        (init_vm(&parsed_test), final_vm(&parsed_test))
    }

    /// These structs represent the test format described in
    /// http://ethereum-tests.readthedocs.io/en/latest/test_types/vm_tests.html
    
    #[derive(Deserialize)]
    struct Test {
        _info: serde_json::Value,
        env: TestEnv,
        pre: serde_json::Value,
        exec: TestExec,
        gas: String, //GAS REMAINING AT END OF EXECUTION
        logs: String,
        out: String,
        post: serde_json::Value, 
        callcreates: serde_json::Value,
    }

    #[derive(Deserialize)]
    struct TestEnv {
        currentCoinbase: String, 
        currentDifficulty: String, 
        currentGasLimit: String,
        currentNumber: String,
        currentTimestamp: String,
        //XXX previousHash: String,
    }
    
    #[derive(Deserialize)]
    struct TestExec {
        address: String,
        origin: String,
        caller: String,
        value: String, 
        data: String,
        code: String,
        gasPrice: String, 
        gas: String,
    }
    
    #[derive(Deserialize)]
    struct TestAccount {
        balance: String,
        nonce: String,
        code: String,
        storage: String,
    }
    
    #[derive(Deserialize)]
    struct Test1 {
        add0: Test,
    }
    
    fn hexstr_to_vec(v: &str) -> Vec<u8> {
        let v_bytes = &v.as_bytes()[2..];
        v_bytes.to_vec()
    }

    fn hexstr_to_address(addr: &str) -> Address {
        let addr_bytes = &addr.as_bytes()[2..];
        Address(clone_into_array(addr_bytes))
    }

    fn hexstr_to_u256(string: &str) -> U256 {
        let str_arr: [u8; 32] = clone_into_array(&string.as_bytes()[2..]);
        From::from(str_arr)
    }

    //fn hexstr_to_biguint(biguint: &str) -> BigUint {
    //    let biguint_bytes = &biguint.as_bytes()[2..];
    //    from_bytes_be(biguint_bytes)
    //}

    // Found at https://stackoverflow.com/questions/25428920/how-to-get-a-slice-as-an-array-in-rust
    fn clone_into_array<A, T>(slice: &[T]) -> A
    where A: Sized + Default + AsMut<[T]>,
          T: Clone
    {
        let mut a = Default::default();
        <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
        a
    }
    
    //NEED TO WIRE THESE VALS INTO THE VM:
    //unused from Test: pre, post, gas (at end), logs, out, callcreates
    //unused from TestEnv: currentCoinbase
    //unused from TestAccount: all (need to use pre/post)

    //The initial VM state for a test
    fn init_vm(test: &Test) -> VM {
        VM {
            result: None,
            state: FrameState {
                code: hexstr_to_vec(&test.exec.code),
                gas_available: hexstr_to_u256(&test.exec.gas),
                pc: 0,
                memory: Vec::new(),
                active_words: U256::zero(),
                stack: Stack::new(),
            },
            env: Env {
                owner: hexstr_to_address(&test.exec.address),
                origin: hexstr_to_address(&test.exec.origin),
                gas_price: hexstr_to_u256(&test.exec.gasPrice),
                data: hexstr_to_vec(&test.exec.data),
                caller: hexstr_to_address(&test.exec.caller),
                transaction_value: hexstr_to_u256(&test.exec.value),
                code: hexstr_to_vec(&test.exec.code),
                header: Header {},
                depth: 0,
            },
            //XXX - This can be sorted out once the BigUint vs U256 thing is figured out
            block: Block {
                beneficiary: Address([0;20]),
                difficulty: U256::one(),
                number: U256::one(),
                gas_limit: U256::one(),
                timestamp: U256::one(),
            }
        }           
    }

    //What the final VM state of a test should be
    fn final_vm(test: &Test) -> VM {
        VM {
            result: None,
            state: FrameState {
                code: hexstr_to_vec(&test.exec.code),
                gas_available: hexstr_to_u256(&test.gas),
                pc: 0, //XXX this is not tracked in the json tests so we should just default to the end PC
                memory: Vec::new(), //XXX 
                active_words: U256::zero(), //XXX
                stack: Stack::new(), //XXX again, not tracked in the json
            },
            env: Env {
                owner: hexstr_to_address(&test.exec.address),
                origin: hexstr_to_address(&test.exec.origin),
                gas_price: hexstr_to_u256(&test.exec.gasPrice),
                data: hexstr_to_vec(&test.exec.data),
                caller: hexstr_to_address(&test.exec.caller),
                transaction_value: hexstr_to_u256(&test.exec.value),
                code: hexstr_to_vec(&test.exec.code),
                header: Header {},
                depth: 0,
            },
            //XXX - This can be sorted out once the BigUint vs U256 thing is figured out
            block: Block {
                beneficiary: Address([0;20]),
                difficulty: U256::one(),
                number: U256::one(), 
                gas_limit: U256::one(),
                timestamp: U256::one(),
            }
        }  
    }
}
