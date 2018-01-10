macro_rules! no_children {
    () => ([
        None, None, None, None,
        None, None, None, None,
        None, None, None, None,
        None, None, None, None
    ])
}

pub mod trie {
    use bigint::uint::U256;
    use nibble::{NibVec, NibSliceExt, u4lo, u4, get_nib};
    use nibble::common::get_nib;
    use num::traits::WrappingAdd;
    use num::{One,FromPrimitive};
    use sha3::{Digest, Keccak256};
    use self::TrieNode::*;
    use core::cmp::min;


    #[derive(Debug, Clone)]
    pub enum TrieNode {
        /// A two-item structure:
        /// * the nibbles in the key not already accounted for by the accumulation of keys and
        ///   branches traversed from the root
        ///   - hex-prefix encoding is used with the second parameter *true*
        /// * data at the leaf
        Leaf {
            nibbles: NibVec,
            data: NibVec,
        },
        /// A two-item structure:
        /// * a series of nibbles of size greater than one that are shared by at least two distinct
        /// keys past the accumulation of nibbles keys and branches as traversed from the root
        ///   - hex-prefix encoding is used with the second parameter *false*
        /// * data at the extension
        Extension {
            nibbles: NibVec,
            data: NibVec,
        },
        /// A 17-item structure whose first sixteen items correspond to each of the sixteen
        /// possible nibble values for the keys at this point in their traversal. The 17th item is
        /// used in the case of this being a terminator node and thus a key being ended at this
        /// point in its traversal.
        Branch {
            children: [Option<Box<TrieNode>>; 16],
            data: Option<NibVec>,
        },
    }

    impl TrieNode {
        pub fn update(self, path: NibVec, value: NibVec) -> TrieNode {
            match self {
                Leaf { nibbles, data } => {
                    // find common prefix
                    let cur_slice = nibbles.as_slice();
                    let new_slice = path.as_slice();
                    let iter_count = min(nibbles.len(), path.len());
                    let mut prefix_len: usize = 0;

                    for i in 0..iter_count {
                        if cur_slice.get(i).to_lo() != new_slice.get(i).to_lo() {
                            break;
                        }
                        prefix_len += 1;
                    }

                    println!("prefix_len: {}, nibbles.len(): {}, path.len(): {}", prefix_len, nibbles.len(), path.len());
                    let prefix = nibbles.slice(0, prefix_len);
                    let cur_extra = nibbles.slice(prefix_len, nibbles.len());
                    let new_extra = path.slice(prefix_len, path.len());

                    println!("prefix: {:?}, cur_extra: {:?}, new_extra: {:?}", prefix, cur_extra, new_extra);
                    println!("prefix_len: {}", prefix_len);
                    if cur_extra.len() == 0 && new_extra.len() == 0 {
                        println!("keys were the same");
                        // TODO: handle inner case:
                        // if not is_inner:
                        println!("not an extension node");
                        return Leaf {
                            nibbles: prefix,
                            data: value,
                        };
                    } else if cur_extra.len() == 0 {
                        println!("old key exhausted");
                        // TODO: if is_inner:
                        println!("new branch");
                        let children = no_children![];
                        let (hd, tl) = nibble_head_tail(new_extra);
                        children[hd.to_lo() as usize].update(tl, value);
                        return Branch {
                            children: children,
                            data: Some(data),
                        };
                    } else {
                        println!("making a branch");
                        let children = no_children![];
                        // TODO: key done and is inner println!("making a branch");
                        println!("key done or not inner");
                        // println!("node: {}, key: {}, value: {}");
                        let (hd, tl) = nibble_head_tail();
                        children[hd].update(tl, value);
                    }
                },
                Extension { nibbles, data } => {
                    println!("extension");
                    Branch {
                        children: no_children![], // XXX
                        data: None,
                    }
                },
                Branch { children, data } => {
                    println!("branch");
                    Branch {
                        children: no_children![], // XXX
                        data: None,
                    }
                },
            }
        }
    }

    impl <'a>Rlp for &'a TrieNode {
        fn rlp(&self) -> Vec<u8> {
            match *self {
                &Leaf { ref nibbles, ref data } => {
                    println!("{:?} -> {:?}", nibbles, data);
                    // let nibbles = nibbles.to_byte_vec();
                    let data    = data.to_byte_vec();
                    println!(
                        "{:?} -> {:?}",
                        ::data_encoding::HEXLOWER.encode(nibbles.to_byte_vec().as_slice()),
                        ::data_encoding::HEXLOWER.encode(data.as_slice()));
                    // let mut result = NibVec::new();
                    // result.append(nibbles.rlp());
                    // result.append(data.rlp());
                    let result = vec![hex_prefix_encode_nibbles(nibbles, true), data];
                    // let bytes = hex_prefix_encode_nibbles(&result, true);
                    result.rlp()
                },
                &Extension { ref nibbles, ref data } => {
                    let encoded = hex_prefix_encode_nibbles(data, false);
                    // let node_composition =
                    // encoded.extend(
                    encoded.rlp()
                },
                &Branch { ref children, ref data } => {
                    Vec::new()

                    // let mut vec = Vec::new();
                    // vec.extend(children.iter().cloned()); // TODO: map rlp
                    // vec.rlp() // , data)

                    // let v = match data {
                    //     None =>
                    // }
                },
            }
        }
    }

    #[derive(Clone)]
    pub struct Trie {
        node: TrieNode,
    }

    pub trait Rlp {
        fn rlp(&self) -> Vec<u8>;
    }

    impl Rlp for Vec<u8> {
        /// R_b
        fn rlp(&self) -> Vec<u8> {
            let bytes = self;
            let len = bytes.len();
            let mut ret: Vec<u8>;
            if len == 1 && bytes[0] < 128 {
                ret = Vec::new();
            } else if len < 56 {
                let len8 = len as u8;
                ret = vec![128 + len8];
            } else {
                // length of the string
                let mut be_buf: [u8; 32] = [0; 32]; // TODO: big enough?

                // length in bytes of the length of the string in binary form
                U256::from(len).to_big_endian(&mut be_buf);
                // let be_len_bytes = be_buf.len() as u8;
                let be_len_bytes = be_buf
                    .iter()
                    .skip_while(|x| **x == 0)
                    .cloned()
                    .collect::<Vec<u8>>();

                // length in bytes of th elength of the string in binary form
                let be_len_bytes_len = be_len_bytes.len() as u8;

                ret = vec![183 + be_len_bytes_len];
                ret.extend(be_len_bytes.as_slice());
            }

            ret.extend(bytes);
            ret
        }
    }

    impl<T> Rlp for Vec<T>
        where T: Rlp {
            /// R_l
            fn rlp(&self) -> Vec<u8> {
                let children = self;
                let bytes: Vec<u8> = children
                    .iter()
                    .map(|x| x.rlp())
                    .collect::<Vec<Vec<u8>>>()
                    .concat();
                let len = bytes.len();
                println!("num children: {}", children.len());
                println!("children[0]: {:?}", ::data_encoding::HEXLOWER.encode(&children[0].rlp()));
                println!("concat output: {:?}", ::data_encoding::HEXLOWER.encode(&bytes));
                println!("concat encoded length: {}", bytes.len());
                let mut prefix: Vec<u8>;
                if len < 56 {
                    let len8 = len as u8;
                    prefix = vec![192 + len8];
                } else {
                    let mut be_buf: [u8; 64] = [0; 64]; // TODO: big enough?

                    // length in bytes of the length of the string in binary form
                    U256::from(len).to_big_endian(&mut be_buf);
                    let be_len_bytes = be_buf
                        .into_iter()
                        .skip_while(|x| **x == 0)
                        .cloned()
                        .collect::<Vec<u8>>();

                    let be_len_bytes_len = be_len_bytes.len() as u8;
                    prefix = vec![247 + be_len_bytes_len];
                    prefix.extend(be_len_bytes.as_slice());
                }
                prefix.extend(bytes);
                prefix
            }
    }

    fn nibble_head_tail(nibbles: NibVec) -> (u4lo, NibVec) {
        (get_nib::<u4lo>(nibbles, 0), nibbles.slice(1, nibbles.len()))
    }

    // HP
    fn hex_prefix_encode_nibbles(nibbles: &NibVec, t: bool) -> Vec<u8> {
        let len = nibbles.len();
        let f = u4lo::from_usize(if t { 2 } else { 0 })
            .expect("a 0 or a 2 couldn't fit into 4 bits!");
        let prefix: u4lo;
        if len % 2 == 0 {
            prefix = f;
        } else {
            prefix = f.wrapping_add(&u4lo::one());
        }
        let mut nibbles2 = nibbles.clone();

        // if even, insert extra nibble
        if len & 1 == 0 { nibbles2.insert(0, u4lo::from_lo(0)); }

        nibbles2.insert(0, prefix);
        nibbles2.to_byte_vec()
    }

    impl Trie {
        pub fn new() -> Trie {
            // TODO: can we move this to a constant?
            let emptyNode: TrieNode = Leaf {
                nibbles: NibVec::new(),
                data: NibVec::new(),
            };

            return Trie { node: emptyNode };
        }

        pub fn insert(&mut self, path: NibVec, value: NibVec) {
            let mut new_node = self.node.clone();
            new_node = new_node.update(path, value);
            println!("new node: {:?}", new_node);
            self.node = new_node;
        }

        pub fn lookup(&self, path: NibVec) -> Option<Vec<u8>> {
            return None
        }

        pub fn hash(&self) -> U256 {
            let mut hasher = Keccak256::default();
            println!("hash input: {:?}", ::data_encoding::HEXLOWER.encode(self.rlp_node().as_slice()));
            hasher.input(self.rlp_node().as_slice());
            let out: &[u8] = &hasher.result();
            U256::from(out)
        }

        pub fn rlp_node(&self) -> Vec<u8> {
            (&self.node).rlp()
        }

        pub fn hex_root(&self) -> String {
            let mut buf = [0; 32];
            self.hash().to_big_endian(&mut buf);
            return ::data_encoding::HEXLOWER.encode(&buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use nibble::NibVec;
    use trie::trie::{Trie,Rlp};

    #[test]
    fn insertion() {
        let t = &mut Trie::new();
        // t.insert(NibVec::new(), vec![1,2,3]);
    }

    #[test]
    fn matches_blog() {
        let t = &mut Trie::new();
        // six nibble key
        let k = NibVec::from_str("010102").unwrap();
        let v = NibVec::from_byte_vec(vec![Vec::from("hello".as_bytes())].rlp());

        // println!("rlp encoded [\"hello\"]: {:x}", v);
        // println!("{:x} -> {:x}", k, v);

        t.insert(k, v);
        assert_eq!(t.hex_root(), "15da97c42b7ed2e1c0c8dab6a6d7e3d9dc0a75580bbc4f1f29c33996d1415dcc");

        let k = NibVec::from_str("010102").unwrap();
        let v = NibVec::from_byte_vec(vec![Vec::from("hellothere".as_bytes())].rlp());
        t.insert(k, v);

        assert_eq!(t.hex_root(), "05e13d8be09601998499c89846ec5f3101a1ca09373a5f0b74021261af85d396");
    }
}
