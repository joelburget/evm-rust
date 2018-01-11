macro_rules! no_children {
    () => ([
        None, None, None, None,
        None, None, None, None,
        None, None, None, None,
        None, None, None, None
    ])
}

macro_rules! todo_case {
    () => (Branch {
        children: no_children![],
        data: None,
    })
}

pub mod trie {
    use bigint::uint::U256;
    use nibble_vec::NibbleVec;
    use num::traits::WrappingAdd;
    use num::{FromPrimitive};
    use sha3::{Digest, Keccak256};
    use self::TrieNode::*;
    use core::cmp::min;
    use core::ops::Deref;
    use data_encoding::HEXLOWER;

    #[derive(Debug, Clone)]
    pub enum TrieNode {
        /// A two-item structure:
        /// * the nibbles in the key not already accounted for by the accumulation of keys and
        ///   branches traversed from the root
        ///   - hex-prefix encoding is used with the second parameter *true*
        /// * data at the leaf
        Leaf {
            nibbles: NibbleVec,
            data: NibbleVec,
        },
        /// A two-item structure:
        /// * a series of nibbles of size greater than one that are shared by at least two distinct
        /// keys past the accumulation of nibbles keys and branches as traversed from the root
        ///   - hex-prefix encoding is used with the second parameter *false*
        /// * data at the extension
        Extension {
            nibbles: NibbleVec,
            subtree: Box<TrieNode>,
        },
        /// A 17-item structure whose first sixteen items correspond to each of the sixteen
        /// possible nibble values for the keys at this point in their traversal. The 17th item is
        /// used in the case of this being a terminator node and thus a key being ended at this
        /// point in its traversal.
        Branch {
            children: [Option<Box<TrieNode>>; 16],
            data: Option<NibbleVec>,
        },
    }

    fn find_prefix(p1: &NibbleVec, p2: &NibbleVec) -> (NibbleVec, NibbleVec, NibbleVec) {
        // find common prefix
        let iter_count = min(p1.len(), p2.len());
        let mut prefix_len: usize = 0;

        for i in 0..iter_count {
            if p1.get(i) != p2.get(i) {
                break;
            }
            prefix_len += 1;
        }

        (
          slice(&p1, 0, prefix_len),
          slice(&p1, prefix_len, p1.len()),
          slice(&p2, prefix_len, p2.len()),
        )
    }

    impl TrieNode {
        pub fn update(&mut self, path: NibbleVec, value: NibbleVec) {
            *self = match *self {
                Leaf { ref nibbles, ref data } => {
                    let (prefix, old_extra, new_extra) = find_prefix(nibbles, &path);

                    println!("prefix: {:?}, old_extra: {:?}, new_extra: {:?}", prefix, old_extra, new_extra);
                    if old_extra.len() == 0 && new_extra.len() == 0 {
                        println!("keys were the same");
                        Leaf {
                            nibbles: prefix,
                            data: value,
                        }
                    } else if old_extra.len() == 0 {
                        println!("old key exhausted; new branch");
                        let mut children = no_children![];
                        let (hd, tl) = nibble_head_tail(new_extra);
                        match children[hd as usize] {
                            None => {
                                children[hd as usize] = Some(Box::new(Leaf {
                                    nibbles: tl,
                                    data: value,
                                }));
                            },
                            Some(ref mut child) => {
                                child.update(tl, value);
                            },
                        };
                        Branch {
                            children,
                            data: Some(data.clone()), // TODO: don't clone
                        }
                    } else {
                        println!("making a branch; key done");
                        let mut children = no_children![];
                        let (hd, tl) = nibble_head_tail(old_extra);
                        match children[hd as usize] {
                            None => {
                                children[hd as usize] = Some(Box::new(Leaf {
                                    nibbles: tl,
                                    data: value,
                                }));
                            },
                            Some(ref mut child) => {
                                child.update(tl, value);
                            }
                        }
                        Branch {
                            children: children,
                            data: Some(data.clone()), // TODO: don't clone
                        }
                    }
                },

                Extension { ref nibbles, ref subtree } => {
                    let (prefix, old_extra, new_extra) = find_prefix(nibbles, &path);
                    println!("updating extension");
                    if old_extra.len() == 0 {
                        println!("new key longer than old extension");
                        // insert old subtree and new data as a branch
                        let mut subtree = subtree.clone(); // TODO: don't clone
                        subtree.update(new_extra, value);
                        Extension {
                            nibbles: nibbles.clone(),
                            subtree: subtree,
                        }
                    } else {
                        // the new key we're inserting bottoms out here
                        let mut children = no_children![];
                        let (hd, tl) = nibble_head_tail(old_extra);
                        // TODO: logic to decide about extension, etc
                        /*
                        match children[hd as usize] {
                            None => {
                                children[hd as usize] = Some(Box::new(Leaf
                            }
                        }
                        */
                        Branch {
                            children,
                            data: Some(value),
                        }
                    }
                },

                Branch { ref children, ref data } => {
                    println!("branch");
                    let mut children = children.clone();
                    // TODO: case path is empty
                    let (hd, tl) = nibble_head_tail(path);
                    match children[hd as usize] {
                        None => {
                            children[hd as usize] = Some(Box::new(Leaf {
                                nibbles: tl,
                                data: value,
                            }));
                        },
                        Some(ref mut child) => {
                            child.update(tl, value);
                        },
                    }
                    Branch {
                        children,
                        data: data.clone(),
                    }
                },
            };
        }
    }

    impl <'a>Rlp for &'a TrieNode {
        fn rlp(&self) -> Vec<u8> {
            match *self {
                &Leaf { ref nibbles, ref data } => {
                    println!(
                        "{:?} -> {:?}",
                        HEXLOWER.encode(nibbles.as_bytes()),
                        HEXLOWER.encode(data.as_bytes()),
                    );

                    vec![
                        hex_prefix_encode_nibbles(nibbles, true),
                        data.clone().into_bytes(),
                    ].rlp()
                },
                &Extension { ref nibbles, ref subtree } => {
                    vec![
                        hex_prefix_encode_nibbles(nibbles, false),
                        subtree.deref().rlp(),
                    ].rlp()
                },
                &Branch { ref children, ref data } => {
                    let mut v = children
                      .to_vec()
                      .iter()
                      .map(|x| match *x {
                          None => Vec::new(),
                          Some(ref data) => data.deref().rlp(),
                      })
                      .collect::<Vec<Vec<u8>>>();

                    match *data {
                        None => {}
                        Some(ref data) => {
                          // TODO: this hex_prefix_encode_nibbles is not right
                          v.push(hex_prefix_encode_nibbles(data, true));
                        }
                    }

                    v.concat().rlp()
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
                println!("children[0]: {:?}", HEXLOWER.encode(&children[0].rlp()));
                println!("concat output: {:?}", HEXLOWER.encode(&bytes));
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

    fn nibble_head_tail(mut nibbles: NibbleVec) -> (u8, NibbleVec) {
        let tl = nibbles.split(1);
        (nibbles.get(0), tl)
    }

    fn slice(nibbles: &NibbleVec, start: usize, end: usize) -> NibbleVec {
        // |----|---------|-----|
        let mut clone = nibbles.clone();

        // |----|---------|
        clone.split(end);

        //      |---------|
        let ret = clone.split(start);
        ret
    }

    // HP
    fn hex_prefix_encode_nibbles(nibbles: &NibbleVec, t: bool) -> Vec<u8> {
        let len = nibbles.len();
        let f = u8::from_usize(if t { 2 } else { 0 })
            .expect("a 0 or a 2 couldn't fit into 4 bits!");
        let prefix: u8;
        if len % 2 == 0 {
            prefix = f;
        } else {
            prefix = f.wrapping_add(1);
        }
        let mut nibbles2 = nibbles.clone();

        // if even, insert extra nibble
        if len & 1 == 0 { nibbles2.push(0); }

        nibbles2.push(prefix);
        nibbles2.into_bytes()
    }

    impl Trie {
        pub fn new() -> Trie {
            // TODO: can we move this to a constant?
            let emptyNode: TrieNode = Leaf {
                nibbles: NibbleVec::new(),
                data: NibbleVec::new(),
            };

            return Trie { node: emptyNode };
        }

        pub fn insert(&mut self, path: NibbleVec, value: NibbleVec) {
            let mut new_node = self.node.clone();
            new_node.update(path, value);
            println!("new node: {:?}", new_node);
            self.node = new_node;
        }

        pub fn lookup(&self, path: NibbleVec) -> Option<Vec<u8>> {
            return None
        }

        pub fn hash(&self) -> U256 {
            let mut hasher = Keccak256::default();
            println!("hash input: {:?}", HEXLOWER.encode(self.rlp_node().as_slice()));
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
            return HEXLOWER.encode(&buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use nibble_vec::NibbleVec;
    use trie::trie::{Trie,Rlp};
    use data_encoding::HEXLOWER;

    #[test]
    fn insertion() {
        let t = &mut Trie::new();
        // t.insert(NibbleVec::new(), vec![1,2,3]);
    }

    #[test]
    fn matches_blog() {
        let t = &mut Trie::new();
        // six nibble key
        let k = NibbleVec::from_byte_vec(HEXLOWER.decode(b"010102").unwrap());
        let v = NibbleVec::from_byte_vec(vec![Vec::from("hello".as_bytes())].rlp());

        // println!("rlp encoded [\"hello\"]: {:x}", v);
        // println!("{:x} -> {:x}", k, v);

        t.insert(k, v);
        assert_eq!(t.hex_root(), "15da97c42b7ed2e1c0c8dab6a6d7e3d9dc0a75580bbc4f1f29c33996d1415dcc");

        let k = NibbleVec::from_byte_vec(HEXLOWER.decode(b"010102").unwrap());
        let v = NibbleVec::from_byte_vec(vec![Vec::from("hellothere".as_bytes())].rlp());
        t.insert(k, v);

        assert_eq!(t.hex_root(), "05e13d8be09601998499c89846ec5f3101a1ca09373a5f0b74021261af85d396");
    }
}
