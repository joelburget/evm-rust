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

    pub struct RlpEncoded(Vec<u8>);

    impl RlpEncoded {
        pub fn to_vec(self) -> Vec<u8> {
            match self {
                RlpEncoded(vec) => vec
            }
        }
    }

    impl Rlp for RlpEncoded {
        fn rlp(&self) -> RlpEncoded {
            match self {
                &RlpEncoded(ref vec) => RlpEncoded(vec.clone())
            }
        }
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

    fn maybe_extend(prefix: NibbleVec, node: TrieNode) -> TrieNode {
        if !prefix.is_empty() {
            Extension {
                nibbles: prefix,
                subtree: Box::new(node),
            }
        } else {
            node
        }
    }

    fn two_branch(prefix: NibbleVec,
                  k1: NibbleVec, v1: NibbleVec,
                  k2: NibbleVec, v2: NibbleVec) -> TrieNode {
        let mut branch = Branch {
            children: no_children![],
            data: None,
        };
        branch.update(k1, v1);
        branch.update(k2, v2);
        maybe_extend(prefix, branch)
    }

    impl TrieNode {
        pub fn lookup(&self, path: NibbleVec) -> Option<Vec<u8>> {
            match self {
                &Leaf { ref nibbles, ref data } => {
                    if path != *nibbles {
                        None
                    } else {
                        Some(data.clone().into_bytes())
                    }
                }

                &Extension { ref nibbles, ref subtree } => {
                    let (prefix, nibbles_extra, path_extra) = find_prefix(nibbles, &path);

                    // the path passed in should be at least as long as the extension nibbles.
                    // return None if not
                    if !nibbles_extra.is_empty() {
                        None
                    } else {
                        subtree.lookup(path_extra)
                    }
                }

                &Branch { ref children, ref data } => {
                    if path.is_empty() {
                        data.clone().map(|x| x.into_bytes())
                    } else {
                        let (hd, tl) = nibble_head_tail(path);
                        match children[hd as usize] {
                            None => None,
                            Some(ref x) => x.lookup(tl),
                        }
                    }
                }
            }
        }

        pub fn update(&mut self, path: NibbleVec, value: NibbleVec) {
            let mut result: Option<TrieNode> = None;
            match self {
                &mut Leaf { ref mut nibbles, ref mut data } => {
                    let (prefix, old_extra, new_extra) = find_prefix(nibbles, &path);

                    if old_extra.len() == 0 && new_extra.len() == 0 {
                        result = Some(Leaf {
                            nibbles: prefix,
                            data: value,
                        });

                    } else {
                        // otherwise we create an extension with prefix pointing to a branch
                        result = Some(two_branch(
                            prefix,
                            old_extra, data.clone(),
                            new_extra, value
                            ));
                    }
                },

                &mut Extension { ref mut nibbles, ref mut subtree } => {
                    let (prefix, old_extra, new_extra) = find_prefix(nibbles, &path);
                    if old_extra.len() == 0 {
                        // insert old subtree and new data as a branch
                        let mut subtree = subtree.deref().clone(); // TODO: don't clone
                        subtree.update(new_extra, value);
                        result = Some(maybe_extend(prefix, *subtree));
                    } else {
                        // the new key we're inserting bottoms out here
                        result = Some(two_branch(
                            prefix,
                            old_extra, nibbles.clone(),
                            new_extra, value
                        ));
                    }
                },

                &mut Branch { ref mut children, ref mut data } => {
                    let mut children = children.clone();
                    if path.is_empty() {
                        result = Some(Branch {
                            children,
                            data: Some(value),
                        });
                    } else {
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
                        result = Some(Branch {
                            children,
                            data: data.clone(),
                        });
                    }
                },
            };

            match result {
                None => {},
                Some(result) => { *self = result; },
            }
        }
    }

    fn rlp_reference(node: &TrieNode) -> RlpEncoded {
        match node {
            &Leaf{..}      => node.rlp(),
            &Extension{..} => node.rlp(),
            &Branch{..}    => {
                let mut hasher = Keccak256::default();
                hasher.input(node.deref().rlp().to_vec().as_slice());
                let subtree_hash: &[u8] = &hasher.result();
                Vec::from(subtree_hash).rlp()
            }
        }
    }

    impl <'a>Rlp for &'a TrieNode {
        fn rlp(&self) -> RlpEncoded {
            match *self {
                &Leaf { ref nibbles, ref data } => {
                    vec![
                        hex_prefix_encode_nibbles(nibbles, true),
                        data.clone().into_bytes().rlp(),
                    ].rlp()
                },

                &Extension { ref nibbles, ref subtree } => {
                    vec![
                        hex_prefix_encode_nibbles(nibbles, false),
                        rlp_reference(subtree)
                    ].rlp()
                },

                &Branch { ref children, ref data } => {
                    let mut v: Vec<RlpEncoded> = Vec::new();

                    for child in children.to_vec().iter() {
                        v.push(match *child {
                          None           => RlpEncoded(vec![0x80]),
                          Some(ref data) => rlp_reference(data),
                        });
                    }

                    v.push(match *data {
                        None           => RlpEncoded(vec![0x80]),
                        Some(ref data) => data.clone().into_bytes().rlp(),
                    });

                    v.rlp()
                },
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct Trie {
        node: TrieNode,
        is_empty: bool,
    }

    pub trait Rlp {
        fn rlp(&self) -> RlpEncoded;
    }

    pub fn rlp_encode_list(lst: Vec<u8>) -> RlpEncoded {
        lst.rlp()
    }

    // alternate name: rlp_encode_str
    impl Rlp for Vec<u8> {
        /// R_b
        fn rlp(&self) -> RlpEncoded {
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
            RlpEncoded(ret)
        }
    }

    // alternate name: rlp_encode_list
    impl<T> Rlp for Vec<T>
        where T: Rlp {
            /// R_l
            fn rlp(&self) -> RlpEncoded {
                let bytes: Vec<u8> = self
                    .iter()
                    .map(|x| x.rlp().to_vec())
                    .collect::<Vec<Vec<u8>>>()
                    .concat();
                let len = bytes.len();

                let mut prefix: Vec<u8>;
                if len < 56 {
                    let len8 = len as u8;
                    prefix = vec![192 + len8];
                } else {
                    let mut be_buf: [u8; 32] = [0; 32]; // TODO: big enough? bigint forces length 32?

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
                RlpEncoded(prefix)
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
    fn hex_prefix_encode_nibbles(nibbles: &NibbleVec, t: bool) -> RlpEncoded {
        let len = nibbles.len();
        let f = u8::from_usize(if t { 2 } else { 0 })
            .expect("a 0 or a 2 couldn't fit into 4 bits!");
        let prefix: u8;
        if len % 2 == 0 {
            prefix = f;
        } else {
            prefix = f.wrapping_add(1);
        }

        let mut ret = NibbleVec::new();
        ret.push(prefix);

        // if even, insert extra nibble
        if len & 1 == 0 { ret.push(0); }

        ret.join(nibbles).into_bytes().rlp()
    }

    impl Trie {
        pub fn new() -> Trie {
            // TODO: can we move this to a constant?
            let emptyNode: TrieNode = Leaf {
                nibbles: NibbleVec::new(),
                data: NibbleVec::new(),
            };

            return Trie { node: emptyNode, is_empty: true };
        }

        pub fn insert(&mut self, path: NibbleVec, value: NibbleVec) {
            if self.is_empty {
                self.node = Leaf {
                    nibbles: path,
                    data: value,
                };
                self.is_empty = false;
            } else {
                self.node.update(path, value);
            }
        }

        pub fn lookup(&self, path: NibbleVec) -> Option<Vec<u8>> {
            self.node.lookup(path)
        }

        pub fn hash(&self) -> U256 {
            let mut hasher = Keccak256::default();
            hasher.input(self.rlp_node().to_vec().as_slice());
            let out: &[u8] = &hasher.result();
            U256::from(out)
        }

        pub fn rlp_node(&self) -> RlpEncoded {
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

    fn hex_to_nibbles(str: &[u8]) -> NibbleVec {
        NibbleVec::from_byte_vec(HEXLOWER.decode(str).unwrap())
    }

    fn vec_str_to_nibbles(v: Vec<&str>) -> NibbleVec {
        let v: Vec<Vec<u8>> = v.iter().map(|x| Vec::from(x.as_bytes())).collect::<Vec<_>>();
        let v: Vec<u8> = v.rlp().to_vec();
        NibbleVec::from_byte_vec(v)
    }

    #[test]
    fn matches_blog() {
        let t = &mut Trie::new();

        println!("exercise 1\n");
        // >>> state.root_node
        // [' \x01\x01\x02', '\xc6\x85hello']
        // >>> rlp.encode(state.root_node)
        // '\xcd\x84 \x01\x01\x02\x87\xc6\x85hello'
        t.insert(hex_to_nibbles(b"010102"), vec_str_to_nibbles(vec!["hello"]));
        assert_eq!(t.hex_root(), "15da97c42b7ed2e1c0c8dab6a6d7e3d9dc0a75580bbc4f1f29c33996d1415dcc");

        // these tests use this as a starting point
        let mut t2b = t.clone();
        let mut t2c = t.clone();
        let mut t2d = t.clone();
        let mut t3  = t.clone();

        println!("exercise 2\n");
        // make an entry with the same key
        t.insert(hex_to_nibbles(b"010102"), vec_str_to_nibbles(vec!["hellothere"]));
        assert_eq!(t.hex_root(), "05e13d8be09601998499c89846ec5f3101a1ca09373a5f0b74021261af85d396");

        println!("exercise 2b\n");
        // make an entry with almost the same key but a different final nibble
        t2b.insert(hex_to_nibbles(b"010103"), vec_str_to_nibbles(vec!["hellothere"]));
        assert_eq!(t2b.hex_root(), "b5e187f15f1a250e51a78561e29ccfc0a7f48e06d19ce02f98dd61159e81f71d");

        println!("exercise 2c\n");
        t2c.insert(hex_to_nibbles(b"0101"), vec_str_to_nibbles(vec!["hellothere"]));
        assert_eq!(t2c.hex_root(), "f3e46945b73ef862d59850a8e1a73ef736625dd9a02bed1c9f2cc3ff4cd798b3");

        println!("exercise 2d\n");
        t2d.insert(hex_to_nibbles(b"01010257"), vec_str_to_nibbles(vec!["hellothere"]));
        assert_eq!(t2d.hex_root(), "dfd000b4b04811e7e59f1648f887bd56c16e4c047d6267793cf0eacf4b035c34");

        println!("exercise 3\n");

        // t.insert(hex_to_nibbles(b"010102"), vec_str_to_nibbles(vec!["hello"]));
        t3.insert(hex_to_nibbles(b"01010255"), vec_str_to_nibbles(vec!["hellothere"]));
        assert_eq!(t3.hex_root(), "17fe8af9c6e73de00ed5fd45d07e88b0c852da5dd4ee43870a26c39fc0ec6fb3");
        t3.insert(hex_to_nibbles(b"01010257"), vec_str_to_nibbles(vec!["jimbojones"]));
        assert_eq!(t3.hex_root(), "fcb2e3098029e816b04d99d7e1bba22d7b77336f9fe8604f2adfb04bcf04a727");

        println!("exercise 4\n");

        assert_eq!(
            t2b.lookup(hex_to_nibbles(b"010102")),
            Some(vec![Vec::from("hello".as_bytes())].rlp().to_vec())
        );
        assert_eq!(
            t2b.lookup(hex_to_nibbles(b"010103")),
            Some(vec![Vec::from("hellothere".as_bytes())].rlp().to_vec())
        );

        assert_eq!(
            t3.lookup(hex_to_nibbles(b"010102")),
            Some(vec![Vec::from("hello".as_bytes())].rlp().to_vec())
        );
        assert_eq!(
            t3.lookup(hex_to_nibbles(b"01010255")),
            Some(vec![Vec::from("hellothere".as_bytes())].rlp().to_vec())
        );
        assert_eq!(
            t3.lookup(hex_to_nibbles(b"01010257")),
            Some(vec![Vec::from("jimbojones".as_bytes())].rlp().to_vec())
        );
    }
}
