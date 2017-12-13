pub mod trie {
    use bigint::uint::U256;
    use nibble::{NibVec, u4lo};
    use num::traits::WrappingAdd;
    use num::{One,FromPrimitive};
    use sha3::{Digest, Keccak256};

    pub enum TrieNode<'a> {
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
            children: [&'a TrieNode<'a>; 16],
            data: Option<&'a TrieNode<'a>>,
        },
    }

    impl <'a>TrieNode<'a> {
        pub fn rlp_node(&self) -> Vec<u8> {
            match *self {
                Leaf { ref nibbles, ref data } => {
                    let mut encoded = hex_prefix_encode_nibbles(data, true);
                    encoded.extend(nibbles.to_byte_vec());
                    hex_prefix_encode_bytes(encoded)
                },
                Extension { ref nibbles, ref data } => {
                    let mut encoded = hex_prefix_encode_nibbles(data, false);
                    // let node_composition =
                    // encoded.extend(
                    hex_prefix_encode_bytes(encoded)
                },
                Branch { ref children, ref data } => {
                    rlp_tree(children) // , data)
                    // let v = match data {
                    //     None =>
                    // }
                },
            }
        }
    }

    pub struct Trie<'a> {
        node: Option<TrieNode<'a>>,
    }

    /// R_b
    pub fn hex_prefix_encode_bytes(bytes: Vec<u8>) -> Vec<u8> {
        let len = bytes.len();
        let mut ret: Vec<u8>;
        if len == 1 && bytes[0] < 128 {
            ret = Vec::new();
            // bytes
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

    /// R_l
    pub fn rlp_tree(children: &[&TrieNode; 16]) -> Vec<u8> {
        let mut bytes: Vec<u8> = children
            .iter()
            .map(|x| x.rlp_node())
            .collect::<Vec<Vec<u8>>>()
            .concat();
        let len = bytes.len();
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

    // HP
    fn hex_prefix_encode_nibbles(nibbles: &NibVec, t: bool) -> Vec<u8> {
        let len = nibbles.len();
        let f = u4lo::from_usize(if t { 2 } else { 0 })
            .expect("a 0 or a 2 couldn't fit into 4 bits!");
        let mut prefix: u4lo;
        if len % 2 == 0 {
            prefix = f;
        } else {
            prefix = f.wrapping_add(&u4lo::one());
        }
        let mut nibbles2 = nibbles.clone();
        nibbles2.push(prefix);
        nibbles2.to_byte_vec()
    }

    use self::TrieNode::*;

    impl <'a>Trie<'a> {
        pub fn new() -> Trie<'a> {
            return Trie { node: None };
        }

        pub fn insert(&self, path: NibVec, value: Vec<u8>) {
            match self.node {
                Some (Leaf { ref nibbles, ref data }) => println!("leaf"),
                Some (Extension { ref nibbles, ref data }) => println!("extension"),
                Some (Branch { ref children, ref data }) => println!("branch"),
                None => println!("empty"),
            }
        }

        pub fn lookup(&self, path: NibVec) -> Option<Vec<u8>> {
            return None
        }

        pub fn hash(&self) -> U256 {
            let mut hasher = Keccak256::default();
            hasher.input(self.rlp_node().as_slice());
            // let out: GenericArray<u8, _> = hasher.result();
            let out: &[u8] = &hasher.result();
            return U256::from(out);
        }

        pub fn rlp_node(&self) -> Vec<u8> {
            match self.node {
                Some (ref node) => node.rlp_node(),
                None => Vec::new(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use nibble::NibVec;
    use trie::trie::Trie;

    #[test]
    fn insertion() {
        let t = &mut Trie::new();
        t.insert(NibVec::new(), vec![1,2,3]);
    }
}
