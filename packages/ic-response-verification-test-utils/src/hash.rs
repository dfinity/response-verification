use ic_certification::Hash;
use sha2::{Digest, Sha256};

pub fn hash<T>(data: T) -> Hash
where
    T: AsRef<[u8]>,
{
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hash_from_hex<T: AsRef<[u8]>>(data: T) -> Hash {
    hex::decode(data).unwrap().try_into().unwrap()
}
