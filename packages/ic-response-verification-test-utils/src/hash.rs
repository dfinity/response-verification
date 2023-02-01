use ic_certified_map::Hash;
use sha256::Sha256Digest;

pub fn hash<T>(content: T) -> Hash
where
    T: Sha256Digest,
{
    let hash = sha256::digest(content);
    let decoded_hash = hex::decode(hash).unwrap();

    decoded_hash.try_into().unwrap()
}

pub fn hash_from_hex<T: AsRef<[u8]>>(data: T) -> Hash {
    hex::decode(data).unwrap().try_into().unwrap()
}
