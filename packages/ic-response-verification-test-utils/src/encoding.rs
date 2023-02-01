use base64::{engine::general_purpose, Engine as _};

pub fn base64_encode<T>(data: &T) -> String
where
    T: AsRef<[u8]>,
{
    general_purpose::STANDARD.encode(data)
}
