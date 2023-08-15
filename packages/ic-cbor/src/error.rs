pub type CborResult<T = ()> = Result<T, CborError>;

#[derive(thiserror::Error, Debug)]
pub enum CborError {
    /// The CBOR was malformed and could not be parsed correctly
    #[error("Invalid cbor: {0}")]
    MalformedCbor(String),

    /// Certificate delegation canister range was not correctly CBOR encoded
    #[error("Invalid cbor canister ranges")]
    MalformedCborCanisterRanges,

    /// The Cbor parser expected a node of a certain type but found a different type
    #[error("Expected node with to have type {expected_type:?}, found {found_type:?}")]
    UnexpectedCborNodeType {
        /// The expected type of the node
        expected_type: String,
        /// The actual type of the node
        found_type: String,
    },

    /// Error converting UTF-8 string
    #[error("Error converting UTF8 string bytes: {0}")]
    Utf8ConversionError(#[from] std::string::FromUtf8Error),

    /// The certificate was malformed and could not be parsed correctly
    #[error(r#"Failed to parse certificate: "{0}""#)]
    MalformedCertificate(String),

    /// The hash tree was malformed and could not be parsed correctly
    #[error(r#"Failed to parse hash tree: "{0}""#)]
    MalformedHashTree(String),

    /// The hash tree pruned data was not the correct length
    #[error(r#"Invalid pruned data: "{0}""#)]
    IncorrectPrunedDataLength(#[from] std::array::TryFromSliceError),

    #[error("UnexpectedEndOfInput")]
    UnexpectedEndOfInput,
}
