pub type CelParserResult<T = ()> = Result<T, CelParserError>;

#[derive(thiserror::Error, Debug)]
pub enum CelParserError {
    #[error(r#""{0}" is not a supported CEL function, only default_certification is currently supported"#)]
    UnrecognizedFunction(String),

    #[error(r#"Parameter at position {parameter_position:?} for function {function_name:?} is missing, expected {parameter_name:?} with type {parameter_type:?}"#)]
    MissingFunctionParameter {
        function_name: String,
        parameter_type: String,
        parameter_name: String,
        parameter_position: u8,
    },

    #[error(r#"Parameter at position {parameter_position:?} for function {function_name:?} has the wrong type, expected {parameter_name:?} {expected_parameter_type:?} found {found_parameter_type:?}"#)]
    IncorrectFunctionParameterType {
        function_name: String,
        parameter_name: String,
        expected_parameter_type: String,
        found_parameter_type: String,
        parameter_position: u8,
    },

    #[error(r#"Expected node with name {node_name:?} to have type {expected_type:?}, found {found_type:?}"#)]
    UnexpectedNodeType {
        node_name: String,
        expected_type: String,
        found_type: String,
    },

    #[error(r#"Expected node with type {node_type:?} to have name {expected_name:?}, found {found_name:?}"#)]
    UnexpectedNodeName {
        node_type: String,
        expected_name: String,
        found_name: String,
    },

    #[error(r#"Expected object {object_name:?} to have property {expected_property_name:?}"#)]
    MissingObjectProperty {
        object_name: String,
        expected_property_name: String,
    },

    #[error(r#"The request_certification object must only specify one of the no_request_certification or request_certification properties, not both"#)]
    ExtraneousRequestCertificationProperty,

    #[error(r#"The request_certification object must specify at least one of the no_request_certification or request_certification properties"#)]
    MissingRequestCertificationProperty,

    #[error(r#"The response_certification object must only specify one of the certified_response_headers or response_header_exclusions properties, not both"#)]
    ExtraneousResponseCertificationProperty,

    #[error(r#"The response_certification object must specify at least one of the certified_response_headers or response_header_exclusions properties"#)]
    MissingResponseCertificationProperty,

    #[error(r#"The ValidationArgs parameter must only specify one of the no_certification or certification properties, not both"#)]
    ExtraneousValidationArgsProperty,

    #[error(r#"The ValidationArgs parameter must specify at least one of the no_certification or certification properties"#)]
    MissingValidationArgsProperty,

    #[error(r#"Cel Syntax Expception: {0}"#)]
    CelSyntaxException(String),
}
