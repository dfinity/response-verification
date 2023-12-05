pub(crate) type CelParserResult<T = ()> = Result<T, CelParserError>;

/// CEL expression parsing error.
#[derive(thiserror::Error, Debug)]
pub enum CelParserError {
    /// The CEL parser encountered an unsupported CEL function.
    #[error(r#""{0}" is not a supported CEL function, only default_certification is currently supported"#)]
    UnrecognizedFunction(String),

    /// The CEL parser expected a parameter at a position, but none was found.
    #[error(r#"Parameter at position {parameter_position:?} for function {function_name:?} is missing, expected {parameter_name:?} with type {parameter_type:?}"#)]
    MissingFunctionParameter {
        /// The name of the function with a missing parameter.
        function_name: String,
        /// The expected type of the missing parameter.
        parameter_type: String,
        /// The expected name of the missing parameter.
        parameter_name: String,
        /// The expected position of the missing parameter.
        parameter_position: u8,
    },

    /// The CEL parser expected a parameter to have a different type than the one it found.
    #[error(r#"Parameter at position {parameter_position:?} for function {function_name:?} has the wrong type, expected {parameter_name:?} {expected_parameter_type:?} found {found_parameter_type:?}"#)]
    IncorrectFunctionParameterType {
        /// The name of the function with an unexpected parameter type.
        function_name: String,
        /// The name of the parameter with the unexpected type.
        parameter_name: String,
        /// The expected type of the parameter.
        expected_parameter_type: String,
        /// The actual type of the parameter.
        found_parameter_type: String,
        /// The position of the parameter.
        parameter_position: u8,
    },

    /// The CEL parser expected a node to have a different type than the one it found.
    #[error(r#"Expected node with name {node_name:?} to have type {expected_type:?}, found {found_type:?}"#)]
    UnexpectedNodeType {
        /// The name of the node with an unexpected type.
        node_name: String,
        /// The expected type of the node.
        expected_type: String,
        /// The actual type of the node.
        found_type: String,
    },

    /// The CEL parser expected a node to have a different name than the one it found.
    #[error(r#"Expected node with type {node_type:?} to have name {expected_name:?}, found {found_name:?}"#)]
    UnexpectedNodeName {
        /// The type of the node with an unexpected name.
        node_type: String,
        /// The expected name of the node.
        expected_name: String,
        /// The actual name of hte node.
        found_name: String,
    },

    /// The CEL parser expected an object to have a property with a particular name, but none was found.
    #[error(r#"Expected object {object_name:?} to have property {expected_property_name:?}"#)]
    MissingObjectProperty {
        /// The name of the object with a missing property.
        object_name: String,
        /// The expected property name.
        expected_property_name: String,
    },

    /// The CEL parser encountered an extraneous property on the request certification's CEL object.
    #[error(r#"The request_certification object must only specify one of the no_request_certification or request_certification properties, not both"#)]
    ExtraneousRequestCertificationProperty,

    /// The CEL parser expected to find a property on the request certification's CEL object, but none was found.
    #[error(r#"The request_certification object must specify at least one of the no_request_certification or request_certification properties"#)]
    MissingRequestCertificationProperty,

    /// The CEL parser encountered an extraneous property on the response certification's CEL object.
    #[error(r#"The response_certification object must only specify one of the certified_response_headers or response_header_exclusions properties, not both"#)]
    ExtraneousResponseCertificationProperty,

    /// The CEL parser expected to find a property on the response certification's CEL object, but none was found.
    #[error(r#"The response_certification object must specify at least one of the certified_response_headers or response_header_exclusions properties"#)]
    MissingResponseCertificationProperty,

    /// The CEL parser encountered an extraneous property on the certification's CEL object.
    #[error(r#"The ValidationArgs parameter must only specify one of the no_certification or certification properties, not both"#)]
    ExtraneousValidationArgsProperty,

    /// The CEL parser expected to find a property on the certification's CEL object, but none was found.
    #[error(r#"The ValidationArgs parameter must specify at least one of the no_certification or certification properties"#)]
    MissingValidationArgsProperty,

    /// The CEL parser encountered a syntax error while parsing the CEL expression. Using the "debug" feature flag can help to debug these syntax errors.
    #[error(r#"Cel Syntax Expception: {0}"#)]
    CelSyntaxException(String),
}
