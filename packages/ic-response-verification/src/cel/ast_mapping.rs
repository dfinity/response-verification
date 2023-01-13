use crate::cel::error::{CelParserError, CelParserResult};
use crate::cel::parser::CelValue;
use crate::types::{Certification, RequestCertification, ResponseCertification};
use std::collections::HashMap;

fn validate_object<'a>(
    cel: &'a CelValue,
    name: &str,
) -> CelParserResult<&'a HashMap<String, CelValue>> {
    let CelValue::Object(object_name, object_value) = cel else {
        return Err(CelParserError::UnexpectedNodeType {
            node_name: name.into(),
            expected_type: "Object".into(),
            found_type: cel.to_string(),
        });
    };

    if object_name != name {
        return Err(CelParserError::UnexpectedNodeName {
            node_type: "Object".into(),
            expected_name: name.into(),
            found_name: object_name.into(),
        });
    }

    Ok(object_value)
}

fn validate_function<'a>(cel: &'a CelValue, name: &str) -> CelParserResult<&'a Vec<CelValue>> {
    let CelValue::Function(function_name, function_value) = cel else {
        return Err(CelParserError::UnexpectedNodeType {
            node_name: name.into(),
            expected_type: "Function".into(),
            found_type: cel.to_string(),
        });
    };

    if function_name != name {
        return Err(CelParserError::UnexpectedNodeName {
            node_type: "Function".into(),
            expected_name: name.into(),
            found_name: function_name.into(),
        });
    }

    Ok(function_value)
}

fn validate_string_array(cel: &CelValue, name: &str) -> CelParserResult<Vec<String>> {
    let CelValue::Array(array) = cel else {
        return Err(CelParserError::UnexpectedNodeType {
            node_name: name.into(),
            expected_type: "Array".into(),
            found_type: cel.to_string(),
        });
    };

    let elements = array
        .iter()
        .map(|e| {
            let CelValue::String(e) = e else {
                return Err(CelParserError::UnexpectedNodeType {
                    node_name: name.into(),
                    expected_type: "String".into(),
                    found_type: cel.to_string(),
                });
            };

            Ok(e.to_owned())
        })
        .collect::<Result<_, _>>()?;

    Ok(elements)
}

fn validate_request_certification(
    certification: &HashMap<String, CelValue>,
) -> CelParserResult<Option<RequestCertification>> {
    let no_request_certification = certification.get("no_request_certification");
    let request_certification = certification.get("request_certification");

    return match (no_request_certification, request_certification) {
        (Some(_), Some(_)) => Err(CelParserError::ExtraneousRequestCertificationProperty),
        (None, None) => Err(CelParserError::MissingRequestCertificationProperty),
        (Some(_), None) => Ok(None),
        (None, Some(request_certification)) => {
            let request_certification =
                validate_object(request_certification, "RequestCertification")?;

            let Some(certified_request_headers) = request_certification.get("certified_request_headers") else {
                return Err(CelParserError::MissingObjectProperty {
                    object_name: "RequestCertification".into(),
                    expected_property_name: "certified_request_headers".into(),
                });
            };
            let certified_request_headers =
                validate_string_array(certified_request_headers, "certified_request_headers")?;

            let Some(certified_query_parameters) = request_certification.get("certified_query_parameters") else {
                return Err(CelParserError::MissingObjectProperty {
                    object_name: "RequestCertification".into(),
                    expected_property_name: "certified_query_parameters".into(),
                });
            };
            let certified_query_parameters =
                validate_string_array(certified_query_parameters, "certified_query_parameters")?;

            Ok(Some(RequestCertification {
                certified_request_headers,
                certified_query_parameters,
            }))
        }
    };
}

fn validate_response_certification(
    certification: &HashMap<String, CelValue>,
) -> CelParserResult<ResponseCertification> {
    let Some(response_certification) = certification.get("response_certification") else {
        return Err(CelParserError::MissingObjectProperty {
            object_name: "RequestCertification".into(),
            expected_property_name: "response_certification".into(),
        });
    };
    let response_certification = validate_object(response_certification, "ResponseCertification")?;

    let get_response_certification_headers =
        |property_name| -> CelParserResult<Option<Vec<String>>> {
            response_certification
                .get(property_name)
                .and_then(|certified_response_headers| {
                    Some(validate_object(
                        certified_response_headers,
                        "ResponseHeaderList",
                    ))
                })
                .transpose()?
                .and_then(|certified_response_headers| certified_response_headers.get("headers"))
                .and_then(|headers| Some(validate_string_array(headers, property_name)))
                .transpose()
        };

    let certified_response_headers =
        get_response_certification_headers("certified_response_headers")?;

    let response_header_exclusions =
        get_response_certification_headers("response_header_exclusions")?;

    return match (certified_response_headers, response_header_exclusions) {
        (Some(_), Some(_)) => Err(CelParserError::ExtraneousResponseCertificationProperty),
        (None, None) => Err(CelParserError::MissingResponseCertificationProperty),
        (Some(headers), None) => Ok(ResponseCertification::CertifiedHeaders(headers)),
        (None, Some(headers)) => Ok(ResponseCertification::HeaderExclusions(headers)),
    };
}

pub fn map_cel_ast(cel: CelValue) -> CelParserResult<Option<Certification>> {
    let default_certification = validate_function(&cel, "default_certification")?;

    let Some(validation_args) = default_certification.get(0) else {
        return Err(CelParserError::MissingFunctionParameter {
            function_name: "default_certification".into(),
            parameter_name: "ValidationArgs".into(),
            parameter_type: "Object".into(),
            parameter_position: 0,
        });
    };

    let validation_args = validate_object(validation_args, "ValidationArgs")?;

    let no_certification = validation_args.get("no_certification");
    let certification = validation_args.get("certification");

    return match (no_certification, certification) {
        (Some(_), Some(_)) => Err(CelParserError::ExtraneousValidationArgsProperty),
        (None, None) => Err(CelParserError::MissingValidationArgsProperty),
        (Some(_), None) => Ok(None),
        (None, Some(certification)) => {
            let certification = validate_object(certification, "Certification")?;

            let request_certification = validate_request_certification(certification)?;

            let response_certification = validate_response_certification(certification)?;

            Ok(Some(Certification {
                request_certification,
                response_certification,
            }))
        }
    };
}
