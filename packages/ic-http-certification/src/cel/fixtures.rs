use rstest::*;

#[fixture]
pub(super) fn no_certification_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                no_certification: Empty {}
            }
        )"#,
    )
}

#[fixture]
pub(super) fn no_request_response_inclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    no_request_certification: Empty {},
                    response_certification: ResponseCertification {
                        certified_response_headers: ResponseHeaderList {
                            headers: [
                                "Cache-Control",
                                "ETag",
                                "Content-Length",
                                "Content-Type",
                                "Content-Encoding"
                            ]
                        }
                    }
                }
            }
        )"#,
    )
}

#[fixture]
pub(super) fn no_request_response_exclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    no_request_certification: Empty {},
                    response_certification: ResponseCertification {
                        response_header_exclusions: ResponseHeaderList {
                            headers: [
                                "Date",
                                "Cookie",
                                "Set-Cookie"
                            ]
                        }
                    }
                }
            }
        )"#,
    )
}

#[fixture]
pub(super) fn no_request_empty_response_inclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    no_request_certification: Empty {},
                    response_certification: ResponseCertification {
                        certified_response_headers: ResponseHeaderList {
                            headers: []
                        }
                    }
                }
            }
        )"#,
    )
}

#[fixture]
pub(super) fn no_request_empty_response_exclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    no_request_certification: Empty {},
                    response_certification: ResponseCertification {
                        response_header_exclusions: ResponseHeaderList {
                            headers: []
                        }
                    }
                }
            }
        )"#,
    )
}

#[fixture]
pub(super) fn include_request_response_header_inclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    request_certification: RequestCertification {
                        certified_request_headers: [
                            "Accept",
                            "Accept-Encoding",
                            "If-Match"
                        ],
                        certified_query_parameters: [
                            "foo",
                            "bar",
                            "baz"
                        ]
                    },
                    response_certification: ResponseCertification {
                        certified_response_headers: ResponseHeaderList {
                            headers: [
                                "Cache-Control",
                                "ETag",
                                "Content-Length",
                                "Content-Type",
                                "Content-Encoding"
                            ]
                        }
                    }
                }
            }
        )"#,
    )
}

#[fixture]
pub(super) fn include_request_response_header_exclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    request_certification: RequestCertification {
                        certified_request_headers: [
                            "Accept",
                            "Accept-Encoding",
                            "If-Match"
                        ],
                        certified_query_parameters: [
                            "foo",
                            "bar",
                            "baz"
                        ]
                    },
                    response_certification: ResponseCertification {
                        response_header_exclusions: ResponseHeaderList {
                            headers: [
                                "Date",
                                "Cookie",
                                "Set-Cookie"
                            ]
                        }
                    }
                }
            }
        )"#,
    )
}

#[fixture]
pub(super) fn include_request_empty_response_inclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    request_certification: RequestCertification {
                        certified_request_headers: [
                            "Accept",
                            "Accept-Encoding",
                            "If-Match"
                        ],
                        certified_query_parameters: [
                            "foo",
                            "bar",
                            "baz"
                        ]
                    },
                    response_certification: ResponseCertification {
                        certified_response_headers: ResponseHeaderList {
                            headers: []
                        }
                    }
                }
            }
        )"#,
    )
}

#[fixture]
pub(super) fn include_request_empty_response_exclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    request_certification: RequestCertification {
                        certified_request_headers: [
                            "Accept",
                            "Accept-Encoding",
                            "If-Match"
                        ],
                        certified_query_parameters: [
                            "foo",
                            "bar",
                            "baz"
                        ]
                    },
                    response_certification: ResponseCertification {
                        response_header_exclusions: ResponseHeaderList {
                            headers: []
                        }
                    }
                }
            }
        )"#,
    )
}

#[fixture]
pub(super) fn empty_request_response_inclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    request_certification: RequestCertification {
                        certified_request_headers: [],
                        certified_query_parameters: []
                    },
                    response_certification: ResponseCertification {
                        certified_response_headers: ResponseHeaderList {
                            headers: []
                        }
                    }
                }
            }
        )"#,
    )
}

#[fixture]
pub(super) fn empty_request_response_exclusions_cel() -> String {
    remove_whitespace(
        r#"default_certification(
            ValidationArgs {
                certification: Certification {
                    request_certification: RequestCertification {
                        certified_request_headers: [],
                        certified_query_parameters: []
                    },
                    response_certification: ResponseCertification {
                        response_header_exclusions: ResponseHeaderList {
                            headers: []
                        }
                    }
                }
            }
        )"#,
    )
}

fn remove_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}
