use ic_http_certification::HeaderField;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader<'a>(Cow<'a, str>, Cow<'a, str>);

impl<'a> ResponseHeader<'a> {
    pub fn new(name: impl Into<Cow<'a, str>>, value: impl Into<Cow<'a, str>>) -> Self {
        ResponseHeader(name.into(), value.into())
    }

    pub fn name(&self) -> &str {
        self.0.as_ref()
    }

    pub fn value(&self) -> &str {
        self.1.as_ref()
    }
}

impl From<(String, String)> for ResponseHeader<'_> {
    fn from((name, value): (String, String)) -> Self {
        ResponseHeader::new(name, value)
    }
}

impl<'a> From<(&'a str, &'a str)> for ResponseHeader<'a> {
    fn from((name, value): (&'a str, &'a str)) -> Self {
        ResponseHeader::new(name, value)
    }
}

impl<'a> From<&(&'a str, &'a str)> for ResponseHeader<'a> {
    fn from(&(name, value): &(&'a str, &'a str)) -> Self {
        ResponseHeader::new(name, value)
    }
}

impl<'a> From<(Cow<'a, str>, Cow<'a, str>)> for ResponseHeader<'a> {
    fn from((name, value): (Cow<'a, str>, Cow<'a, str>)) -> Self {
        ResponseHeader(name, value)
    }
}

impl<'a> Into<HeaderField> for ResponseHeader<'a> {
    fn into(self) -> HeaderField {
        (self.0.into(), self.1.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    fn response_header_with_borrowed_values() {
        let header: ResponseHeader<'_> = ("Content-Type", "application/json").into();

        assert_eq!(header.name(), "Content-Type");
        assert_eq!(header.value(), "application/json");
    }

    #[rstest]
    fn response_header_with_owned_values() {
        let header: ResponseHeader<'_> =
            ("Content-Type".to_string(), "application/json".to_string()).into();

        assert_eq!(header.name(), "Content-Type");
        assert_eq!(header.value(), "application/json");
    }
}
