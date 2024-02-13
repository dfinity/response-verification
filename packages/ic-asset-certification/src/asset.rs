use glob_match::glob_match;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset<'a> {
    path: Cow<'a, str>,
    url: String,
    pub content: Cow<'a, [u8]>,
}

impl<'a> Asset<'a> {
    pub fn new(path: impl Into<Cow<'a, str>>, content: impl Into<Cow<'a, [u8]>>) -> Self {
        let path = path.into();

        Asset {
            url: path_to_url(path.as_ref()),
            path,
            content: content.into(),
        }
    }

    pub fn path(&self) -> &str {
        self.path.as_ref()
    }

    pub fn url(&self) -> &str {
        self.url.as_ref()
    }

    pub fn content(&self) -> &[u8] {
        self.content.as_ref()
    }

    pub fn matches(&self, glob: &str) -> bool {
        glob_match(glob, self.path())
    }
}

fn path_to_url(path: &str) -> String {
    if !path.starts_with("/") {
        format!("/{}", path)
    } else {
        path.to_string()
    }
}
