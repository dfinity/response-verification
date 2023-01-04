#![allow(dead_code, unused_variables, unused_imports, unused_imports)]

mod ast_mapping;
mod error;
mod mock;
mod model;
mod parser;

pub use model::*;

use crate::ast_mapping::map_cel_ast;
use crate::error::{CelParserError, CelParserResult};
use crate::parser::parse_cel_expression;
use mock::*;

pub fn cel_to_certification(cel: &str) -> CelParserResult<Option<Certification>> {
    parse_cel_expression(cel).and_then(map_cel_ast)
}
