mod error;
pub use error::*;

mod ast_mapping;
mod parser;

use crate::cel::ast_mapping::map_cel_ast;
use crate::cel::error::CelParserResult;
use crate::cel::parser::parse_cel_expression;
use crate::types::Certification;

pub fn cel_to_certification(cel: &str) -> CelParserResult<Option<Certification>> {
    parse_cel_expression(cel).and_then(map_cel_ast)
}
