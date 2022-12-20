#![allow(dead_code, unused_variables, unused_imports, unused_imports)]

mod mock;
mod model;
mod parser;

pub use model::*;

use mock::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
