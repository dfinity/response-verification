pub fn say_hello() -> &'static str {
    "Hello World!"
}

#[cfg(test)]
mod tests {
    use crate::say_hello;

    #[test]
    fn say_hello_returns_a_string() {
        let result = say_hello();

        assert_eq!(result, "Hello World!");
    }
}
