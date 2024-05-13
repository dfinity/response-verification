/// The prefix for all paths in an HTTP certification tree.
pub const PATH_PREFIX: &str = "http_expr";

/// The prefix for all paths in an HTTP certification tree, as bytes.
pub const PATH_PREFIX_BYTES: &[u8] = PATH_PREFIX.as_bytes();

/// A trailing slash used to indicate a directory in an HTTP certification tree.
pub const PATH_DIR_SEPARATOR: &str = "";

/// A trailing slash used to indicate a directory in an HTTP certification tree, as bytes.
pub const PATH_DIR_SEPARATOR_BYTES: &[u8] = PATH_DIR_SEPARATOR.as_bytes();

/// A terminator used to indicate the end of an exact path in an HTTP certification tree.
pub const EXACT_PATH_TERMINATOR: &str = "<$>";

/// A terminator used to indicate the end of an exact path in an HTTP certification tree, as bytes.
pub const EXACT_PATH_TERMINATOR_BYTES: &[u8] = EXACT_PATH_TERMINATOR.as_bytes();

/// A terminator used to indicate the end of a wildcard path in an HTTP certification tree.
pub const WILDCARD_PATH_TERMINATOR: &str = "<*>";

/// A terminator used to indicate the end of a wildcard path in an HTTP certification tree, as bytes.
pub const WILDCARD_PATH_TERMINATOR_BYTES: &[u8] = WILDCARD_PATH_TERMINATOR.as_bytes();

/// Returns whether the given wildcard path is valid for the given request path.
pub fn is_wildcard_path_valid_for_request_path(
    wildcard_path: &[Vec<u8>],
    request_path: &[Vec<u8>],
) -> bool {
    // request_path must be a superset of wildcard_path
    if request_path.starts_with(wildcard_path) {
        return true;
    }

    // if the wildcard path includes a trailing slash then remove it and try the same check again
    // request paths will not include trailing slashes between path elements
    if wildcard_path.ends_with(&[PATH_DIR_SEPARATOR_BYTES.to_vec()]) {
        return request_path.starts_with(&wildcard_path[..wildcard_path.len() - 1]);
    }

    false
}

fn strip_path_affixes(path: &mut Vec<Vec<u8>>) {
    // strip any leading `http_expr` segments
    if matches!(
        path.first(),
        Some(first) if first == PATH_PREFIX_BYTES,
    ) {
        path.remove(0);
    }

    // strip any trailing `<*>` or `<$>` segments
    if matches!(path.last(), Some(last) if
        last == EXACT_PATH_TERMINATOR_BYTES ||
        last == WILDCARD_PATH_TERMINATOR_BYTES)
    {
        path.pop();
    }

    // after stripping out prefixes and suffixes,
    // the only path that should have a leading `/`,
    // is a single segment path (i.e. the root path)
    if path.len() > 1
        && matches!(
            path.first(),
            Some(first) if first == PATH_DIR_SEPARATOR_BYTES,
        )
    {
        path.remove(0);
    }
}

/// Returns a list of wildcard paths that are more specific than the responding
/// wildcard path. A wildcard path is more specific than another if it has more
/// segments and it contains the requested path as a prefix. The responding
/// wildcard path is expected to be a prefix of the requested path.
///
/// For example, if the requested path is `["a", "b", "c"]` and the responding
/// wildcard path is `["a", "b"]`, then the more specific wildcard paths are
/// `["a", "b", "c", "<*>"]` and `["a", "b", "/", "<*>"]`.
pub fn more_specific_wildcards_for(
    requested_path: &[Vec<u8>],
    responding_wildcard_path: &[Vec<u8>],
) -> Vec<Vec<Vec<u8>>> {
    let mut valid_wildcards: Vec<Vec<Vec<u8>>> = vec![];

    let mut potential_path = requested_path.to_vec();
    strip_path_affixes(&mut potential_path);

    let mut responding_wildcard_path = responding_wildcard_path.to_vec();
    strip_path_affixes(&mut responding_wildcard_path);

    // if the responding wildcard path is not a valid prefix of the requested path,
    // then we start from an empty path so that we can return all valid wildcards
    if !is_wildcard_path_valid_for_request_path(&responding_wildcard_path, &potential_path) {
        responding_wildcard_path = vec![];
    }

    while potential_path.len() > responding_wildcard_path.len()
        || potential_path.last() != responding_wildcard_path.last()
    {
        potential_path.push(WILDCARD_PATH_TERMINATOR_BYTES.to_vec());
        valid_wildcards.push(potential_path.clone());
        potential_path.pop(); // remove the wildcard terminator

        // if we didn't have a trailing slash in this round,
        // add it so we can handle it in the next round
        if potential_path.ends_with(&[PATH_DIR_SEPARATOR_BYTES.to_vec()]) {
            potential_path.pop(); // remove the last segment of the path
        } else {
            potential_path.pop(); // remove the last segment of the path
            potential_path.push(PATH_DIR_SEPARATOR_BYTES.to_vec());
        }
    }

    valid_wildcards
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case(responding_path_a(), more_specific_paths_a())]
    #[case(responding_path_b(), more_specific_paths_b())]
    #[case(responding_path_c(), more_specific_paths_c())]
    #[case(responding_path_d(), more_specific_paths_d())]
    #[case(responding_path_e(), more_specific_paths_e())]
    #[case(responding_path_f(), more_specific_paths_f())]
    #[case(responding_path_g(), more_specific_paths_g())]
    #[case(responding_path_h(), more_specific_paths_h())]
    fn test_more_specific_wildcards_for(
        requested_path: Vec<Vec<u8>>,
        #[case] responding_path: Vec<Vec<u8>>,
        #[case] expected: Vec<Vec<Vec<u8>>>,
    ) {
        let more_specific_paths = more_specific_wildcards_for(&requested_path, &responding_path);

        assert_eq!(more_specific_paths, expected);
    }

    #[fixture]
    fn requested_path() -> Vec<Vec<u8>> {
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    }

    #[fixture]
    fn responding_path_a() -> Vec<Vec<u8>> {
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    }

    #[fixture]
    fn more_specific_paths_a() -> Vec<Vec<Vec<u8>>> {
        vec![]
    }

    #[fixture]
    fn responding_path_b() -> Vec<Vec<u8>> {
        vec![
            b"a".to_vec(),
            b"b".to_vec(),
            PATH_DIR_SEPARATOR_BYTES.to_vec(),
        ]
    }

    #[fixture]
    fn more_specific_paths_b() -> Vec<Vec<Vec<u8>>> {
        vec![vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
        ]]
    }

    #[fixture]
    fn responding_path_c() -> Vec<Vec<u8>> {
        vec![b"a".to_vec(), b"b".to_vec()]
    }

    #[fixture]
    fn more_specific_paths_c() -> Vec<Vec<Vec<u8>>> {
        vec![
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
        ]
    }

    #[fixture]
    fn responding_path_d() -> Vec<Vec<u8>> {
        vec![b"a".to_vec(), PATH_DIR_SEPARATOR_BYTES.to_vec()]
    }

    #[fixture]
    fn more_specific_paths_d() -> Vec<Vec<Vec<u8>>> {
        vec![
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
        ]
    }

    #[fixture]
    fn responding_path_e() -> Vec<Vec<u8>> {
        vec![b"a".to_vec()]
    }

    #[fixture]
    fn more_specific_paths_e() -> Vec<Vec<Vec<u8>>> {
        vec![
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
        ]
    }

    #[fixture]
    fn responding_path_f() -> Vec<Vec<u8>> {
        vec![PATH_DIR_SEPARATOR_BYTES.to_vec()]
    }

    #[fixture]
    fn more_specific_paths_f() -> Vec<Vec<Vec<u8>>> {
        vec![
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![b"a".to_vec(), WILDCARD_PATH_TERMINATOR_BYTES.to_vec()],
        ]
    }

    #[fixture]
    fn responding_path_g() -> Vec<Vec<u8>> {
        vec![]
    }

    #[fixture]
    fn more_specific_paths_g() -> Vec<Vec<Vec<u8>>> {
        vec![
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![b"a".to_vec(), WILDCARD_PATH_TERMINATOR_BYTES.to_vec()],
            vec![
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
        ]
    }

    #[fixture]
    fn responding_path_h() -> Vec<Vec<u8>> {
        vec![b"d".to_vec(), b"e".to_vec(), b"f".to_vec()]
    }

    #[fixture]
    fn more_specific_paths_h() -> Vec<Vec<Vec<u8>>> {
        vec![
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![
                b"a".to_vec(),
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
            vec![b"a".to_vec(), WILDCARD_PATH_TERMINATOR_BYTES.to_vec()],
            vec![
                PATH_DIR_SEPARATOR_BYTES.to_vec(),
                WILDCARD_PATH_TERMINATOR_BYTES.to_vec(),
            ],
        ]
    }
}
