macro_rules! debug_state {
    ($message:expr, $matrix:expr) => {
        #[cfg(debug_assertions)]
        {
            println!("{}", $message);
            $matrix.pretty_print();
        }
    };
}

pub(crate) use debug_state;
