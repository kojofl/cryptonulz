use mightrix::{ColumnPrio, ColumnPrioMatrix, Reftrix};

pub fn add(left: usize, right: usize) -> usize {
    let mut x = &mut [1, 2, 3, 4, 5, 6];
    let m = Reftrix::<2, 3, ColumnPrio, u8>::from_values(&mut x[..]);
    m.rows().fold(0, |res, row| res + row.into_iter().map(|el| *el as i32).sum::<i32>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 21);
    }
}
