#[cfg(test)]
use super::FuzzingEngine;

pub(super) trait OptionValueExt<T> {
    fn or_value(self, default: T) -> T;
    fn or_else_value<F>(self, default: F) -> T
    where
        F: FnOnce() -> T;
}

impl<T> OptionValueExt<T> for Option<T> {
    fn or_value(self, default: T) -> T {
        match self {
            Some(value) => value,
            None => default,
        }
    }

    fn or_else_value<F>(self, default: F) -> T
    where
        F: FnOnce() -> T,
    {
        match self {
            Some(value) => value,
            None => default(),
        }
    }
}

#[cfg(test)]
#[path = "attack_runner_tests.rs"]
mod tests;
