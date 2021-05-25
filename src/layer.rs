//! 'Layer' trait

use core::fmt::Debug;

use crate::Error;

pub trait Layer: Debug {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error>;

    fn name(&self) -> &str;

    fn short_name(&self) -> &str;
}

#[derive(Debug, Default)]
pub struct FakeLayer;

impl<'a> Layer for FakeLayer {
    fn from_u8<'b>(&mut self, _btes: &'_ [u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        Ok((Some(Box::new(FakeLayer {})), 0))
    }

    fn name(&self) -> &str {
        "fake"
    }

    fn short_name(&self) -> &str {
        "fake"
    }
}
