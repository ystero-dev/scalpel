//! 'Layer' trait

use std::fmt::Debug;

use crate::Error;

pub trait Layer: Debug {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error>;
}

#[derive(Debug, Default)]
pub struct FakeLayer;

impl<'a> Layer for FakeLayer {
    fn from_u8<'b>(&mut self, _btes: &'_ [u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        Ok((Some(Box::new(FakeLayer {})), 0))
    }
}
