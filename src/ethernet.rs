use std::cell::RefCell;
use std::rc::Rc;

use crate::Error;
use crate::Layer;

#[derive(Debug, Default, Clone)]
pub(crate) struct Ethernet {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ethertype: u32,
    payload: Vec<u8>,
}

impl<'a> Layer<'a> for Ethernet {
    fn from_u8(&mut self, _bytes: &[u8]) -> Result<(Option<Rc<RefCell<dyn Layer>>>, usize), Error> {
        Ok((None, 0))
    }
}
