#![cfg(feature = "sculpting")]

use crate::{errors::Error, Layer, Packet};

#[derive(Debug, Default)]
pub struct PacketBuilder {
    inner: Packet,
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stacks a layer on top of the Packet. The return value on success is the
    /// `PacketBuilder` on success. Failure happens when a layer is attempted to
    /// be pushed after pushing bytes. In this case it returns a
    /// [SculptingError][`crate::errors::Error::SculptingError`].
    pub fn stack(mut self, layer: Box<dyn Layer + Send>) -> Result<Self, Error> {
        if self.inner.unprocessed.is_empty() {
            self.inner.layers.push(layer);
            Ok(self)
        } else {
            Err(Error::SculptingError(
                "Cannot push layer on top of raw byte layer".to_string(),
            ))
        }
    }

    /// Stacks bytes on top of the packet. If the layer already contains some bytes
    /// the new bytes are concatenated to the previous bytes in the packet.
    pub fn stack_bytes(mut self, bytes: &[u8]) -> Self {
        self.inner.unprocessed.extend(bytes);
        self
    }

    pub fn build(mut self) -> Result<(Packet, Vec<Vec<u8>>), Error> {
        let len = self.inner.layers.len();
        if len < 1 {
            return Err(Error::SculptingError(
                "Packet to build does not contain any layers".to_string(),
            ));
        }
        let mut results = vec![];

        // last layer
        let next_layer = if self.inner.unprocessed.is_empty() {
            None
        } else {
            Some(self.inner.unprocessed.as_slice())
        };
        let mut bytes = self.inner.layers[len - 1].stack_and_encode(next_layer, "raw")?;
        results.push(bytes);

        for i in (0..len - 1).rev() {
            let next_layer = results.last().map(|layer| layer.as_slice());
            let info = self.inner.layers[i + 1].name();
            bytes = self.inner.layers[i].stack_and_encode(next_layer, info)?;
            results.push(bytes);
        }

        results.reverse();
        Ok((self.inner, results))
    }

    // TODO: Add metadata related functions
}
