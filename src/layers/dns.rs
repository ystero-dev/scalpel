//! Handling of DNS layer

use core::convert::TryInto;

use crate::errors::Error;
use crate::layer::Layer;
use crate::layers::udp;

/// Register ourselves with parent
pub fn register_defaults() -> Result<(), Error> {
    udp::register_app(53, DNS::creator)
}

#[derive(Debug, Default, Clone)]
struct DNSName(Vec<u8>);

#[derive(Debug, Default, Clone)]
pub struct DNSQRecord {
    name: DNSName,
    type_: u16,
    class: u16,
}

#[derive(Debug, Default, Clone)]
pub struct DNSResRecord {
    name: DNSName,
    type_: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct DNS {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    questions: Vec<DNSQRecord>,
    answers: Vec<DNSResRecord>,
    nameservers: Vec<DNSResRecord>,
    additional: Vec<DNSResRecord>,
}

impl DNS {
    pub fn creator() -> Box<dyn Layer> {
        Box::new(DNS::default())
    }

    fn dns_name_from_u8(
        bytes: &[u8],
        start: usize,
        remaining: usize,
    ) -> Result<(DNSName, usize), Error> {
        #[inline(always)]
        fn name_from_offset(
            bytes: &[u8],
            offset: usize,
            remaining: usize,
        ) -> Result<(DNSName, usize), Error> {
            let mut i = offset;
            while bytes[i] != 0x00 {
                i += 1;
                if i > remaining + 5 {
                    return Err(Error::TooShort);
                }
            }
            i += 1;

            let name = DNSName(bytes[offset..i].try_into().unwrap());

            Ok((name, i))
        }

        if bytes[start] == 0xC0 {
            let offset = (bytes[start + 1] - 12) as usize; // Don't count the first 12 bytes
            let (name, _) = name_from_offset(bytes, offset, remaining)?;
            return Ok((name, 2));
        } else {
            let offset = start;
            name_from_offset(bytes, offset, remaining)
        }
    }

    fn dns_resrecord_from_u8(
        bytes: &[u8],
        start: usize,
        mut remaining: usize,
    ) -> Result<(DNSResRecord, usize), Error> {
        let mut i = 0;
        let mut offset = start;
        let (name, consumed) = Self::dns_name_from_u8(bytes, start, remaining)?;

        i += consumed;
        remaining -= consumed;
        offset += consumed;

        if remaining < 10 {
            return Err(Error::TooShort);
        }

        let type_ = (bytes[offset] as u16) << 8 | (bytes[offset + 1] as u16);
        let class = (bytes[offset + 2] as u16) << 8 | (bytes[offset + 3] as u16);
        let ttl = (bytes[offset + 4] as u32) << 24
            | (bytes[offset + 5] as u32) << 16
            | (bytes[offset + 6] as u32) << 8
            | (bytes[offset + 7] as u32);
        let rdlength = (bytes[offset + 8] as u16) << 8 | (bytes[offset + 9] as u16);
        if remaining < (rdlength as usize) {
            return Err(Error::TooShort);
        }
        let rdata = bytes[offset + 8..rdlength as usize].try_into().unwrap();

        i += 10 + rdlength as usize;
        Ok((
            DNSResRecord {
                name,
                type_,
                class,
                ttl,
                rdlength,
                rdata,
            },
            i,
        ))
    }

    fn records_from_u8(&mut self, bytes: &[u8], mut remaining: usize) -> Result<usize, Error> {
        let mut i = 0;

        // First questions
        for _ in 0..self.qdcount {
            let (name, consumed) = Self::dns_name_from_u8(bytes, i, remaining)?;

            i += consumed;
            remaining -= consumed;

            let type_ = (bytes[i] as u16) << 8 | (bytes[i + 1] as u16);
            let class = (bytes[i + 2] as u16) << 8 | (bytes[i + 3] as u16);

            self.questions.push(DNSQRecord { name, type_, class });
            i += 4;
            remaining -= 4;
        }

        for _ in 0..self.ancount {
            let (record, consumed) = Self::dns_resrecord_from_u8(bytes, i, remaining)?;

            i += consumed;
            remaining -= consumed;
            self.answers.push(record);
        }

        for _ in 0..self.nscount {
            let (record, consumed) = Self::dns_resrecord_from_u8(bytes, i, remaining)?;

            i += consumed;
            remaining -= consumed;
            self.nameservers.push(record);
        }

        for _ in 0..self.arcount {
            let (record, consumed) = Self::dns_resrecord_from_u8(bytes, i, remaining)?;

            i += consumed;
            remaining -= consumed;
            self.additional.push(record);
        }

        Ok(i)
    }
}

impl Layer for DNS {
    fn from_u8(&mut self, bytes: &[u8]) -> Result<(Option<Box<dyn Layer>>, usize), Error> {
        let mut decoded;

        if bytes.len() < 12 {
            return Err(Error::TooShort);
        }

        self.id = (bytes[0] as u16) << 8 | (bytes[1] as u16);

        let first = bytes[2];
        self.qr = (first & 0x80) != 0x00;
        self.opcode = (first & 0x78) >> 3;
        self.aa = (first & 0x04) != 0x00;
        self.tc = (first & 0x02) != 0x00;
        self.rd = (first & 0x01) != 0x00;

        let second = bytes[3];
        self.ra = (second & 0x80) != 0x80;
        self.z = 0;
        self.rcode = second & 0x0f;

        self.qdcount = (bytes[4] as u16) << 8 | (bytes[5] as u16);
        self.ancount = (bytes[6] as u16) << 8 | (bytes[7] as u16);
        self.nscount = (bytes[8] as u16) << 8 | (bytes[9] as u16);
        self.arcount = (bytes[10] as u16) << 8 | (bytes[11] as u16);

        decoded = 12;

        let remaining = bytes.len() - 12;
        let qbytes = self.records_from_u8(&bytes[decoded..], remaining)?;
        decoded += qbytes;

        Ok((None, decoded))
    }

    fn name(&self) -> &str {
        "DNS"
    }

    fn short_name(&self) -> &str {
        "dns"
    }
}
