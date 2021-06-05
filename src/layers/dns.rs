//! Handling of DNS layer

use core::convert::TryInto;

use crate::errors::Error;
use crate::layer::Layer;
use crate::layers::udp;
use crate::{IPv4Address, IPv6Address};

#[derive(Default, Debug, Clone)]
pub struct DNSSOA {
    mname: DNSName,
    rname: DNSName,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

#[derive(Clone, Debug)]
pub enum DNSRecordData {
    Empty,
    A(IPv4Address),
    AAAA(IPv6Address),
    CNAME(DNSName),
    MB(DNSName),
    MD(DNSName),
    MF(DNSName),
    MG(DNSName),
    MINFO((DNSName, DNSName)),
    MR(DNSName),
    MX((u16, DNSName)),
    PTR(DNSName),
    NULL(Vec<u8>),
    SOA(DNSSOA),
}

/// Register ourselves with parent
pub fn register_defaults() -> Result<(), Error> {
    udp::register_app(53, DNS::creator)
}

#[derive(Debug, Default, Clone)]
pub struct DNSName(Vec<u8>);

#[derive(Debug, Default, Clone)]
pub struct DNSQRecord {
    name: DNSName,
    type_: u16,
    class: u16,
}

#[derive(Debug, Clone)]
pub struct DNSResRecord {
    name: DNSName,
    type_: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: DNSRecordData,
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
        // FIXME: For this function - Every call to this function results in a `Vec` allocation,
        // which is not so easy to get rid of. But may be we could do better if we could use
        // references, but the code would be very tricky.
        //
        // The `gopacket` code for a similar function does something clever, but I have not fully
        // understood that.
        fn labels_from_offset(
            bytes: &[u8],
            offset: usize,
            mut remaining: usize,
            check_remaining: bool,
        ) -> Result<(Vec<u8>, usize), Error> {
            let mut i = offset;

            let mut consumed = 0;
            // Almost always we have to extend this header, so it's a good idea to reserve it with
            // capacity.
            let mut labels: Vec<u8> = Vec::with_capacity(32);
            let _ = loop {
                let ptr = bytes[i] & 0xC0;
                match ptr {
                    0xC0 => {
                        // This is in offset form, collect labels
                        // There are a couple of things we are doing here, which are worth keeping
                        // in mind.
                        // 1. The offset is from the start of DNS layer, but the slice we are
                        //    dealing with is past the first header (12 bytes), hence we subtract
                        //    the offset.
                        // 2. In the Offset form, we collect the previous one by just going through
                        //    the array, rather than recursively calling ourselves. Because the
                        //    `offset` form is guaranteed to be terminated in a label ending with
                        //    zero.
                        let first = ((bytes[i] & 0x3f) as u16) << 8 | (bytes[i + 1] as u16) - 12;
                        let mut last = first as usize;
                        loop {
                            if bytes[last] == 0x00 {
                                break;
                            }
                            last += 1;
                        }
                        labels.extend_from_slice(&bytes[first as usize..=last]);
                        consumed += 2;
                        break true;
                    }
                    0x00 => {
                        if bytes[i] == 0x00 {
                            consumed += 1;
                            labels.extend_from_slice(&bytes[i..i + 1]);
                            break false;
                        }

                        // Collect a single label
                        let count = bytes[i] as usize + 1_usize;
                        if check_remaining {
                            if remaining < count {
                                return Err(Error::TooShort);
                            }
                            consumed += count;
                            remaining -= count;
                        }

                        labels.extend_from_slice(&bytes[i..i + count]);
                        i += count;
                    }
                    _ => {
                        return Err(Error::ParseError);
                    }
                }
            };

            Ok((labels, consumed))
        }

        let (labels, consumed) = labels_from_offset(bytes, start, remaining, true)?;

        Ok((DNSName(labels), consumed))
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
        offset += 10;
        let rdata_buffer = &bytes[offset..offset + rdlength as usize];

        i += 10 + rdlength as usize;
        remaining -= 10 + rdlength as usize;

        let rdata = match type_ {
            1 => DNSRecordData::A(rdata_buffer.try_into().unwrap()), /* A */
            28 => DNSRecordData::AAAA(rdata_buffer.try_into().unwrap()), /* AAAA */
            2 | 3 | 4 | 5 | 7 | 8 | 9 => {
                let (name, _) = Self::dns_name_from_u8(bytes, i, remaining)?;
                DNSRecordData::CNAME(name)
            }
            6 => {
                // FIXME: into an inline function?
                let (mname, consumed) = Self::dns_name_from_u8(bytes, i, remaining)?;
                i += consumed;
                remaining -= consumed;
                let (rname, consumed) = Self::dns_name_from_u8(bytes, i, remaining)?;
                i += consumed;
                remaining -= consumed;
                if remaining < 20 {
                    return Err(Error::TooShort);
                }
                // serial, refresh, retry, expire, minimum
                let serial = (bytes[i] as u32) << 24
                    | (bytes[i + 1] as u32) << 16
                    | (bytes[i + 2] as u32) << 8
                    | (bytes[i + 3] as u32);
                let refresh = (bytes[i + 4] as u32) << 24
                    | (bytes[i + 5] as u32) << 16
                    | (bytes[i + 6] as u32) << 8
                    | (bytes[i + 7] as u32);
                let retry = (bytes[i + 8] as u32) << 24
                    | (bytes[i + 9] as u32) << 16
                    | (bytes[i + 10] as u32) << 8
                    | (bytes[i + 11] as u32);
                let expire = (bytes[i + 12] as u32) << 24
                    | (bytes[i + 13] as u32) << 16
                    | (bytes[i + 14] as u32) << 8
                    | (bytes[i + 15] as u32);
                let minimum = (bytes[i + 16] as u32) << 24
                    | (bytes[i + 17] as u32) << 16
                    | (bytes[i + 18] as u32) << 8
                    | (bytes[i + 19] as u32);

                i += 20;
                DNSRecordData::SOA(DNSSOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            _ => DNSRecordData::NULL(rdata_buffer.into()),
        };

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

#[cfg(test)]
mod tests {
    #[test]
    fn parse_valid_dns_packet() {
        use crate::layers;

        let _ = layers::register_defaults();

        let dns_query = vec![
	0x52, 0x54, 0x00, 0xbd, 0x1c, 0x70, 0xfe, 0x54, /* RT...p.T */
	0x00, 0x3e, 0x00, 0x96, 0x08, 0x00, 0x45, 0x00, /* .>....E. */
	0x00, 0xe0, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, /* ....@.@. */
	0xc4, 0x74, 0xc0, 0xa8, 0x7a, 0x01, 0xc0, 0xa8, /* .t..z... */
	0x7a, 0x46, 0x00, 0x35, 0xdb, 0x13, 0x00, 0xcc, /* zF.5.... */
	0x76, 0x76, /* DNS */ 0xf3, 0x03, 0x81, 0x80, 0x00, 0x01, /* vv...... */
	0x00, 0x01, 0x00, 0x04, 0x00, 0x04, 0x03, 0x77, /* .......w */
	0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, /* ww.googl */
	0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, /* e.com... */
	0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, /* ........ */
	0x00, 0x00, 0x01, 0x2c, 0x00, 0x10, 0x2a, 0x00, /* ...,..*. */
	0x14, 0x50, 0x40, 0x0c, 0x0c, 0x01, 0x00, 0x00, /* .P@..... */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x69, 0xc0, 0x10, /* .....i.. */
	0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, /* ........ */
	0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x10, /* ...ns4.. */
	0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, /* ........ */
	0xa3, 0x00, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x32, /* .....ns2 */
	0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, /* ........ */
	0x00, 0x02, 0xa3, 0x00, 0x00, 0x06, 0x03, 0x6e, /* .......n */
	0x73, 0x31, 0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, /* s1...... */
	0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x06, /* ........ */
	0x03, 0x6e, 0x73, 0x33, 0xc0, 0x10, 0xc0, 0x6c, /* .ns3...l */
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, /* ........ */
	0x00, 0x04, 0xd8, 0xef, 0x20, 0x0a, 0xc0, 0x5a, /* .... ..Z */
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, /* ........ */
	0x00, 0x04, 0xd8, 0xef, 0x22, 0x0a, 0xc0, 0x7e, /* ...."..~ */
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, /* ........ */
	0x00, 0x04, 0xd8, 0xef, 0x24, 0x0a, 0xc0, 0x48, /* ....$..H */
	0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, /* ........ */
	0x00, 0x04, 0xd8, 0xef, 0x26, 0x0a, /* ....&. */
        ];

        //let p = Packet::from_u8(&dns_query, ENCAP_TYPE_ETH);
        let mut dns: Box<dyn crate::Layer> = Box::new(super::DNS::default());

        let p = dns.from_u8(&dns_query[42..]);
        assert!(p.is_ok(), "{:?}", p.err());
    }

    #[test]
    fn test_dns_parse_gopacket_regression() {
        use crate::layers;
        use crate::types::ENCAP_TYPE_ETH;
        use crate::Packet;

        let _ = layers::register_defaults();
        // testPacketDNSRegression is the packet:
        //   11:08:05.708342 IP 109.194.160.4.57766 > 95.211.92.14.53: 63000% [1au] A? picslife.ru. (40)
        //      0x0000:  0022 19b6 7e22 000f 35bb 0b40 0800 4500  ."..~"..5..@..E.
        //      0x0010:  0044 89c4 0000 3811 2f3d 6dc2 a004 5fd3  .D....8./=m..._.
        //      0x0020:  5c0e e1a6 0035 0030 a597 f618 0010 0001  \....5.0........
        //      0x0030:  0000 0000 0001 0870 6963 736c 6966 6502  .......picslife.
        //      0x0040:  7275 0000 0100 0100 0029 1000 0000 8000  ru.......)......
        //      0x0050:  0000                                     ..
        let test_packet_dns_regression = vec![
            0x00, 0x22, 0x19, 0xb6, 0x7e, 0x22, 0x00, 0x0f, 0x35, 0xbb, 0x0b, 0x40, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x44, 0x89, 0xc4, 0x00, 0x00, 0x38, 0x11, 0x2f, 0x3d, 0x6d, 0xc2,
            0xa0, 0x04, 0x5f, 0xd3, 0x5c, 0x0e, 0xe1, 0xa6, 0x00, 0x35, 0x00, 0x30, 0xa5, 0x97,
            0xf6, 0x18, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x70,
            0x69, 0x63, 0x73, 0x6c, 0x69, 0x66, 0x65, 0x02, 0x72, 0x75, 0x00, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        ];
        let p = Packet::from_u8(&test_packet_dns_regression, ENCAP_TYPE_ETH);
        assert!(p.is_ok());
        let p = p.unwrap();
        assert!(p.layers.len() == 4, "{:#?}", p);
    }
}
