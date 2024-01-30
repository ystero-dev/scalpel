/// EtherType structure and definition of Well Known EtherTypes
///
pub type EtherType = u16;

pub static ETHERTYPE_IP: EtherType = 0x0800_u16;
pub static ETHERTYPE_IP6: EtherType = 0x86dd_u16;
pub static ETHERTYPE_ARP: EtherType = 0x0806_u16;
pub static ETHERTYPE_MPLS_UNICAST: EtherType = 0x8847_u16;
