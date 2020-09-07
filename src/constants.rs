use num_derive::{FromPrimitive, ToPrimitive};

#[derive(FromPrimitive, ToPrimitive)]
pub enum DomainMode {
    Tunneled,
    DynamicDNS,
}
