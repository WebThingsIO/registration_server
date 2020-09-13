use num_derive::{FromPrimitive, ToPrimitive};
use serde::Deserialize;

#[derive(Clone, Copy, Deserialize, FromPrimitive, ToPrimitive)]
pub enum DomainMode {
    Tunneled,
    DynamicDNS,
}
