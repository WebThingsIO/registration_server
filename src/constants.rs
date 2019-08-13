#[derive(FromPrimitive, ToPrimitive)]
pub enum DomainMode {
    Tunneled,
    DynamicDNS,
}
