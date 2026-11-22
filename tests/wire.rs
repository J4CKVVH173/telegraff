use telegraff::{
    application::{Channel, Family, Protocol},
    infrastructure::{
        receiver::Assembly,
        wire::{DATA, Frame, PART},
    },
};
fn frame(part: u16, bytes: usize) -> Frame {
    Frame {
        kind: DATA,
        agent: "node-01".into(),
        cycle: 0,
        channel: Channel {
            family: Family::Ipv4,
            protocol: Protocol::Udp,
        },
        transfer: 0,
        total: 2200,
        part,
        parts: 2,
        payload: vec![4; bytes],
    }
}
#[test]
fn authentication_covers_header_and_payload() {
    let f = frame(0, PART);
    let bytes = f.encode(&[7; 32]);
    assert!(bytes.len() <= 1232);
    assert!(Frame::decode(&bytes, &[7; 32]).is_ok());
    assert!(Frame::decode(&bytes, &[8; 32]).is_err());
    for index in [5, 40, 54, 62] {
        let mut damaged = bytes.clone();
        damaged[index] ^= 1;
        assert!(Frame::decode(&damaged, &[7; 32]).is_err());
    }
    assert!(Frame::decode(&vec![0; 300000], &[7; 32]).is_err());
}
#[test]
fn reordering_and_duplicates_preserve_unique_bytes() {
    let mut a = Assembly::new(&frame(1, PART));
    assert!(a.add(&frame(1, PART)).unwrap());
    assert!(!a.add(&frame(1, PART)).unwrap());
    assert!(a.add(&frame(0, PART)).unwrap());
    assert_eq!(a.bytes, 2200);
    let mut conflict = frame(0, PART);
    conflict.payload[0] = 9;
    a.add(&conflict).unwrap();
    assert!(a.invalid);
}
#[test]
fn invalid_part_geometry_is_rejected() {
    let mut a = Assembly::new(&frame(0, PART));
    assert!(a.add(&frame(2, PART)).is_err());
    assert!(a.add(&frame(0, PART - 1)).is_err());
}

#[test]
fn expired_assembly_does_not_accept_more_data() {
    let mut a = Assembly::new(&frame(0, PART));
    a.add(&frame(0, PART)).unwrap();
    a.started = std::time::Instant::now() - std::time::Duration::from_secs(121);
    assert!(a.add(&frame(1, PART)).is_err());
    assert_eq!(a.bytes, PART);
}
