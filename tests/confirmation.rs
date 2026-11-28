mod common;
use telegraff::application::{
    Family, Protocol,
    confirmation::{Confirmation, passes},
    ports::TransferRequest,
};

#[test]
fn confirmation_checks_every_identity_field_for_both_transports() {
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let transfer = common::transfer(3600, Family::Ipv4, protocol, 153600);
        let request = TransferRequest {
            agent: transfer.agent.clone(),
            cycle: transfer.cycle,
            channel: transfer.channel,
            transfer: transfer.transfer,
            total: transfer.bytes,
        };
        let confirmation = Confirmation::accepted(&transfer);
        assert_eq!(confirmation.validate(&request).unwrap(), 153600);
        for field in 0..6 {
            let mut wrong = confirmation.clone();
            match field {
                0 => wrong.agent = "another-agent".into(),
                1 => wrong.cycle += 1,
                2 => wrong.channel.family = Family::Ipv6,
                3 => {
                    wrong.channel.protocol = if protocol == Protocol::Tcp {
                        Protocol::Udp
                    } else {
                        Protocol::Tcp
                    }
                }
                4 => wrong.transfer += 1,
                _ => wrong.bytes += 1,
            }
            assert!(
                wrong.validate(&request).is_err(),
                "{protocol:?}, field {field}"
            );
        }
    }
}
#[test]
fn sender_and_receiver_share_exact_success_thresholds() {
    let p = common::policy();
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        for bytes in [0, 152063, 152064, 153599, 153600, 153601] {
            let t = common::transfer(0, Family::Ipv4, protocol, bytes);
            assert_eq!(
                t.passes(&p),
                passes(protocol, bytes, p.payload_bytes, p.udp_threshold)
            );
        }
    }
    assert!(!passes(Protocol::Tcp, 0, 0, 99));
    assert!(passes(Protocol::Udp, 152064, 153600, 99));
    assert!(!passes(Protocol::Udp, 152063, 153600, 99));
}
