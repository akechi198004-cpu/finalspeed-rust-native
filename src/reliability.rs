use std::collections::BTreeMap;
use std::time::Instant;

use crate::packet::Packet;
use bytes::Bytes;

use crate::constants::{INITIAL_RTO, MAX_RETRANSMISSIONS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Opening,
    Established,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct SentPacket {
    pub packet: Packet,
    pub sent_at: Instant,
    pub retransmit_count: u32,
}

#[derive(Debug)]
pub struct SendState {
    pub next_sequence: u32,
    pub unacked: BTreeMap<u32, SentPacket>,
    pub send_window: u16,
}

impl SendState {
    pub fn new(send_window: u16) -> Self {
        Self {
            next_sequence: 1, // Sequence starts from 1
            unacked: BTreeMap::new(),
            send_window,
        }
    }

    pub fn can_send(&self) -> bool {
        self.unacked.len() < self.send_window as usize
    }

    pub fn next_seq(&mut self) -> u32 {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        if self.next_sequence == 0 {
            // Skip 0 as it might be used for initial un-acked state, though arbitrary
            self.next_sequence = 1;
        }
        seq
    }

    pub fn save_unacked(&mut self, sequence: u32, packet: Packet) {
        self.unacked.insert(
            sequence,
            SentPacket {
                packet,
                sent_at: Instant::now(),
                retransmit_count: 0,
            },
        );
    }

    pub fn handle_ack(&mut self, ack_num: u32) {
        // cumulative ack: remove all packets with sequence <= ack_num
        // Because sequence numbers can wrap around, we need a robust check if we allow wrapping.
        // For Phase 3, standard cumulative ack without wrap-around handling is fine or simple check.
        // A simple approach: remove keys <= ack_num.
        let mut keys_to_remove = Vec::new();
        for key in self.unacked.keys() {
            if *key <= ack_num {
                keys_to_remove.push(*key);
            } else {
                break; // Since it's a BTreeMap, keys are sorted
            }
        }
        for key in keys_to_remove {
            self.unacked.remove(&key);
        }
    }

    pub fn get_timed_out_packets(
        &mut self,
        now: Instant,
    ) -> Result<Vec<Packet>, crate::error::FSpeedError> {
        let mut to_retransmit = Vec::new();
        for (_, sent_packet) in self.unacked.iter_mut() {
            if now.duration_since(sent_packet.sent_at) >= INITIAL_RTO {
                sent_packet.retransmit_count += 1;
                if sent_packet.retransmit_count > MAX_RETRANSMISSIONS {
                    return Err(crate::error::FSpeedError::Decode(
                        "Max retransmissions exceeded".to_string(),
                    ));
                }
                sent_packet.sent_at = now; // reset timer
                to_retransmit.push(sent_packet.packet.clone());
            }
        }
        Ok(to_retransmit)
    }
}

#[derive(Debug)]
pub struct ReceiveState {
    pub next_expected: u32,
    pub out_of_order: BTreeMap<u32, Bytes>,
    pub receive_window: u16,
}

impl ReceiveState {
    pub fn new(receive_window: u16) -> Self {
        Self {
            next_expected: 1, // Expect sequence starting from 1
            out_of_order: BTreeMap::new(),
            receive_window,
        }
    }

    pub fn receive_packet(&mut self, sequence: u32, payload: Bytes) -> Vec<Bytes> {
        let mut delivered = Vec::new();

        if sequence < self.next_expected {
            // Duplicate packet, drop it
            return delivered;
        }

        if sequence > self.next_expected {
            // Out of order, buffer it if within window
            if sequence - self.next_expected < self.receive_window as u32 {
                self.out_of_order.insert(sequence, payload);
            }
            return delivered;
        }

        // sequence == self.next_expected
        delivered.push(payload);
        self.next_expected += 1;

        // Check if any out-of-order packets can now be delivered
        while let Some(cached_payload) = self.out_of_order.remove(&self.next_expected) {
            delivered.push(cached_payload);
            self.next_expected += 1;
        }

        delivered
    }

    pub fn generate_ack(&self) -> u32 {
        // Ack is the last continuously received packet sequence
        self.next_expected - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Packet, PacketType};
    use crate::session::ConnectionId;
    use bytes::Bytes;

    fn create_test_packet(seq: u32) -> Packet {
        Packet::try_new(
            PacketType::Data,
            0,
            ConnectionId(1),
            seq,
            0,
            1024,
            Bytes::from(vec![0; 10]),
        )
        .unwrap()
    }

    #[test]
    fn test_send_state_sequence() {
        let mut send_state = SendState::new(1024);
        assert_eq!(send_state.next_seq(), 1);
        assert_eq!(send_state.next_seq(), 2);
    }

    #[test]
    fn test_send_state_unacked_and_ack() {
        let mut send_state = SendState::new(1024);

        let pkt1 = create_test_packet(1);
        let pkt2 = create_test_packet(2);
        let pkt3 = create_test_packet(3);

        send_state.save_unacked(1, pkt1);
        send_state.save_unacked(2, pkt2);
        send_state.save_unacked(3, pkt3);

        assert_eq!(send_state.unacked.len(), 3);

        // Ack up to 2
        send_state.handle_ack(2);
        assert_eq!(send_state.unacked.len(), 1);
        assert!(send_state.unacked.contains_key(&3));
    }

    #[test]
    fn test_send_state_sliding_window() {
        let mut send_state = SendState::new(2); // Window size 2

        assert!(send_state.can_send());
        send_state.save_unacked(1, create_test_packet(1));

        assert!(send_state.can_send());
        send_state.save_unacked(2, create_test_packet(2));

        // Window is full
        assert!(!send_state.can_send());

        // Ack frees window
        send_state.handle_ack(1);
        assert!(send_state.can_send());
    }

    #[test]
    fn test_send_state_retransmit_timeout() {
        let mut send_state = SendState::new(1024);
        let pkt = create_test_packet(1);

        send_state.save_unacked(1, pkt.clone());

        let now = Instant::now();

        // Before RTO
        let retransmit = send_state
            .get_timed_out_packets(now + std::time::Duration::from_millis(500))
            .unwrap();
        assert!(retransmit.is_empty());

        // After RTO
        let retransmit = send_state
            .get_timed_out_packets(now + std::time::Duration::from_millis(1500))
            .unwrap();
        assert_eq!(retransmit.len(), 1);
        assert_eq!(send_state.unacked.get(&1).unwrap().retransmit_count, 1);
    }

    #[test]
    fn test_send_state_max_retransmit_failure() {
        let mut send_state = SendState::new(1024);
        let pkt = create_test_packet(1);
        send_state.save_unacked(1, pkt);

        // Simulate MAX_RETRANSMISSIONS + 1 timeouts
        let mut now = Instant::now();
        for _ in 0..MAX_RETRANSMISSIONS {
            now += INITIAL_RTO + std::time::Duration::from_millis(1);
            let result = send_state.get_timed_out_packets(now);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().len(), 1);
        }

        // The next timeout should trigger failure
        now += INITIAL_RTO + std::time::Duration::from_millis(1);
        let result = send_state.get_timed_out_packets(now);
        assert!(result.is_err());
    }

    #[test]
    fn test_receive_state_in_order() {
        let mut rx_state = ReceiveState::new(1024);

        let p1 = rx_state.receive_packet(1, Bytes::from("A"));
        assert_eq!(p1.len(), 1);
        assert_eq!(rx_state.generate_ack(), 1);

        let p2 = rx_state.receive_packet(2, Bytes::from("B"));
        assert_eq!(p2.len(), 1);
        assert_eq!(rx_state.generate_ack(), 2);
    }

    #[test]
    fn test_receive_state_out_of_order() {
        let mut rx_state = ReceiveState::new(1024);

        // Receive 2 before 1
        let p2 = rx_state.receive_packet(2, Bytes::from("B"));
        assert!(p2.is_empty());
        assert_eq!(rx_state.generate_ack(), 0); // Still expecting 1

        // Receive 3
        let p3 = rx_state.receive_packet(3, Bytes::from("C"));
        assert!(p3.is_empty());
        assert_eq!(rx_state.generate_ack(), 0);

        // Receive 1, should deliver 1, 2, 3
        let p1 = rx_state.receive_packet(1, Bytes::from("A"));
        assert_eq!(p1.len(), 3);
        assert_eq!(p1[0], Bytes::from("A"));
        assert_eq!(p1[1], Bytes::from("B"));
        assert_eq!(p1[2], Bytes::from("C"));
        assert_eq!(rx_state.generate_ack(), 3);
    }

    #[test]
    fn test_receive_state_duplicate() {
        let mut rx_state = ReceiveState::new(1024);

        rx_state.receive_packet(1, Bytes::from("A"));
        let dup = rx_state.receive_packet(1, Bytes::from("A"));

        assert!(dup.is_empty());
        assert_eq!(rx_state.generate_ack(), 1);
    }

    #[test]
    fn test_connection_state_transitions() {
        let mut state = ConnectionState::Opening;
        assert_eq!(state, ConnectionState::Opening);

        state = ConnectionState::Established;
        assert_eq!(state, ConnectionState::Established);

        state = ConnectionState::Closing;
        assert_eq!(state, ConnectionState::Closing);

        state = ConnectionState::Closed;
        assert_eq!(state, ConnectionState::Closed);

        state = ConnectionState::Failed;
        assert_eq!(state, ConnectionState::Failed);
    }

    #[test]
    fn test_receive_state_out_of_order_missing_gap() {
        let mut rx_state = ReceiveState::new(1024);

        // Sequence 1 is lost, receive 2 and 3
        let p2 = rx_state.receive_packet(2, Bytes::from("B"));
        assert!(p2.is_empty());
        let p3 = rx_state.receive_packet(3, Bytes::from("C"));
        assert!(p3.is_empty());

        assert_eq!(rx_state.generate_ack(), 0); // Still expecting 1

        // Receive 4
        let p4 = rx_state.receive_packet(4, Bytes::from("D"));
        assert!(p4.is_empty());

        // Gap is filled with 1
        let p1 = rx_state.receive_packet(1, Bytes::from("A"));

        // Should deliver 1, 2, 3, 4 sequentially
        assert_eq!(p1.len(), 4);
        assert_eq!(p1[0], Bytes::from("A"));
        assert_eq!(p1[1], Bytes::from("B"));
        assert_eq!(p1[2], Bytes::from("C"));
        assert_eq!(p1[3], Bytes::from("D"));

        assert_eq!(rx_state.generate_ack(), 4);

        // Sequence 6 arrives
        let p6 = rx_state.receive_packet(6, Bytes::from("F"));
        assert!(p6.is_empty());
        assert_eq!(rx_state.generate_ack(), 4);
    }
}
