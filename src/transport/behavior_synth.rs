//! Markov-chain Traffic Shaping Engine — Industrial Mimicry
//!
//! The `BehaviorSynthesizer` is designed to defeat statistical analysis performed by
//! advanced DPI (Deep Packet Inspection) firewalls. It achieves this by synthesizing
//! packet timing (inter-packet arrival times) and sizing based on pre-defined Markov
//! chain models of common protocols.
//!
//! ### Supported Profiles
//! - **Modbus/TCP**: Mimics industrial control traffic with small, frequent status queries.
//! - **MQTT Sensor**: Mimics IoT telemetry with periodic heartbeats and variable burst sizes.
//! - **Standard HTTPS**: Mimics typical web browsing patterns with large MTU-bound bursts.
//!
//! ### How it Works
//! The synthesizer maintains an internal state (`Idle`, `SmallBurst`, `LargeBurst`) and
//! uses transition probabilities to move between them. For each step, it generates
//! a (size, duration) tuple that can be used to pace outgoing traffic or inject padding.

use rand::Rng;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicProfile {
    ModbusTcp,
    MqttSensor,
    StandardHttps,
}

/// A state in the Markov chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficState {
    Idle,
    SmallBurst,
    LargeBurst,
}

pub struct BehaviorSynthesizer {
    profile: MimicProfile,
    current_state: TrafficState,
}

impl BehaviorSynthesizer {
    pub fn new(profile: MimicProfile) -> Self {
        Self {
            profile,
            current_state: TrafficState::Idle,
        }
    }

    /// Predict the next packet size and delay based on the current state.
    pub fn next_step(&mut self) -> (usize, Duration) {
        let mut rng = rand::thread_rng();

        // State transition logic
        self.current_state = match self.current_state {
            TrafficState::Idle => {
                if rng.gen_bool(0.1) { TrafficState::SmallBurst } else { TrafficState::Idle }
            }
            TrafficState::SmallBurst => {
                if rng.gen_bool(0.4) { TrafficState::LargeBurst } else if rng.gen_bool(0.3) { TrafficState::Idle } else { TrafficState::SmallBurst }
            }
            TrafficState::LargeBurst => {
                if rng.gen_bool(0.6) { TrafficState::Idle } else { TrafficState::SmallBurst }
            }
        };

        // Size and delay generation based on profile and state
        match self.profile {
            MimicProfile::ModbusTcp => self.gen_modbus_step(),
            MimicProfile::MqttSensor => self.gen_mqtt_step(),
            MimicProfile::StandardHttps => self.gen_https_step(),
        }
    }

    fn gen_modbus_step(&self) -> (usize, Duration) {
        let mut rng = rand::thread_rng();
        match self.current_state {
            TrafficState::Idle => (0, Duration::from_millis(rng.gen_range(100..500))),
            TrafficState::SmallBurst => (rng.gen_range(12..24), Duration::from_millis(rng.gen_range(10..50))),
            TrafficState::LargeBurst => (rng.gen_range(25..256), Duration::from_millis(rng.gen_range(5..20))),
        }
    }

    fn gen_mqtt_step(&self) -> (usize, Duration) {
        let mut rng = rand::thread_rng();
        match self.current_state {
            TrafficState::Idle => (0, Duration::from_secs(rng.gen_range(1..10))),
            TrafficState::SmallBurst => (rng.gen_range(2..64), Duration::from_millis(rng.gen_range(50..200))),
            TrafficState::LargeBurst => (rng.gen_range(65..512), Duration::from_millis(rng.gen_range(100..500))),
        }
    }

    fn gen_https_step(&self) -> (usize, Duration) {
        let mut rng = rand::thread_rng();
        match self.current_state {
            TrafficState::Idle => (0, Duration::from_millis(rng.gen_range(500..2000))),
            TrafficState::SmallBurst => (rng.gen_range(100..512), Duration::from_millis(rng.gen_range(20..100))),
            TrafficState::LargeBurst => (rng.gen_range(513..1460), Duration::from_millis(rng.gen_range(5..30))),
        }
    }
}
