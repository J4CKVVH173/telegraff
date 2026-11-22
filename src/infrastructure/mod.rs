pub mod agent;
pub mod config;
pub mod dns;
pub mod hub;
pub mod notification;
pub mod receiver;
pub mod registration;
pub mod store;
pub mod wire;

pub struct SystemClock;
impl crate::application::ports::Clock for SystemClock {
    fn now(&self) -> u64 {
        crate::utils::unix_time()
    }
}

pub mod process;
pub mod setup;

mod http;
