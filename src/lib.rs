#![cfg(target_os = "windows")]
#![doc = include_str!("../README.md")]

pub mod error;
pub mod injector;
mod paths;
mod payload;
mod pe;
mod remote;
pub mod strategy;
pub mod target;

pub use error::{Error, Result};
pub use injector::{InjectedModule, Injector, LoadTiming, inject};
pub use strategy::Strategy;
pub use target::{BorrowedTarget, LoaderState, OwnedTarget, Target, find_primary_thread_id};
