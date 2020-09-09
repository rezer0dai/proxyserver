#![crate_type = "cdylib"]
#![feature(asm)]

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

extern crate winapi;
extern crate kernel32;

extern crate generic;

mod cfg;

mod hooker;

use std::{thread, time};

pub fn main() {
    unsafe {
        hooker::hook();

        asm!("int3");

        thread::sleep(time::Duration::from_millis(1000 * 10));
    }
}
