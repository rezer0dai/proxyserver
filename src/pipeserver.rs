use std::io::{
    Read,
    Write,
    Cursor
};

extern crate byteorder;
use self::byteorder::{
    BigEndian,
};

use pipeserver::byteorder::ReadBytesExt;

extern crate named_pipe;
use self::named_pipe::*;

extern crate generic;

pub struct VsmbPipe {
    pipe: PipeServer,
    wait: bool,
}

impl VsmbPipe {
    pub fn new(pipe_name: &String) -> VsmbPipe {
        let pipe = PipeOptions::new(pipe_name).single().unwrap();
        let pipe = match pipe.wait() {
            Ok(pipe) => pipe,
            Err(msg) => panic!("server <{}> wait fail: {}", pipe_name, msg)
        };
        // pipe.set_read_timeout(Some(std::time::Duration::from_millis(333)));
        VsmbPipe {
            pipe: pipe,
            wait: true,
        }
    }
    pub fn ready(&self) -> bool { self.wait }
    pub fn recv_size(&mut self) -> u32 {
        let mut size = [0u8; 4];
        match self.pipe.read(&mut size) {
            Ok(total) => {
                assert!(total == 4);
                let mut rdr = Cursor::new(size);
                rdr.read_u32::<BigEndian>().unwrap()
            }
            Err(msg) => panic!("recv_loop fail: {}", msg)
        }
    }
    pub fn receive_packet(&mut self, data: &mut[u8]) {
        let total = match self.pipe.read(data) {
            Ok(size) => size,
            Err(msg) => panic!("do_receive fail: {}", msg)
        };
        assert!(total == data.len());
        if total != data.len() {
            panic!("incomplete packet {} vs {}", total, data.len());
        }
        if 2 != data[0x10] {
            self.wait = false;
        }
    }
    pub fn send_packet(&mut self, data: &[u8]) {
        let total = match self.pipe.write(data) {
            Ok(size) => size,
            Err(msg) => panic!("send_packet fail: {}", msg)
        };
        assert!(total == data.len());
        if total != data.len() {
            panic!("incomplete packet {} vs {}", total, data.len());
        }
        self.wait = true;
    }
}
