#![crate_type = "cdylib"]

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

use std::{
//    self,
    thread,
    sync::Once,
    sync::ONCE_INIT,
    sync::RwLock,
};

extern crate winapi;
extern crate kernel32;

extern crate generic;

mod cfg;
use cfg::VSMBCONFIG;

mod hooker;

mod pipeserver;
use pipeserver::*;

mod vsmbproxy;
use vsmbproxy::VsmbProxy;

lazy_static! {
    static ref VSMBPROXY: RwLock<VsmbProxy> = RwLock::new(VsmbProxy::new());
    static ref SERVER: RwLock<VsmbPipe> = RwLock::new(VsmbPipe::new(&VSMBCONFIG.pipe));
}

static START: Once = ONCE_INIT;

#[no_mangle]
pub extern fn DllMain() -> usize {
    START.call_once(|| {
        thread::spawn(move || {
            unsafe { hooker::hook() }
            recv_loop()
        });
    });
    42
}

// +++++++++++++++++++++++++++++++
//         vmsb pipe
// +++++++++++++++++++++++++++++++

fn recv_loop() {
// seems no cleaner way, singleton
    // let mut server = VsmbPipe::new(&VSMBCONFIG.pipe);
// debug .exe purpose when no loop { ... }
    // { SERVER.read().unwrap(); }
    let mut cache = vec![];
    loop {
//++++++++++++++++++++++++++
// receive data
//++++++++++++++++++++++++++
        let mut data = match SERVER.write() {
            Ok(mut server) => {
                if !server.ready() {//avoid deadlocks
                    continue//though it should be trough set_read_timeout
                }//TODO...
                let size = server.recv_size();
                let mut data = vec![0u8; size as usize];
                server.receive_packet(&mut data);
                data
            }
            Err(msg) => panic!("recv_loop server poisoned: {}", msg)
        };
//++++++++++++++++++++++++++
// proxy it to vmusrv
//++++++++++++++++++++++++++
        match VSMBPROXY.write() {
            Ok(mut vsmb) => vsmb.proxy(data.as_mut_ptr(), data.len() as u32),
            Err(msg) => panic!("recv_loop proxy poisoned: {}", msg)
        };
//++++++++++++++++++++++++++
// save it permanently to vmusrv freely access ( + free ? ) it
//++++++++++++++++++++++++++
        cache.push(data);
    }
}

// +++++++++++++++++++++++++++++++
//         locked hooks
// +++++++++++++++++++++++++++++++

#[no_mangle]
pub unsafe extern fn pkwritepipebytestream(
    unkn0: usize,
    unkn1: usize,
    smb_packet: *mut u8,
    packet_size: u32,
    ) -> usize {

//debug
kernel32::OutputDebugStringA(
    format!("\n>PKTWRITEHO@K!!\0\n").as_ptr() as *const i8);

//lets have it here to be more clean
    let mut server = SERVER.write().unwrap();

//singleton hence hooking
    match VSMBPROXY.read() {
        Ok(vsmb) => vsmb.reply(
                        unkn0,
                        unkn1,
                        smb_packet,
                        packet_size,
                        &mut server,
                        ),
        Err(msg) => panic!("vsmbproxy is unavailable at reply [{:?}]", msg)
    }
}
#[no_mangle]
pub unsafe extern fn writefile(
    unkn0: usize,
    smb_packet: *mut u8,
    packet_size: u32,
    unkn1: usize,
    unkn2: usize,
    ) -> usize {

//debug
kernel32::OutputDebugStringA(
    format!("\n>WRITEFILEHO@K!!\0\n").as_ptr() as *const i8);

//lets have it here to be more clean
    let mut server = SERVER.write().unwrap();

//singleton hence hooking
    match VSMBPROXY.read() {
        Ok(vsmb) => vsmb.reply_ex(
                        unkn0,
                        smb_packet,
                        packet_size,
                        unkn1,
                        unkn2,
                        &mut server,
                        ),
        Err(msg) => panic!("vsmbproxy is unavailable at reply_ex [{:?}]", msg)
    }
}

#[no_mangle]
pub unsafe extern fn smb2_receive(
    srv_connection: usize,
    smb_packet: *mut u8,
    packet_size: u32,
    unkn1: usize,
    unkn2: usize,
    unkn3: usize,
    unkn4: usize,
    unkn5: usize,
    ) -> usize {

//debug
kernel32::OutputDebugStringA(
    format!("\n>SMB2RECeIVEHO@K!!\0\n").as_ptr() as *const i8);

//singleton hence hooking
    match VSMBPROXY.write() {
        Ok(mut vsmb) => vsmb.receive(
                        srv_connection,
                        smb_packet,
                        packet_size,
                        unkn1,
                        unkn2,
                        unkn3,
                        unkn4,
                        unkn5,
                        ),
        Err(msg) => panic!("vsmbproxy is unavailable at receive [{:?}]", msg)
    }
}
