use std::collections::HashMap;

extern crate generic;

use super::cfg::*;
use super::pipeserver::VsmbPipe;

extern crate byteorder;
use self::byteorder::{
    ByteOrder,
    BigEndian,
};

type TSmb2Receive = unsafe extern "system" fn(
    srv_connection: usize,
    smb_packet: *mut u8,
    packet_size: u32,
    unkn1: usize,
    unkn2: usize,
    unkn3: usize,
    unkn4: usize,
    unkn5: usize,
    ) -> usize;

type TPkWritePipeByteStream = unsafe extern "system" fn(
    unkn0: usize,
    unkn1: usize,
    smb_packet: *const u8,
    packet_size: u32,
    ) -> usize;

type TWriteFile = unsafe extern "system" fn(
    unkn0: usize,
    smb_packet: *const u8,
    packet_size: u32,
    unkn1: usize,
    unkn2: usize,
    ) -> usize;

pub struct VsmbProxy {
    msg_id: u64,
    queue: HashMap<u64, u64>,
    smb2_receive: TSmb2Receive,
    smb2_reply: TPkWritePipeByteStream,
    smb2_reply_ex: TWriteFile,

//stand-in for smb2receive replace call
    srv_connection: usize,
    unkn1: usize,
    unkn2: usize,
    unkn3: usize,
    unkn4: usize,
    unkn5: usize,
}

impl VsmbProxy {
    pub fn new() -> VsmbProxy {
        assert!(VSMBCONFIG.vmusrv_hooks[0].hook_symbol.eq("smb2_receive"),
                "first symbol must be smb2_receive");
        assert!(VSMBCONFIG.vmusrv_hooks[1].hook_symbol.eq("pkwritepipebytestream"),
                "second symbol must be pkwritepipebytestream");
        assert!(VSMBCONFIG.vmusrv_hooks[2].hook_symbol.eq("writefile"),
                "second symbol must be writefile");

        VsmbProxy {
            msg_id: 0,
            queue: HashMap::new(),
            smb2_receive: unsafe { std::mem::transmute::<_, TSmb2Receive>(
                VSMBCONFIG.vmusrv_hooks[0].target_offset + generic::get_module("vmusrv")) },
            smb2_reply: unsafe { std::mem::transmute::<_, TPkWritePipeByteStream>(
                VSMBCONFIG.vmusrv_hooks[1].target_offset + generic::get_module("vmusrv")) },
            smb2_reply_ex: unsafe { std::mem::transmute::<_, TWriteFile>(
                generic::load_api("kernel32", "WriteFile") },

            srv_connection: 0,
            unkn1: 0,
            unkn2: 0,
            unkn3: 0,
            unkn4: 0,
            unkn5: 0,
        }
    }
    pub fn receive(
        &mut self,
        srv_connection: usize,
        smb_packet: *mut u8,
        packet_size: u32,
        unkn1: usize,
        unkn2: usize,
        unkn3: usize,
        unkn4: usize,
        unkn5: usize,
        ) -> usize {

        self.srv_connection = srv_connection;

        let packet = unsafe { ::std::slice::from_raw_parts_mut(smb_packet, 0x20) };
        let msg_id = generic::data_unsafe::<u64>(&mut packet[0x18..0x20]);

        if self.queue.contains_key(msg_id) { // blacklist replaced msg
            return 0 // we will send our response instead
            // is ok to send both actually, and more smooth for original
        } else if *msg_id & 0xFFFF000000000000 == 0x6666000000000000 {
            *msg_id = self.msg_id + 1;// recognize our msg
        }

        if *msg_id > self.msg_id { // do to async to check this
            self.msg_id = *msg_id;
        }

        unsafe {
            (self.smb2_receive)(
                srv_connection,
                smb_packet,
                packet_size,
                unkn1,
                unkn2,
                unkn3,
                unkn4,
                unkn5,
                ) }
    }
    fn process_packet(
        &self,
        smb_packet: *mut u8,
        packet_size: u32,
        pipe: &mut VsmbPipe,
        ) {

        let packet = unsafe { ::std::slice::from_raw_parts_mut(smb_packet, 0x24) };

        // let magic = generic::data_unsafe::<u32>(&mut packet[0..4]);
        let magic = *b"\xFESMB" == packet[0..4];
        let msg_id = if magic {
            generic::data_unsafe::<u64>(&mut packet[0x18..0x20])
        } else {
            generic::data_unsafe::<u64>(&mut packet[4+0x18..4+0x20])
        };

        match self.queue.get(msg_id) {
            Some(mid) => {
                if magic {
                    let mut size = [0u8; 4];
                    BigEndian::write_u32(&mut size, packet_size);
                    pipe.send_packet(&size);
                }
                *msg_id = *mid;
                pipe.send_packet( unsafe {
                    ::std::slice::from_raw_parts(smb_packet, packet_size as usize) });
            }
            None => ()
        };
    }
    pub fn reply(
        &self,
        unkn0: usize,
        unkn1: usize,
        smb_packet: *mut u8,
        packet_size: u32,
        pipe: &mut VsmbPipe,
        ) -> usize {

        if 4 != packet_size {
            self.process_packet(smb_packet, packet_size, pipe)
        }

        unsafe {
            (self.smb2_reply)(
                unkn0,
                unkn1,
                smb_packet,
                packet_size,
                ) }
    }
    pub fn reply_ex(
        &self,
        unkn0: usize,
        smb_packet: *mut u8,
        packet_size: u32,
        unkn1: usize,
        unkn2: usize,
        pipe: &mut VsmbPipe,
        ) -> usize {

        if 4 != packet_size {
            self.process_packet(smb_packet, packet_size, pipe)
        }

        unsafe {
            (self.smb2_reply_ex)(
                unkn0,
                smb_packet,
                packet_size,
                unkn1,
                unkn2,
                ) }
    }
    pub fn proxy(&mut self, smb_packet: *mut u8, packet_size: u32) -> bool {
        let unkn1 = self.unkn1;
        let unkn2 = self.unkn2;
        let unkn3 = self.unkn3;
        let unkn4 = self.unkn4;
        let unkn5 = self.unkn5;
        let srv_connection = self.srv_connection;
        assert!(0 != srv_connection);

        let packet = unsafe { ::std::slice::from_raw_parts_mut(smb_packet, 0x20) };
        let msg_id = generic::data_unsafe::<u64>(&mut packet[0x18..0x20]);
        let o_id = *msg_id;

        *msg_id = *msg_id + 0x6666000000000000;

        let status = self.receive(
                srv_connection,
                smb_packet,
                packet_size,
                unkn1,
                unkn2,
                unkn3,
                unkn4,
                unkn5
                );

        assert!(0 == status);
        if 0 != status {
            return false
        }

        self.queue.insert(self.msg_id, o_id);
        true
    }
}
