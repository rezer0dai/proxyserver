extern crate winapi;
extern crate kernel32;

extern crate generic;

use std;

use super::cfg::*;

unsafe fn c_callback(api: &String) -> usize {
    std::mem::transmute::<winapi::minwindef::FARPROC, _>(
        generic::load_api("server", api))
}

unsafe fn do_hook(
    ind: u32,
    vmusrv_base: usize,
    calltable_abs: usize,
    hook_offset: usize,
    hook_symbol: &String,
    ) -> usize {
    let calltable_rel = (VSMBCONFIG.calltable_offset - hook_offset) as u32;

    let addr = hook_offset + vmusrv_base;
    let callback = std::mem::transmute::<_, [u8; 8]>(
        c_callback(hook_symbol));

    let mut hook = [ 0x48, 0xff, 0x25, 0, 0, 0, 0 ];
    hook[3..3+4].clone_from_slice(
        generic::any_as_u8_slice(&(calltable_rel + ind*8)));

    generic::mem_patch(addr - hook.len(), &hook);
    generic::mem_patch(calltable_abs + ind as usize * 8, &callback);

    hook.len()
}


pub unsafe fn hook() {
    kernel32::OutputDebugStringA(
        VSMBCONFIG.version.as_ptr() as *const i8);

    let vmusrv_base: usize = generic::get_module("vmusrv");
    let calltable_abs: usize = vmusrv_base + VSMBCONFIG.calltable_offset;

    for (i, vhook) in VSMBCONFIG.vmusrv_hooks
        .iter()
        .enumerate() {
            if 0 == vhook.target_offset {
                continue
            } // we will skip import hook of write file, do it trough windbg instead!
            let hook_len = do_hook(
                i as u32,
                vmusrv_base, calltable_abs,
                vhook.target_offset, &vhook.hook_symbol);

            let addr = vmusrv_base + vhook.patch_offset + 1;
            let hook_loc: u32 = *std::mem::transmute::<_, *const u32>(addr) - hook_len as u32;
            generic::mem_patch(addr, generic::any_as_u8_slice(&hook_loc));
    }
}

