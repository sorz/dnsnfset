#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use std::ffi::CString;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));


pub struct Nftables {
    ctx: *mut nft_ctx,
}


impl Nftables {
    pub fn new() -> Self {
        let ctx = unsafe { nft_ctx_new(0) };
        Self { ctx }
    }

    pub fn run(&mut self, cmd: String) -> Result<(), ()> {
        let cmd = CString::new(cmd).map_err(|_| ())?;
        match unsafe { nft_run_cmd_from_buffer(self.ctx, cmd.as_ptr()) } {
            0 => Ok(()),
            _ => Err(()),
        }
    }
}

impl Drop for Nftables {
    fn drop(&mut self) {
        unsafe { nft_ctx_free(self.ctx) };
    }
}

