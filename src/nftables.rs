#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use anyhow::{bail, Context, Result};
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

    pub fn run(&mut self, cmd: String) -> Result<()> {
        let cmd = CString::new(cmd).context("nftables command contains null byte")?;
        match unsafe { nft_run_cmd_from_buffer(self.ctx, cmd.as_ptr()) } {
            0 => Ok(()),
            ret => bail!("nft_run_cmd_from_buffer failed with return code {}", ret),
        }
    }
}

impl Default for Nftables {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Nftables {
    fn drop(&mut self) {
        unsafe { nft_ctx_free(self.ctx) };
    }
}
