#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use anyhow::{bail, Context, Result};
use std::ffi::CString;

#[allow(clippy::all, unused, non_upper_case_globals, non_camel_case_types, non_snake_case)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
use bindings::*;

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

    pub fn run_with_output(&mut self, cmd: &str) -> Result<String> {
        let cmd_c = CString::new(cmd).context("nftables command contains null byte")?;
        unsafe {
            nft_ctx_buffer_output(self.ctx);
            nft_ctx_buffer_error(self.ctx);
            let ret = nft_run_cmd_from_buffer(self.ctx, cmd_c.as_ptr());
            if ret != 0 {
                let err_ptr = nft_ctx_get_error_buffer(self.ctx);
                let err_msg = if !err_ptr.is_null() {
                    std::ffi::CStr::from_ptr(err_ptr)
                        .to_string_lossy()
                        .into_owned()
                } else {
                    format!("nft_run_cmd_from_buffer failed with return code {}", ret)
                };
                bail!("{}", err_msg.trim());
            }
            let out_ptr = nft_ctx_get_output_buffer(self.ctx);
            let out_str = if !out_ptr.is_null() {
                std::ffi::CStr::from_ptr(out_ptr)
                    .to_string_lossy()
                    .into_owned()
            } else {
                String::new()
            };
            Ok(out_str)
        }
    }

    pub fn list_set_json(
        &mut self,
        family: Option<crate::nft::NftFamily>,
        table: &str,
        set: &str,
    ) -> Result<String> {
        unsafe {
            let current_flags = nft_ctx_output_get_flags(self.ctx);
            nft_ctx_output_set_flags(self.ctx, current_flags | NFT_CTX_OUTPUT_JSON);
            let cmd = if let Some(family) = family {
                format!("list set {} {} {}", family, table, set)
            } else {
                format!("list set {} {}", table, set)
            };
            let res = self.run_with_output(&cmd);
            nft_ctx_output_set_flags(self.ctx, current_flags);
            res
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
