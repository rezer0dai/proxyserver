extern crate toml;
extern crate generic;

#[derive(Debug, Deserialize, Serialize)]
pub struct Hook {
    pub target_offset: usize,
    pub hook_symbol: String,
    pub patch_offset: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VsmbConfig {
    pub version: String,
    pub pipe: String,
    pub calltable_offset: usize,
    pub vmusrv_hooks: Vec<Hook>,
}

impl VsmbConfig {
    fn new() -> VsmbConfig {
        let mut cfg: VsmbConfig = match generic::read_file("vsmb.toml") {
            Ok(data) => toml::from_str(&data).unwrap(),
            Err(e) => panic!("vsmb.toml problem! {:?}", e),
        };
        cfg.version.push('\x00');
        cfg
    }
}

lazy_static! {
    pub static ref VSMBCONFIG: VsmbConfig = VsmbConfig::new();
}

