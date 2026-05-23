// src/kernel/ebpf_loader.rs
use crate::error::Result;
use aya::Bpf;
use aya::programs::{Xdp, XdpFlags};
use tracing::{info, warn};

pub struct EbpfLoader {
    bpf: Option<Bpf>,
}

impl EbpfLoader {
    pub fn new() -> Self {
        Self { bpf: None }
    }

    pub fn load_xdp(&mut self, interface: &str, bytecode: &[u8]) -> Result<()> {
        info!("eBPF: Loading XDP program onto interface {}", interface);
        
        let mut bpf = Bpf::load(bytecode).map_err(|e| anyhow::anyhow!("Bpf::load failed: {}", e))?;
        let program: &mut Xdp = bpf.program_mut("rustray_xdp")
            .ok_or_else(|| anyhow::anyhow!("Program 'rustray_xdp' not found in bytecode"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Program type conversion failed: {}", e))?;

        program.load().map_err(|e| anyhow::anyhow!("Program::load failed: {}", e))?;
        program.attach(interface, XdpFlags::default())
            .map_err(|e| anyhow::anyhow!("Program::attach failed: {}", e))?;

        info!("eBPF: XDP program attached successfully");
        self.bpf = Some(bpf);
        Ok(())
    }

    pub fn unload(&mut self) {
        if let Some(_bpf) = self.bpf.take() {
            warn!("eBPF: Unloading XDP program");
            // Programs are detached automatically when dropped in Aya
        }
    }
}
