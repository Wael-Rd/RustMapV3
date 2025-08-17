use crate::scanner::{ScanConfig, ScanResults, Scanner};
use crate::targets::Target;
use crate::Result;
use tracing::info;

#[derive(Clone)]
pub struct FallbackScanner { rustscan_args: Option<String>, scan_cfg: ScanConfig }
impl FallbackScanner { pub fn new(rustscan_args: Option<String>, scan_cfg: ScanConfig) -> Self { Self { rustscan_args, scan_cfg } }
    pub async fn scan_targets(&self, targets: &[Target], ports: &[u16]) -> Result<Vec<ScanResults>> {
        if self.rustscan_args.is_some() { info!("RustScan args were provided, but internal high-speed scanner is used for stability."); }
        let scanner = Scanner::new(self.scan_cfg.clone()); scanner.scan_targets(targets, ports).await
    }
}