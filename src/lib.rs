pub mod attestation;
pub mod config;
pub mod config_store;
pub mod escrow;
pub mod handlers;
pub mod jwt;
pub mod kbs;
pub mod ownership;
pub mod proof;
pub mod receipts;
pub mod sev;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tokio::sync::RwLock;
use zeroize::Zeroizing;

use attestation::AaTokenCache;
use config::Config;
use kbs::KbsCacheEntry;
use ownership::{BootstrapChallenge, OwnershipGuard};
use receipts::ReceiptSigner;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub http_client: reqwest::Client,
    pub aa_token_cache: Arc<RwLock<AaTokenCache>>,
    pub kbs_resource_cache: Arc<RwLock<HashMap<String, KbsCacheEntry>>>,
    pub startup_owner_seed: Arc<RwLock<Option<Zeroizing<[u8; 32]>>>>,
    pub ownership: Arc<OwnershipGuard>,
    pub bootstrap_challenges: Arc<Mutex<VecDeque<BootstrapChallenge>>>,
    pub receipt_signer: Arc<ReceiptSigner>,
    pub tls_leaf_spki_sha256: [u8; 32],
}
