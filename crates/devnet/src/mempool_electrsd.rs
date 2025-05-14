//! Electrsd
//!
//! Utility to run a regtest electrs process (v3.2.0+), useful in integration‑testing
//! environments.  This version has been rewritten to match the *Mempool Electrum Rust
//! Server* 3.x CLI (see `electrs --help` output pasted in the prompt).  The wrapper
//! retains the same public surface as the original crate wherever possible, while
//! dropping obsolete arguments (e.g. `--daemon-p2p-addr`, `--cookie-file`) and
//! embracing the new flags.

#![warn(missing_docs)]

use corepc_node::anyhow::Context;
use corepc_node::get_available_port;
use corepc_node::serde_json::Value;
use corepc_node::tempfile::TempDir;
use corepc_node::{anyhow, Node};
use log::{debug, warn};
use std::env;
use std::ffi::OsStr;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub use corepc_node;

// -----------------------------------------------------------------------------
// Configuration ---------------------------------------------------------------
// -----------------------------------------------------------------------------

/// Electrs configuration parameters.  A convenient [`Default`] impl is provided
/// for the most common test‑net setup (regtest, quiet stderr, no HTTP).
///
/// ````
/// let mut conf = electrsd::Conf::default();
/// conf.view_stderr = true;              // show electrs logs while debugging
/// conf.http_enabled = true;             // expose Mempool‑style HTTP API
/// conf.network = "regtest";            // must match bitcoind network
/// conf.tmpdir = None;                   // tmpdir autoselected under /tmp
/// conf.staticdir = None;                // using a temp dir by default
/// ````
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config<'a> {
    /// Extra command‑line arguments to pass to *electrs* **after** the ones that
    /// this wrapper sets automatically.
    pub args: Vec<&'a str>,

    /// If `true`, *electrs* stderr is inherited by the current process.  When
    /// `false` the output is discarded.
    pub view_stderr: bool,

    /// If `true`, the wrapper opens an Mempool HTTP endpoint by passing
    /// `--http-addr` (and `--monitoring-addr` is always set regardless).
    pub http_enabled: bool,

    /// Which Bitcoin network electrs should index — must match the attached
    /// bitcoind instance (`mainnet`, `testnet`, `signet`, or `regtest`).
    pub network: &'a str,

    /// Directory configuration for electrs data storage.
    pub data_dir: DataDirConfig,

    /// Number of spawn retries on port‑allocation races.
    attempts: u8,
}

/// Configuration for electrs data directory storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDirConfig {
    /// Use a temporary directory that will be automatically cleaned up
    Temporary(Option<PathBuf>),
    /// Use a persistent directory that will be left intact
    Persistent(PathBuf),
}

impl Default for Config<'_> {
    fn default() -> Self {
        Self {
            args: vec!["-vvvvv", "--timestamp"],
            view_stderr: false,
            http_enabled: true,
            network: "regtest",
            data_dir: DataDirConfig::Temporary(None),
            attempts: 3,
        }
    }
}

// -----------------------------------------------------------------------------
// MempoolElectrsD wrapper -----------------------------------------------------
// -----------------------------------------------------------------------------

/// Handle to a running *electrs* process.  When dropped the underlying process
/// is terminated (gently on Unix with SIGINT, force‑killed on Windows).
pub struct MempoolElectrsD {
    process: Child,

    work_dir: DataDir,
    /// `ip:port` string for the Electrum JSONRPC endpoint (tcp).
    pub electrum_url: String,
    /// Optional `http://ip:port` string for the Mempool HTTP API.
    pub mempool_http_url: Option<String>,
}

/// Represents whether the electrs datadir is temporary (deleted automatically)
/// or persistent (left intact on drop).
pub enum DataDir {
    /// Persistent working directory owned by the caller.
    Persistent(PathBuf),
    /// Ephemeral directory removed when the tempdir handle is dropped.
    Temporary(TempDir),
}

impl DataDir {
    fn path(&self) -> PathBuf {
        match self {
            Self::Persistent(p) => p.clone(),
            Self::Temporary(t) => t.path().to_path_buf(),
        }
    }
}
struct SetupArgs {
    args: Vec<String>,
    work_dir: DataDir,
    electrum_url: String,
    mempool_http_url: Option<String>,
}

/// Parse a string like "tcp://127.0.0.1:60401" or "127.0.0.1:60401" into a [`SocketAddr`].
fn parse_tcp_addr(url: &str) -> anyhow::Result<SocketAddr> {
    let stripped = url.strip_prefix("tcp://").unwrap_or(url);
    stripped
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid electrum url: {url}"))
}

impl MempoolElectrsD {
    // ---------------------------------------------------------------------
    // Constructors ---------------------------------------------------------
    // ---------------------------------------------------------------------

    /// Spawn *electrs* (binary at `exe`) wired to the provided `bitcoind`
    /// instance with default [`Conf`].
    pub fn new<S: AsRef<OsStr>>(exe: S, bitcoind: &Node) -> anyhow::Result<Self> {
        let mut conf = Config::default();
        Self::with_conf(&mut conf, bitcoind, exe)
    }

    fn setup_args(conf: &Config, bitcoind: &Node) -> anyhow::Result<SetupArgs> {
        if bitcoind
            .client
            .call::<Value>("getblockchaininfo", &[])?
            .get("initialblockdownload")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let addr = bitcoind.client.call::<Value>("getnewaddress", &[])?;
            bitcoind
                .client
                .call::<Value>("generatetoaddress", &[1.into(), addr])?;
        }

        // -------------------------- Work directory ------------------------
        let work_dir = match &conf.data_dir {
            DataDirConfig::Persistent(p) => {
                std::fs::create_dir_all(p)?;
                DataDir::Persistent(p.clone())
            }
            DataDirConfig::Temporary(root) => match root {
                Some(root) => DataDir::Temporary(TempDir::new_in(root)?),
                None => match env::var("TEMPDIR_ROOT").map(PathBuf::from) {
                    Ok(root) => DataDir::Temporary(TempDir::new_in(root)?),
                    Err(_) => DataDir::Temporary(TempDir::new()?),
                },
            },
        };

        // ------------------------- Build CLI args -------------------------
        let mut args = conf.args.clone();

        // Database directory
        let db_dir = work_dir.path();
        let db_dir_str = db_dir.to_string_lossy();
        args.extend(["--db-dir", &db_dir_str]);

        // Network selection
        args.extend(["--network", conf.network]);

        // Import via JSONRPC instead of blk*.dat files
        args.push("--jsonrpc-import");

        // Cookie
        let cookie_value = std::fs::read_to_string(&bitcoind.params.cookie_file)
            .context("reading bitcoind .cookie file")?;
        args.extend(["--cookie", cookie_value.trim()]);

        // Bitcoind RPC URI
        let rpc_socket = bitcoind.params.rpc_socket.to_string();
        args.extend(["--daemon-rpc-addr", &rpc_socket]);

        // Electrum RPC (TCP)
        let electrum_url = format!("0.0.0.0:{}", get_available_port()?);
        args.extend(["--electrum-rpc-addr", &electrum_url]);

        // Monitoring (Prometheus metrics)
        let monitoring_url = format!("0.0.0.0:{}", get_available_port()?);
        args.extend(["--monitoring-addr", &monitoring_url]);

        let url = format!("0.0.0.0:{}", get_available_port()?);

        // Optional Mempool HTTP API
        let mempool_http_url = if conf.http_enabled {
            args.extend(["--http-addr", url.as_str()]);
            Some(format!("http://{}", url))
        } else {
            None
        };

        debug!("electrs args: {args:?}");
        Ok(SetupArgs {
            args: args.into_iter().map(|s| s.to_string()).collect(),
            work_dir,
            electrum_url,
            mempool_http_url,
        })
    }

    /// Spawn *electrs* with a custom [`Conf`].
    pub fn with_conf<S: AsRef<OsStr>>(
        conf: &Config,
        bitcoind: &Node,
        exe: S,
    ) -> anyhow::Result<Self> {
        let mut attempts = conf.attempts;

        let (process, work_dir, electrum_url, mempool_http_url) = loop {
            // ----- retry gate -----
            if attempts == 0 {
                return Err(Error::RetryFailed.into());
            }

            // Build CLI args & temp dirs.
            let setup_args = Self::setup_args(conf, bitcoind)?;
            let electrum_addr = parse_tcp_addr(&setup_args.electrum_url)?;

            // Pipe electrs' stderr when requested.
            let view_stderr = if conf.view_stderr {
                Stdio::inherit()
            } else {
                Stdio::null()
            };

            let mut process = Command::new(&exe)
                .args(&setup_args.args)
                .stderr(view_stderr)
                .spawn()
                .with_context(|| format!("Error executing {:?}", exe.as_ref()))?;

            let res: Option<(Child, DataDir, String, Option<String>)> = loop {
                // a) try the TCP socket first
                match TcpStream::connect_timeout(&electrum_addr, Duration::from_secs(1)) {
                    Ok(stream) => {
                        drop(stream); // success – electrs is live
                        break Some((
                            process,
                            setup_args.work_dir,
                            setup_args.electrum_url,
                            setup_args.mempool_http_url,
                        ));
                    }
                    Err(_) => {
                        // socket not live yet – fall through to process / timeout checks
                    }
                }

                // b) did the child exit prematurely?
                if let Some(status) = process.try_wait()? {
                    eprintln!("electrs exited early with {status:?}; retrying...");
                    break None; // will hit the retry branch below
                }
                std::thread::sleep(Duration::from_millis(250));
            };
            // ------------------- end inner loop ------------------------
            match res {
                Some(res) => break res,
                None => {
                    // keep polling
                }
            }

            // Prepare for another attempt.
            attempts -= 1;
        };

        Ok(Self {
            process,
            work_dir,
            electrum_url,
            mempool_http_url,
        })
    }

    /// Returns the effective electrs data directory.
    pub fn workdir(&self) -> PathBuf {
        self.work_dir.path()
    }

    /// Gracefully terminate the electrs process.
    pub fn kill(&mut self) -> anyhow::Result<()> {
        match &self.work_dir {
            DataDir::Persistent(_) => {
                self.inner_kill()?;
                self.process.wait()?;
                Ok(())
            }
            DataDir::Temporary(_) => Ok(self.process.kill()?),
        }
    }

    fn inner_kill(&mut self) -> anyhow::Result<()> {
        Ok(self.process.kill()?)
    }
}

impl Drop for MempoolElectrsD {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

/// Returns the path to the electrs executable
pub fn exe_path() -> anyhow::Result<String> {
    if let Ok(path) = std::env::var("ELECTRS_EXE") {
        return Ok(path);
    }

    // TODO: remove this once we have a way to download the electrs executable
    /*
    if let Ok(path) = downloaded_exe_path() {
        return Ok(path);
    }
    */
    which::which("electrs")
        .map_err(|_| Error::NoElectrsExecutableFound.into())
        .map(|p| p.display().to_string())
}
/// All the possible error in this crate
#[derive(Debug)]
pub enum Error {
    /// Wrapper of io Error
    Io(std::io::Error),

    /// Wrapper of bitcoind Error
    Bitcoind(corepc_node::Error),

    /// Wrapper of early exit status
    EarlyExit(std::process::ExitStatus),

    RetryFailed,

    /// Returned when calling methods requiring the bitcoind executable but none is found
    /// (no feature, no `ELECTRS_EXEC`, no `electrs` in `PATH` )
    NoElectrsExecutableFound,

    /// Returned if both env vars `ELECTRS_EXEC` and `ELECTRS_EXE` are found
    BothEnvVars,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Bitcoind(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<corepc_node::Error> for Error {
    fn from(e: corepc_node::Error) -> Self {
        Error::Bitcoind(e)
    }
}

// -----------------------------------------------------------------------------
// Tests -----------------------------------------------------------------------
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use crate::mempool_electrs_rest_client::{BaseClient, ReqwestClient};

    use super::*;
    use corepc_node::P2P;
    use log::{debug, log_enabled, Level};
    use reqwest::Url;

    fn init() -> (String, String) {
        let _ = env_logger::try_init();
        let bitcoind_exe = corepc_node::exe_path().unwrap();
        let electrs_exe = exe_path().unwrap();
        (bitcoind_exe, electrs_exe)
    }

    pub fn setup() -> (String, corepc_node::Node, MempoolElectrsD) {
        let (bitcoind_exe, electrs_exe) = init();
        debug!("bitcoind -> {}", bitcoind_exe);
        debug!("electrs  -> {}", electrs_exe);

        let mut btc_conf = corepc_node::Conf::default();
        btc_conf.view_stdout = log_enabled!(Level::Debug);
        btc_conf.p2p = P2P::No;

        let bitcoind = corepc_node::Node::with_conf(&bitcoind_exe, &btc_conf).unwrap();

        let electrs_conf = Config {
            view_stderr: true,
            http_enabled: true,
            ..Default::default()
        };

        let electrsd = MempoolElectrsD::with_conf(&electrs_conf, &bitcoind, &electrs_exe).unwrap();
        (electrs_exe, bitcoind, electrsd)
    }
    #[test]
    fn test_mempool_electrsd_crashes_on_dead_bitcoind() {
        let (bitcoind_exe, electrs_exe) = init();
        debug!("bitcoind -> {}", bitcoind_exe);
        debug!("electrs  -> {}", electrs_exe);

        let mut btc_conf = corepc_node::Conf::default();
        btc_conf.view_stdout = log_enabled!(Level::Debug);
        btc_conf.p2p = P2P::No;

        let mut bitcoind = corepc_node::Node::with_conf(&bitcoind_exe, &btc_conf).unwrap();

        let electrs_conf = Config {
            view_stderr: false,
            http_enabled: true,
            ..Default::default()
        };
        bitcoind.stop().unwrap();

        let electrsd = MempoolElectrsD::with_conf(&electrs_conf, &bitcoind, &electrs_exe);
        assert!(electrsd.is_err());
    }

    #[tokio::test]
    async fn test_mempool_electrsd_http_api() {
        let (_, corepc_node, electrsd) = setup();
        let mempool_http_url = electrsd.mempool_http_url.clone().unwrap();
        let client = ReqwestClient::new(Url::parse(mempool_http_url.as_str()).unwrap());
        let height = client.blocks_tip_height().await.unwrap();
        println!("height = {}", height);
        assert!(height > 0);

        let address = corepc_node.client.new_address().unwrap();
        corepc_node.client.generate_to_address(1, &address).unwrap();

        loop {
            let address = client.address_overview(&address.to_string()).await.unwrap();
            if address.chain_stats.tx_count > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let address_str = address.to_string();

        // Test /address/ endpoint
        let address = client.address_overview(&address_str).await.unwrap();
        println!("address = {:?}", address);
        assert!(address.chain_stats.tx_count > 0);

        // Test /address/txs endpoint
        let txs = client.address_txs(&address_str).await.unwrap();
        println!("txs = {:?}", txs);
        assert!(!txs.is_empty());

        // Test /blocks/tip/hash endpoint
        let hash = client.blocks_tip_hash().await.unwrap();
        println!("hash = {:?}", hash);
    }
}
