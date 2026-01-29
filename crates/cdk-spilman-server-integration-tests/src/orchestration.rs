//! Process orchestration for mint and server processes.
//!
//! This module handles spawning, monitoring, and cleanup of:
//! - CDK mint daemon (`cdk-mintd`)
//! - ASCII art servers (TS, Rust, Python, Go)

use std::env;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::time::sleep;

/// Find an available port by binding to port 0
pub fn find_available_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("Failed to bind to port 0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Get the project root directory (where Cargo.toml workspace is)
pub fn project_root() -> PathBuf {
    // This crate is at crates/cdk-spilman-server-integration-tests
    // Project root is two levels up
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Server type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerType {
    TypeScript,
    Rust,
    Python,
    Go,
}

impl ServerType {
    /// Parse from environment variable
    pub fn from_env() -> Result<Self> {
        let server_type = env::var("SERVER_TYPE").unwrap_or_else(|_| "ts".to_string());
        match server_type.to_lowercase().as_str() {
            "ts" | "typescript" => Ok(Self::TypeScript),
            "rust" | "rs" => Ok(Self::Rust),
            "python" | "py" => Ok(Self::Python),
            "go" | "golang" => Ok(Self::Go),
            _ => Err(anyhow!(
                "Unknown SERVER_TYPE '{}'. Use: ts, rust, python, or go",
                server_type
            )),
        }
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            Self::TypeScript => "TypeScript",
            Self::Rust => "Rust",
            Self::Python => "Python",
            Self::Go => "Go",
        }
    }
}

/// A running mint process
pub struct MintProcess {
    child: Child,
    pub port: u16,
    pub url: String,
}

impl MintProcess {
    /// Spawn a new CDK mint using the existing shell script
    pub async fn spawn() -> Result<Self> {
        let port = find_available_port()?;
        let root = project_root();

        // Use the existing run_temporary_mint.sh script
        let script_path = root.join("scripts/run_temporary_mint.sh");

        tracing::info!("Starting mint on port {} using {}", port, script_path.display());

        let child = Command::new(&script_path)
            .arg("cdk")
            .arg(port.to_string())
            .current_dir(&root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn mint process")?;

        let url = format!("http://localhost:{}", port);
        let mut mint = Self { child, port, url };

        // Wait for mint to be ready
        mint.wait_for_ready().await?;

        Ok(mint)
    }

    /// Wait for the mint to be ready by polling /v1/info
    async fn wait_for_ready(&mut self) -> Result<()> {
        let client = reqwest::Client::new();
        let info_url = format!("{}/v1/info", self.url);

        for i in 0..60 {
            match client.get(&info_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("Mint ready after {} attempts", i + 1);
                    return Ok(());
                }
                _ => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        Err(anyhow!("Mint failed to become ready within 30 seconds"))
    }
}

impl Drop for MintProcess {
    fn drop(&mut self) {
        tracing::info!("Stopping mint on port {}", self.port);

        // Try graceful shutdown first
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(self.child.id().to_string())
                .exec();
        }

        // Force kill if still running
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A running server process
pub struct ServerProcess {
    child: Child,
    pub port: u16,
    pub base_url: String,
    pub server_type: ServerType,
}

impl ServerProcess {
    /// Spawn a server of the specified type
    pub async fn spawn(server_type: ServerType, mint_url: &str) -> Result<Self> {
        let port = find_available_port()?;
        let root = project_root();

        tracing::info!(
            "Starting {} server on port {} with mint {}",
            server_type.name(),
            port,
            mint_url
        );

        let child = match server_type {
            ServerType::TypeScript => Self::spawn_ts_server(&root, port, mint_url)?,
            ServerType::Rust => Self::spawn_rust_server(&root, port, mint_url)?,
            ServerType::Python => Self::spawn_python_server(&root, port, mint_url)?,
            ServerType::Go => Self::spawn_go_server(&root, port, mint_url)?,
        };

        let base_url = format!("http://localhost:{}", port);
        let mut server = Self {
            child,
            port,
            base_url,
            server_type,
        };

        // Wait for server to be ready
        server.wait_for_ready().await?;

        Ok(server)
    }

    fn spawn_ts_server(root: &Path, port: u16, mint_url: &str) -> Result<Child> {
        let server_dir = root.join("examples/ts-ascii-art");

        Command::new("npx")
            .args(["tsx", "src/index.ts", "server"])
            .env("PORT", port.to_string())
            .env("MINT_URL", mint_url)
            .current_dir(&server_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn TypeScript server")
    }

    fn spawn_rust_server(root: &Path, port: u16, mint_url: &str) -> Result<Child> {
        let binary = root.join("target/debug/cdk-ascii-art");

        Command::new(&binary)
            .env("PORT", port.to_string())
            .env("MINT_URL", mint_url)
            .current_dir(root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn Rust server")
    }

    fn spawn_python_server(root: &Path, port: u16, mint_url: &str) -> Result<Child> {
        let server_dir = root.join("examples/python-ascii-art");
        let venv_python = root.join("examples/python-ascii-art/.venv/bin/python");

        // Use venv python if available, otherwise system python
        let python = if venv_python.exists() {
            venv_python
        } else {
            PathBuf::from("python3")
        };

        Command::new(&python)
            .arg("server.py")
            .env("PORT", port.to_string())
            .env("MINT_URL", mint_url)
            .current_dir(&server_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn Python server")
    }

    fn spawn_go_server(root: &Path, port: u16, mint_url: &str) -> Result<Child> {
        let server_dir = root.join("examples/go-ascii-art");
        let ld_library_path = root.join("target/debug");

        Command::new("go")
            .args(["run", ".", "server"])
            .env("PORT", port.to_string())
            .env("MINT_URL", mint_url)
            .env("LD_LIBRARY_PATH", &ld_library_path)
            .current_dir(&server_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn Go server")
    }

    /// Wait for the server to be ready by polling /channel/params
    async fn wait_for_ready(&mut self) -> Result<()> {
        let client = reqwest::Client::new();
        let params_url = format!("{}/channel/params", self.base_url);

        for i in 0..60 {
            match client.get(&params_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        "{} server ready after {} attempts",
                        self.server_type.name(),
                        i + 1
                    );
                    return Ok(());
                }
                _ => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // Dump any output from the server for debugging
        self.dump_output();

        Err(anyhow!(
            "{} server failed to become ready within 30 seconds",
            self.server_type.name()
        ))
    }

    /// Dump stdout/stderr for debugging
    fn dump_output(&mut self) {
        if let Some(stdout) = self.child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines().take(20).flatten() {
                tracing::error!("Server stdout: {}", line);
            }
        }
        if let Some(stderr) = self.child.stderr.take() {
            let reader = BufReader::new(stderr);
            for line in reader.lines().take(20).flatten() {
                tracing::error!("Server stderr: {}", line);
            }
        }
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        tracing::info!(
            "Stopping {} server on port {}",
            self.server_type.name(),
            self.port
        );

        // Force kill - servers don't need graceful shutdown
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Test environment with mint and server
pub struct TestEnvironment {
    pub mint: MintProcess,
    pub server: ServerProcess,
}

impl TestEnvironment {
    /// Create a new test environment with the specified server type
    pub async fn new(server_type: ServerType) -> Result<Self> {
        // Check if we should use external mint/server
        if let Ok(mint_url) = env::var("MINT_URL") {
            if let Ok(server_port) = env::var("SERVER_PORT") {
                tracing::info!(
                    "Using external mint at {} and server on port {}",
                    mint_url,
                    server_port
                );
                // TODO: Support external processes for development
                return Err(anyhow!("External mint/server not yet supported"));
            }
        }

        // Spawn our own mint and server
        let mint = MintProcess::spawn().await?;
        let server = ServerProcess::spawn(server_type, &mint.url).await?;

        Ok(Self { mint, server })
    }

    /// Get the mint URL
    pub fn mint_url(&self) -> &str {
        &self.mint.url
    }

    /// Get the server base URL
    pub fn server_url(&self) -> &str {
        &self.server.base_url
    }
}
