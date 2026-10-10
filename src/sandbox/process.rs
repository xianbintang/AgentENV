use super::native_process::{
    NativeClient, NativeDownloadHandle, NativeFileHandle, NativeHandle, NativeIdentity,
    NativeStatus, NativeUploadHandle,
};
use std::{collections::HashMap, sync::Arc};

use anyhow::{bail, Context, Result};
use futures::{FutureExt, StreamExt};
use tokio::time::Duration;
use tonic::Request;

use envd::filesystem::MakeDirRequest;
use envd::process::{
    process_event, process_input, process_selector, ProcessClient, ProcessConfig, ProcessInput,
    ProcessSelector, SendInputRequest, SendSignalRequest, Signal, StartRequest, StartResponse,
};

use super::envd::EnvdInstance;

const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

fn guest_request<T>(message: T, root_user: bool) -> Request<T> {
    let mut request = Request::new(message);
    if root_user {
        // envd uses HTTP Basic's username to select the guest account.
        request.metadata_mut().insert(
            "authorization",
            tonic::metadata::MetadataValue::from_static("Basic cm9vdDo="),
        );
    }
    request
}

/// Receives stdout/stderr chunks while the process is being awaited.
#[derive(Clone)]
pub struct ProcessOutputCallback(Arc<OutputCallback>);

type OutputCallback = dyn Fn(bool, &[u8]) + Send + Sync;

impl std::fmt::Debug for ProcessOutputCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProcessOutputCallback")
    }
}

/// Options for starting a process inside the sandbox.
#[derive(Clone, Debug, Default)]
pub struct ProcessOpts {
    /// Environment variables to set for the process.
    pub envs: HashMap<String, String>,
    /// Working directory. If `None`, the process inherits the envd default.
    pub cwd: Option<String>,
    /// Maximum time to wait for the process to complete.
    pub timeout: Option<Duration>,
    pub output_callback: Option<ProcessOutputCallback>,
}

impl ProcessOpts {
    pub fn with_output_callback(
        mut self,
        callback: impl Fn(bool, &[u8]) + Send + Sync + 'static,
    ) -> Self {
        self.output_callback = Some(ProcessOutputCallback(Arc::new(callback)));
        self
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Set environment variables (builder-style).
    pub fn with_envs(mut self, envs: HashMap<String, String>) -> Self {
        self.envs = envs;
        self
    }

    /// Set working directory (builder-style).
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set execution timeout (builder-style).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// The result of a completed process execution.
#[derive(Clone, Debug)]
pub struct ProcessOutput {
    /// Combined standard output.
    pub stdout: String,
    /// Combined standard error.
    pub stderr: String,
    /// Process exit code.
    pub exit_code: i32,
}

/// Handle to a running process inside the sandbox.
///
/// Created by [`SandboxExecutor::start_process`][crate::sandbox::SandboxExecutor::start_process].
/// Can be used to stream output, send stdin, or kill the process.
struct EnvdProcessHandle {
    pid: u32,
    client: ProcessClient,
    stream: tonic::Streaming<StartResponse>,
    output_callback: Option<ProcessOutputCallback>,
    timeout: Option<Duration>,
    root_user: bool,
}

impl EnvdProcessHandle {
    /// The PID of the running process inside the guest VM.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait for the process to exit and collect all remaining output.
    pub async fn wait(&mut self) -> Result<ProcessOutput> {
        let mut stdout = String::new();
        let mut stderr = String::new();

        let collect = async {
            while let Some(response) = self.stream.next().await {
                let resp = response.context("gRPC stream error")?;
                let Some(event_wrapper) = resp.event else {
                    continue;
                };
                match event_wrapper.event {
                    Some(process_event::Event::Data(data_event)) => {
                        if let Some(callback) = &self.output_callback {
                            match &data_event.output {
                                Some(process_event::data_event::Output::Stdout(bytes)) => {
                                    (callback.0)(false, bytes)
                                }
                                Some(process_event::data_event::Output::Stderr(bytes)) => {
                                    (callback.0)(true, bytes)
                                }
                                _ => {}
                            }
                        }
                        Self::collect_output(&data_event, &mut stdout, &mut stderr);
                        if stdout.len() + stderr.len() > MAX_OUTPUT_BYTES {
                            bail!(
                                "process output exceeded maximum allowed size ({MAX_OUTPUT_BYTES} bytes)"
                            );
                        }
                    }
                    Some(process_event::Event::End(end_event)) => {
                        return Ok(ProcessOutput {
                            stdout,
                            stderr,
                            exit_code: end_event.exit_code,
                        });
                    }
                    _ => {}
                }
            }
            bail!("process stream ended without an exit event");
        };

        match self.timeout {
            Some(timeout) => match tokio::time::timeout(timeout, collect).await {
                Ok(res) => res,
                Err(_) => {
                    // Best-effort cleanup to avoid leaving an orphaned process running.
                    let _ = self.kill().await;
                    bail!("process timed out after {timeout:?}");
                }
            },
            None => collect.await,
        }
    }

    /// Send data to the process's standard input.
    pub async fn send_stdin(&mut self, data: &[u8]) -> Result<()> {
        let selector = ProcessSelector {
            selector: Some(process_selector::Selector::Pid(self.pid)),
        };
        self.client
            .send_input(guest_request(
                SendInputRequest {
                    process: Some(selector),
                    input: Some(ProcessInput {
                        input: Some(process_input::Input::Stdin(data.to_vec())),
                    }),
                },
                self.root_user,
            ))
            .await
            .context("failed to send stdin")?;
        Ok(())
    }

    /// Send a signal to the process (e.g. SIGTERM, SIGKILL).
    pub async fn send_signal(&mut self, signal: Signal) -> Result<()> {
        let selector = ProcessSelector {
            selector: Some(process_selector::Selector::Pid(self.pid)),
        };
        self.client
            .send_signal(guest_request(
                SendSignalRequest {
                    process: Some(selector),
                    signal: signal as i32,
                },
                self.root_user,
            ))
            .boxed()
            .await
            .context("failed to send signal")?;
        Ok(())
    }

    /// Kill the process with SIGKILL.
    pub async fn kill(&mut self) -> Result<()> {
        self.send_signal(Signal::Sigkill).await
    }

    /// Extract stdout/stderr from a DataEvent into the provided buffers.
    fn collect_output(
        data_event: &process_event::DataEvent,
        stdout: &mut String,
        stderr: &mut String,
    ) {
        match &data_event.output {
            Some(process_event::data_event::Output::Stdout(bytes)) => {
                stdout.push_str(&String::from_utf8_lossy(bytes));
            }
            Some(process_event::data_event::Output::Stderr(bytes)) => {
                stderr.push_str(&String::from_utf8_lossy(bytes));
            }
            _ => {}
        }
    }
}

pub struct ProcessHandle {
    inner: ProcessKind,
}
enum ProcessKind {
    Envd(Box<EnvdProcessHandle>),
    Native(NativeHandle),
}
impl ProcessHandle {
    pub fn pid(&self) -> Option<u32> {
        match &self.inner {
            ProcessKind::Envd(h) => Some(h.pid()),
            ProcessKind::Native(_) => None,
        }
    }
    pub fn native_identity(&self) -> Option<&NativeIdentity> {
        match &self.inner {
            ProcessKind::Native(h) => Some(&h.identity),
            _ => None,
        }
    }
    pub async fn wait(&mut self) -> Result<ProcessOutput> {
        match &mut self.inner {
            ProcessKind::Envd(h) => h.wait().await,
            ProcessKind::Native(h) => h.wait().await,
        }
    }
    pub async fn send_stdin(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.inner {
            ProcessKind::Envd(h) => h.send_stdin(data).await,
            ProcessKind::Native(_) => bail!("native stdin unsupported"),
        }
    }
    pub async fn send_signal(&mut self, signal: Signal) -> Result<()> {
        match &mut self.inner {
            ProcessKind::Envd(h) => h.send_signal(signal).await,
            ProcessKind::Native(_) => bail!("native arbitrary signals unsupported"),
        }
    }
    pub async fn kill(&mut self) -> Result<()> {
        match &mut self.inner {
            ProcessKind::Envd(h) => h.kill().await,
            ProcessKind::Native(h) => h.control("cancel").await,
        }
    }
    pub async fn query_native_status(&self) -> Result<NativeStatus> {
        match &self.inner {
            ProcessKind::Native(h) => h.query_status().await,
            _ => bail!("process is not native"),
        }
    }
    pub async fn query_native(&self) -> Result<()> {
        match &self.inner {
            ProcessKind::Native(h) => h.control("query").await,
            _ => bail!("process is not native"),
        }
    }
}

// ── Executor ──────────────────────────────────────────────────────────────────

/// A handle for executing processes inside a running sandbox.
///
/// Obtained via [`SandboxExecutor::executor`][crate::sandbox::SandboxExecutor::executor].
/// Owns the sandbox's envd connection settings or its original native actor.
pub struct Executor {
    backend: ExecutorBackend,
    root_user: bool,
}

enum ExecutorBackend {
    Envd(EnvdInstance),
    Native(Arc<NativeClient>),
}
impl Executor {
    pub(crate) fn for_endpoint(address: String, token: Option<super::EnvdAccessToken>) -> Self {
        Self::new(EnvdInstance::new(address, token))
    }
    pub(super) fn new(envd_instance: EnvdInstance) -> Self {
        Self {
            backend: ExecutorBackend::Envd(envd_instance),
            root_user: false,
        }
    }
    pub(super) fn native(client: Arc<NativeClient>) -> Self {
        Self {
            backend: ExecutorBackend::Native(client),
            root_user: false,
        }
    }
    /// Select root for internal filesystem maintenance, independently of USER.
    pub(super) fn with_root_user(mut self) -> Self {
        self.root_user = true;
        self
    }

    /// Run a command and wait for it to complete.
    pub async fn run_command(&self, cmd: &str, args: &[&str]) -> Result<ProcessOutput> {
        self.run_command_with_opts(cmd, args, &ProcessOpts::default())
            .await
    }

    /// Run a command with custom options and wait for it to complete.
    pub async fn run_command_with_opts(
        &self,
        cmd: &str,
        args: &[&str],
        opts: &ProcessOpts,
    ) -> Result<ProcessOutput> {
        let mut handle = self
            .start_process_inner(cmd, args, opts, false)
            .boxed()
            .await?;
        handle.wait().boxed().await
    }

    /// Start a long-running process and return a [`ProcessHandle`].
    pub async fn start_process(
        &self,
        cmd: &str,
        args: &[&str],
        opts: &ProcessOpts,
    ) -> Result<ProcessHandle> {
        self.start_process_inner(cmd, args, opts, true).await
    }

    /// Admit a protected bounded host spool before starting one original download.
    pub async fn start_native_download(
        &self,
        path: &str,
        max_bytes: u64,
    ) -> Result<NativeDownloadHandle> {
        match &self.backend {
            ExecutorBackend::Native(client) => client.start_download(path, max_bytes).await,
            ExecutorBackend::Envd(_) => bail!("native download requires native executor"),
        }
    }

    /// Begin one in-place whole-file upload under its original identity.
    pub fn start_native_upload(
        &self,
        path: &str,
        size: u64,
        sha256: &str,
        create_parents: bool,
    ) -> Result<NativeUploadHandle> {
        match &self.backend {
            ExecutorBackend::Native(client) => {
                client.start_upload(path, size, sha256, create_parents)
            }
            ExecutorBackend::Envd(_) => bail!("native upload requires native executor"),
        }
    }

    pub fn start_native_stat(&self, path: &str) -> Result<super::NativeMetadataHandle> {
        self.native_metadata("file_stat", path)
    }
    pub fn start_native_mkdir(&self, path: &str) -> Result<super::NativeMetadataHandle> {
        self.native_metadata("make_dir", path)
    }
    pub fn start_native_list(&self, path: &str) -> Result<super::NativeMetadataHandle> {
        self.native_metadata("list_begin", path)
    }
    fn native_metadata(&self, kind: &str, path: &str) -> Result<super::NativeMetadataHandle> {
        match &self.backend {
            ExecutorBackend::Native(client) => client.start_metadata(kind, path, None),
            ExecutorBackend::Envd(_) => bail!("native metadata requires native executor"),
        }
    }

    /// Reserve one confined native read chunk (1..=16384 bytes).
    /// The returned original identity remains queryable after an uncertain reply.
    pub fn start_native_file_read(
        &self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<NativeFileHandle> {
        match &self.backend {
            ExecutorBackend::Native(client) => client.start_file_read(path, offset, length),
            ExecutorBackend::Envd(_) => bail!("native file read requires native executor"),
        }
    }

    /// Reserve one confined native write chunk (0..=16384 bytes).
    /// This does not truncate, create parent directories, or replace a whole file.
    pub fn start_native_file_write(
        &self,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<NativeFileHandle> {
        match &self.backend {
            ExecutorBackend::Native(client) => client.start_file_write(path, offset, data),
            ExecutorBackend::Envd(_) => bail!("native file write requires native executor"),
        }
    }

    /// Create a directory (and any missing parents) inside the sandbox via
    /// envd's filesystem service, so no binary from the guest image is
    /// involved. An already-existing directory is not an error, matching
    /// `mkdir -p` semantics.
    pub async fn create_dir_all(&self, path: &str) -> Result<()> {
        let ExecutorBackend::Envd(envd_instance) = &self.backend else {
            bail!("native mkdir unsupported");
        };
        let mut client = envd_instance.filesystem_client().await?;
        match client
            .make_dir(guest_request(
                MakeDirRequest {
                    path: path.to_string(),
                },
                self.root_user,
            ))
            .await
        {
            Ok(_) => Ok(()),
            Err(status) if status.code() == tonic::Code::AlreadyExists => Ok(()),
            Err(status) => {
                Err(status).with_context(|| format!("failed to create directory {path} via envd"))
            }
        }
    }

    /// Start a process via the envd gRPC client and return a [`ProcessHandle`].
    async fn start_process_inner(
        &self,
        cmd: &str,
        args: &[&str],
        opts: &ProcessOpts,
        stdin_enabled: bool,
    ) -> Result<ProcessHandle> {
        let envd_instance = match &self.backend {
            ExecutorBackend::Native(client) => {
                anyhow::ensure!(!self.root_user, "native root-user execution unsupported");
                anyhow::ensure!(
                    opts.output_callback.is_none(),
                    "native streaming output callback unsupported"
                );
                return Ok(ProcessHandle {
                    inner: ProcessKind::Native(client.start(cmd, args, opts)?),
                });
            }
            ExecutorBackend::Envd(instance) => instance,
        };
        let request = guest_request(
            StartRequest {
                process: Some(ProcessConfig {
                    cmd: cmd.to_string(),
                    args: args.iter().map(|s| s.to_string()).collect(),
                    envs: opts.envs.clone(),
                    cwd: opts.cwd.clone(),
                }),
                pty: None,
                tag: None,
                stdin: Some(stdin_enabled),
            },
            self.root_user,
        );

        let mut client = envd_instance.process_client().boxed().await?;
        let mut stream = client
            .start(request)
            .boxed()
            .await
            .context("failed to start process via envd")?
            .into_inner();

        // Wait for the StartEvent to learn the PID.
        let pid = Self::wait_for_start_event(&mut stream).boxed().await?;

        Ok(ProcessHandle {
            inner: ProcessKind::Envd(Box::new(EnvdProcessHandle {
                pid,
                client,
                stream,
                timeout: opts.timeout,
                output_callback: opts.output_callback.clone(),
                root_user: self.root_user,
            })),
        })
    }

    /// Consume stream messages until we get the `Start` event with the PID.
    async fn wait_for_start_event(stream: &mut tonic::Streaming<StartResponse>) -> Result<u32> {
        while let Some(response) = stream.next().await {
            let resp = response.context("gRPC stream error while waiting for start event")?;
            let Some(event_wrapper) = resp.event else {
                continue;
            };
            if let Some(process_event::Event::Start(start_event)) = event_wrapper.event {
                return Ok(start_event.pid);
            }
        }
        bail!("process stream closed before receiving start event");
    }
}

#[cfg(test)]
mod tests {
    use super::super::native_process::{NativeCallerKey, NativeFraming};
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[tokio::test]
    async fn native_root_user_refuses_before_same_actor_admission_or_dispatch() -> Result<()> {
        let (host, peer) = tokio::io::duplex(131072);
        let (read, write) = tokio::io::split(host);
        let (peer_read, _peer_write) = tokio::io::split(peer);
        let mut peer_read = BufReader::new(peer_read);
        let client = NativeClient::install(
            BufReader::new(read),
            write,
            std::time::Instant::now() + std::time::Duration::from_secs(3),
            NativeFraming::new("node", "owner", 1, &"a".repeat(64))?,
        );
        let key = NativeCallerKey {
            api_key_sha256: [7; 32],
            epoch: 41,
            operation_id: "original".into(),
        };
        let original = client.start_keyed(key.clone(), "/bin/sh", &[], &ProcessOpts::default())?;
        let mut frame = String::new();
        tokio::time::timeout(Duration::from_secs(1), peer_read.read_line(&mut frame)).await??;
        let frame: serde_json::Value = serde_json::from_str(&frame)?;
        assert_eq!(frame["kind"], "exec");
        assert_eq!(frame["operation_id"], original.identity.operation_id);
        let before = client
            .keyed_truth_for_test(&key)
            .expect("retained original actor record");
        assert_eq!((before.3, before.5), (1, 1));
        let root = Executor::native(client.clone()).with_root_user();
        let ExecutorBackend::Native(held) = &root.backend else {
            panic!("same native actor")
        };
        assert!(Arc::ptr_eq(held, &client));
        for _ in 0..2 {
            let error = root
                .start_process("/bin/sh", &[], &ProcessOpts::default())
                .await
                .err()
                .expect("root request must refuse");
            assert_eq!(error.to_string(), "native root-user execution unsupported");
            assert_eq!(client.keyed_truth_for_test(&key), Some(before));
        }
        let mut absent = String::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer_read.read_line(&mut absent))
                .await
                .is_err()
        );
        // The same actor remains available for ordinary admission; refusal did not seal it.
        let ordinary = Executor::native(client.clone())
            .start_process("/bin/sh", &[], &ProcessOpts::default())
            .await?;
        assert_ne!(
            ordinary
                .native_identity()
                .expect("native original")
                .operation_id,
            original.identity.operation_id
        );
        let after = client
            .keyed_truth_for_test(&key)
            .expect("original retained");
        assert_eq!((after.3, after.5), (2, 2));
        client.close();
        Ok(())
    }
}
