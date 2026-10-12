//! Opaque access to the existing authenticated actor; no independent operation ledger.
use super::{
    native_process::{NativeCallerKey, NativeClient, NativeKeyedHandle, NativeUploadObservation},
    ProcessOpts,
};
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
    sync::Arc,
    time::Duration,
};

#[derive(Clone)]
pub struct NativeControl {
    client: Arc<NativeClient>,
    epoch: u64,
}
impl std::fmt::Debug for NativeControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeControl")
            .field("route_epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Exec {
        command: String,
        args: Vec<String>,
        env: HashMap<String, String>,
        cwd: Option<String>,
        timeout_ms: u64,
    },
    FileRead {
        path: String,
        offset: u64,
        length: usize,
    },
    FileWrite {
        path: String,
        offset: u64,
        data: String,
    },
    UploadBegin {
        path: String,
        size: u64,
        sha256: String,
        create_parents: bool,
    },
    UploadChunk {
        sequence: u64,
        data: String,
    },
    UploadCommit {},
    DownloadBegin {
        path: String,
        max_bytes: u64,
    },
    DownloadReceive {},
    DownloadRead {
        offset: u64,
        length: usize,
    },
    ExecRead {
        stream: String,
        offset: usize,
        length: usize,
    },
    Query {},
    Cancel {},
    Stat {
        path: String,
    },
    List {
        path: String,
    },
    Mkdir {
        path: String,
    },
    ListNext {
        cursor: u64,
    },
    ListPage {
        cursor: u64,
    },
}
impl NativeControl {
    pub(crate) fn new(client: Arc<NativeClient>) -> Self {
        Self { client, epoch: 0 }
    }
    pub(crate) fn publish(mut self, epoch: u64) -> Result<Self> {
        self.client.bind_caller_epoch(epoch)?;
        self.epoch = epoch;
        Ok(self)
    }
    #[cfg(test)]
    pub(crate) fn test_pair(epoch: u64) -> (Self, tokio::io::DuplexStream) {
        let (control, peer) = Self::test_unpublished_pair();
        (control.publish(epoch).unwrap(), peer)
    }
    #[cfg(test)]
    pub(crate) fn test_unpublished_pair() -> (Self, tokio::io::DuplexStream) {
        let (host, peer) = tokio::io::duplex(131072);
        let (r, w) = tokio::io::split(host);
        let framing =
            super::native_process::NativeFraming::new("n", "o", 1, &"a".repeat(64)).unwrap();
        let client = NativeClient::install_with_downloads(
            tokio::io::BufReader::new(r),
            w,
            std::time::Instant::now() + Duration::from_secs(30),
            framing,
            None,
        );
        (Self::new(client), peer)
    }
    #[cfg(test)]
    pub(crate) fn original_truth_test(
        &self,
        digest: [u8; 32],
        operation_id: &str,
    ) -> Option<(bool, bool, u64, usize, usize, usize)> {
        self.client.keyed_truth_for_test(&NativeCallerKey {
            api_key_sha256: digest,
            epoch: self.epoch,
            operation_id: operation_id.into(),
        })
    }
    #[cfg(test)]
    pub(crate) fn close_test(&self) {
        self.client.close();
    }
    pub(crate) fn available(&self) -> bool {
        self.client.is_ready()
    }
    pub(crate) fn operations(&self) -> Vec<&'static str> {
        let mut operations = vec![
            "exec",
            "exec_read",
            "file_read",
            "file_write",
            "upload_begin",
            "upload_chunk",
            "upload_commit",
            "query",
            "cancel",
            "stat",
            "list",
            "mkdir",
            "list_next",
            "list_page",
        ];
        if self.client.download_available() {
            operations.extend(["download_begin", "download_receive", "download_read"]);
        }
        // Keep the implemented-and-qualified fence exercised without advertising
        // an unimplemented request kind.
        debug_assert!(!self.client.directory_available());
        operations
    }
    pub(crate) fn epoch(&self) -> &str {
        self.client.incarnation()
    }
    pub(crate) fn route_epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn close_admission(&self) {
        self.client.close_caller_admission();
    }
    pub(crate) fn reopen_admission(&self) -> Result<()> {
        self.client.reopen_caller_admission(self.epoch)
    }
    pub(crate) fn uncertain(&self, digest: [u8; 32], epoch: &str, operation_id: String) {
        if epoch != self.epoch() {
            return;
        }
        self.client.mark_keyed_uncertain(&NativeCallerKey {
            api_key_sha256: digest,
            epoch: self.epoch,
            operation_id,
        });
    }
    /// Synchronous admission to the same keyed actor. Callers may hold their
    /// original admission fence across this operation; no I/O future is polled.
    pub(crate) fn admit_exec(
        &self,
        digest: [u8; 32],
        epoch: &str,
        operation_id: String,
        request: Request,
    ) -> Result<Value> {
        if epoch != self.epoch() || self.epoch == 0 {
            bail!("native epoch unavailable");
        }
        let Request::Exec {
            command,
            args,
            env,
            cwd,
            timeout_ms,
        } = request
        else {
            bail!("native exec admission kind refused");
        };
        if timeout_ms == 0 || timeout_ms > 240000 {
            bail!("native exec timeout refused");
        }
        let key = NativeCallerKey {
            api_key_sha256: digest,
            epoch: self.epoch,
            operation_id,
        };
        let opts = ProcessOpts {
            envs: env,
            cwd,
            timeout: Some(Duration::from_millis(timeout_ms)),
            output_callback: None,
        };
        let args: Vec<_> = args.iter().map(String::as_str).collect();
        let identity = self
            .client
            .start_keyed(key.clone(), &command, &args, &opts)?
            .identity;
        Ok(
            json!({"kind":"accepted","epoch":epoch,"session_id":identity.session_id,
            "operation_id":identity.operation_id,"caller_operation_id":key.operation_id}),
        )
    }
    pub(crate) async fn dispatch(
        &self,
        digest: [u8; 32],
        epoch: &str,
        operation_id: String,
        request: Request,
    ) -> Result<Value> {
        if epoch != self.epoch() || self.epoch == 0 {
            bail!("native epoch unavailable");
        }
        if matches!(request, Request::Exec { .. }) {
            return self.admit_exec(digest, epoch, operation_id, request);
        }
        let key = NativeCallerKey {
            api_key_sha256: digest,
            epoch: self.epoch,
            operation_id,
        };
        let admitted = match request {
            Request::Exec { .. } => bail!("native exec admission branch refused"),
            Request::FileRead {
                path,
                offset,
                length,
            } => Some(
                self.client
                    .start_file_read_keyed(
                        key.clone(),
                        &path,
                        offset,
                        u64::try_from(length)
                            .map_err(|_| anyhow::anyhow!("native file length refused"))?,
                    )?
                    .identity()
                    .clone(),
            ),
            Request::FileWrite { path, offset, data } => Some(
                self.client
                    .start_file_write_keyed(key.clone(), &path, offset, &decode(&data)?)?
                    .identity()
                    .clone(),
            ),
            Request::UploadBegin {
                path,
                size,
                sha256,
                create_parents,
            } => Some(
                self.client
                    .start_upload_keyed(key.clone(), &path, size, &sha256, create_parents)?
                    .identity()
                    .clone(),
            ),
            Request::DownloadBegin { path, max_bytes } => Some(
                self.client
                    .start_download_keyed(key.clone(), &path, max_bytes)
                    .await?
                    .identity()
                    .clone(),
            ),
            Request::Cancel {} => Some(self.client.cancel_keyed(&key).await?),
            Request::DownloadReceive {} => Some(self.client.register_keyed_receive(&key).await?),
            Request::ExecRead {
                stream,
                offset,
                length,
            } => return self.client.keyed_output(&key, &stream, offset, length),
            Request::Stat { path } => Some(
                self.client
                    .start_metadata("file_stat", &path, Some(key.clone()))?
                    .identity()
                    .clone(),
            ),
            Request::List { path } => Some(
                self.client
                    .start_metadata("list_begin", &path, Some(key.clone()))?
                    .identity()
                    .clone(),
            ),
            Request::Mkdir { path } => Some(
                self.client
                    .start_metadata("make_dir", &path, Some(key.clone()))?
                    .identity()
                    .clone(),
            ),
            phase => return self.phase(&key, phase).await,
        };
        let id = admitted.expect("admitted identity");
        Ok(
            json!({"kind":"accepted","epoch":epoch,"session_id":id.session_id,"operation_id":id.operation_id,"caller_operation_id":key.operation_id}),
        )
    }
    async fn phase(&self, key: &NativeCallerKey, request: Request) -> Result<Value> {
        let owner = self
            .client
            .keyed_handle(key)?
            .ok_or_else(|| anyhow::anyhow!("native original absent"))?;
        let payload = match (owner, request) {
            (NativeKeyedHandle::Exec(h), Request::Query {}) => {
                let s = h.query_status().await?;
                json!({"kind":"status","session_id":s.identity.session_id,"operation_id":s.identity.operation_id,"state":s.state,"exit_code":s.exit_code,"stdout_bytes":s.stdout_bytes,"stderr_bytes":s.stderr_bytes,"process_absent":s.process_absent,"acked_sequence":s.acked_sequence,"terminal":s.terminal})
            }
            (NativeKeyedHandle::Metadata(h), Request::Query {}) => {
                let receipt = h.query().await?;
                let mut value = serde_json::to_value(receipt)?;
                value["complete"] = json!(h.complete());
                value["session_id"] = json!(h.identity().session_id);
                value["operation_id"] = json!(h.identity().operation_id);
                value
            }
            (NativeKeyedHandle::Metadata(h), Request::ListNext { cursor }) => {
                let receipt = h.next(cursor).await?;
                let mut value = serde_json::to_value(receipt)?;
                value["complete"] = json!(h.complete());
                value["session_id"] = json!(h.identity().session_id);
                value["operation_id"] = json!(h.identity().operation_id);
                value
            }
            (NativeKeyedHandle::Metadata(h), Request::ListPage { cursor }) => {
                let page = h.cached_page(cursor)?;
                let mut value = serde_json::to_value(page)?;
                value["kind"] = json!("list_page");
                value["complete"] = json!(h.complete());
                value["session_id"] = json!(h.identity().session_id);
                value["operation_id"] = json!(h.identity().operation_id);
                value
            }
            (NativeKeyedHandle::File(h), Request::Query {}) => {
                let r = h.query_result().await?;
                json!({"kind":"file_result","session_id":r.identity.session_id,"operation_id":r.identity.operation_id,"path":r.path,"offset":r.offset,"data":STANDARD.encode(r.data),"sha256":r.sha256})
            }
            (NativeKeyedHandle::Upload(h), Request::Query {}) => upload(h.query().await?),
            (NativeKeyedHandle::Upload(h), Request::UploadChunk { sequence, data }) => {
                upload(h.write_chunk_at(sequence, &decode(&data)?).await?)
            }
            (NativeKeyedHandle::Upload(h), Request::UploadCommit {}) => {
                upload(h.commit_once().await?)
            }
            (NativeKeyedHandle::Download(h), Request::Query {}) => {
                let (progress, result) = h.query_any().await?;
                if let Some(r) = result {
                    json!({"kind":"download_result","session_id":r.identity.session_id,"operation_id":r.identity.operation_id,"path":r.path,"size":r.size,"sha256":r.sha256})
                } else {
                    let r = progress
                        .ok_or_else(|| anyhow::anyhow!("native download truth unavailable"))?;
                    json!({"kind":"download_progress","session_id":r.identity.session_id,"operation_id":r.identity.operation_id,"path":r.path,"size":r.size,"sha256":r.sha256,"preparing":r.preparing,"next_sequence":r.next_sequence,"retained_sequence":r.retained_sequence})
                }
            }
            (NativeKeyedHandle::Download(h), Request::DownloadRead { offset, length }) => {
                if length == 0 || length > 16384 {
                    bail!("native download read bounds");
                }
                let r = h.query_result().await?;
                if offset > r.size {
                    bail!("native download read bounds");
                }
                let mut reader = r.open_read()?;
                reader.seek(SeekFrom::Start(offset))?;
                let n = (r.size - offset).min(length as u64) as usize;
                let mut data = vec![0; n];
                reader.read_exact(&mut data)?;
                json!({"kind":"download_data","session_id":r.identity.session_id,"operation_id":r.identity.operation_id,"offset":offset,"data":STANDARD.encode(data),"size":r.size,"sha256":r.sha256})
            }
            (NativeKeyedHandle::Pending(id), Request::Query {}) => {
                let pending = self.client.keyed_backing_pending(key)?;
                if pending {
                    json!({"kind":"pending","session_id":id.session_id,"operation_id":id.operation_id})
                } else {
                    json!({"kind":"status","state":"unknown","session_id":id.session_id,"operation_id":id.operation_id})
                }
            }
            _ => bail!("native original phase refused"),
        };
        let response =
            json!({"epoch":self.epoch(),"caller_operation_id":key.operation_id,"result":payload});
        if serde_json::to_vec(&response)?.len() > 65536 {
            bail!("native metadata response bounds");
        }
        Ok(response)
    }
}
fn decode(s: &str) -> Result<Vec<u8>> {
    if s.len() > 21848 {
        bail!("native data bounds");
    }
    let data = STANDARD.decode(s)?;
    if data.len() > 16384 || STANDARD.encode(&data) != s {
        bail!("native data canonicality");
    }
    Ok(data)
}
fn upload(o: NativeUploadObservation) -> Value {
    match o {
        NativeUploadObservation::Progress(r) => {
            json!({"kind":"upload_progress","session_id":r.identity.session_id,"operation_id":r.identity.operation_id,"received":r.received,"next_sequence":r.next_sequence})
        }
        NativeUploadObservation::Complete(r) => {
            json!({"kind":"upload_result","session_id":r.identity.session_id,"operation_id":r.identity.operation_id,"path":r.path,"size":r.size,"sha256":r.sha256})
        }
    }
}
