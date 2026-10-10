use super::*;
use tokio::io::{split, BufReader};

fn key(operation: &str) -> NativeCallerKey {
    NativeCallerKey {
        api_key_sha256: [7; 32],
        epoch: 41,
        operation_id: operation.into(),
    }
}
fn fixture(
    spool: Option<Arc<super::super::native_download::NativeDownloadSpool>>,
) -> (
    Arc<NativeClient>,
    BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    tokio::io::WriteHalf<tokio::io::DuplexStream>,
) {
    let (host, peer) = tokio::io::duplex(131072);
    let (read, write) = split(host);
    let (peer_read, peer_write) = split(peer);
    (
        NativeClient::install_with_downloads(
            BufReader::new(read),
            write,
            Instant::now() + std::time::Duration::from_secs(10),
            minimum_framing(),
            spool,
        ),
        BufReader::new(peer_read),
        peer_write,
    )
}
async fn receive<R: AsyncBufRead + Unpin>(reader: &mut R) -> Envelope {
    serde_json::from_slice(&read_line(reader, &mut Vec::new()).await.unwrap()).unwrap()
}
#[tokio::test]
async fn keyed_exec_duplicate_and_payload_drift_keep_one_original_pipe_effect() {
    let (client, mut reader, mut writer) = fixture(None);
    let first = client
        .start_keyed(
            key("run"),
            "/bin/sh",
            &["-c", "printf x"],
            &ProcessOpts::default(),
        )
        .unwrap();
    let frame = receive(&mut reader).await;
    let Some(NativeKeyedHandle::Exec(recovered)) = client.keyed_handle(&key("run")).unwrap() else {
        panic!("original exec owner")
    };
    assert_eq!(recovered.identity.operation_id, first.identity.operation_id);
    let second = client
        .start_keyed(
            key("run"),
            "/bin/sh",
            &["-c", "printf x"],
            &ProcessOpts::default(),
        )
        .unwrap();
    assert_eq!(first.identity.operation_id, second.identity.operation_id);
    assert_eq!(frame.operation_id, first.identity.operation_id);
    let before = {
        let s = client.state.lock().unwrap();
        (s.records.len(), s.bytes, s.lifetime_admissions)
    };
    assert!(client
        .start_keyed(
            key("run"),
            "/bin/sh",
            &["-c", "printf y"],
            &ProcessOpts::default()
        )
        .is_err());
    assert_eq!(before, {
        let s = client.state.lock().unwrap();
        (s.records.len(), s.bytes, s.lifetime_admissions)
    });
    // This is a trusted broker IPC actor fixture. Its terminal event releases
    // the actor slot; it is not proof of a physical guest process or VM absence.
    let other = client
        .start_keyed(key("other"), "/bin/echo", &[], &ProcessOpts::default())
        .unwrap();
    for identity in [&first.identity, &other.identity] {
        let terminal = Envelope {
            kind: "terminal".into(),
            session_id: identity.session_id.clone(),
            operation_id: identity.operation_id.clone(),
            payload: json!({"state":"succeeded","exit_code":0,"stdout_bytes":0,
                "stderr_bytes":0,"process_absent":true,"acked_sequence":0}),
        };
        let mut raw = serde_json::to_vec(&terminal).unwrap();
        raw.push(b'\n');
        writer.write_all(&raw).await.unwrap();
        writer.flush().await.unwrap();
        if identity.operation_id == first.identity.operation_id {
            let completed = first.wait().await.unwrap();
            assert_eq!(completed.exit_code, 0);
            let dispatched = receive(&mut reader).await;
            assert_eq!(dispatched.kind, "exec");
            assert_eq!(dispatched.operation_id, other.identity.operation_id);
        } else {
            assert_eq!(other.wait().await.unwrap().exit_code, 0);
        }
    }
    let completed_budget = {
        let s = client.state.lock().unwrap();
        assert!(s.records[&first.identity.operation_id].terminal.is_some());
        assert!(s.records[&other.identity.operation_id].terminal.is_some());
        (s.records.len(), s.bytes, s.lifetime_admissions)
    };
    let retry = client
        .start_keyed(
            key("run"),
            "/bin/sh",
            &["-c", "printf x"],
            &ProcessOpts::default(),
        )
        .unwrap();
    assert_eq!(retry.identity.operation_id, first.identity.operation_id);
    assert_eq!(completed_budget, {
        let s = client.state.lock().unwrap();
        (s.records.len(), s.bytes, s.lifetime_admissions)
    });
    // A FIFO Query barrier after the retry proves it did not queue an Exec
    // behind the formerly active slot. No timing-only quiet-pipe assertion.
    other.control("query").await.unwrap();
    let barrier = receive(&mut reader).await;
    assert_eq!(barrier.kind, "query");
    assert_eq!(barrier.operation_id, other.identity.operation_id);
    client.close();
    // Exact retry can still locate the tombstone after transport closes.
    assert_eq!(
        client
            .start_keyed(
                key("run"),
                "/bin/sh",
                &["-c", "printf x"],
                &ProcessOpts::default()
            )
            .unwrap()
            .identity
            .operation_id,
        first.identity.operation_id
    );
}
#[tokio::test]
async fn keyed_file_upload_share_caller_partition_epoch_and_original_payload() {
    let (client, _reader, _writer) = fixture(None);
    let read = client
        .start_file_read_keyed(key("read"), "data", 0, 3)
        .unwrap();
    assert_eq!(
        read.identity.operation_id,
        client
            .start_file_read_keyed(key("read"), "data", 0, 3)
            .unwrap()
            .identity
            .operation_id
    );
    assert!(client
        .start_file_read_keyed(key("read"), "data", 1, 3)
        .is_err());
    assert!(client
        .start_file_write_keyed(key("read"), "data", 0, b"abc")
        .is_err());
    let write = client
        .start_file_write_keyed(key("write"), "data", 0, b"abc")
        .unwrap();
    assert_eq!(
        write.identity.operation_id,
        client
            .start_file_write_keyed(key("write"), "data", 0, b"abc")
            .unwrap()
            .identity
            .operation_id
    );
    assert!(client
        .start_file_write_keyed(key("write"), "data", 0, b"abd")
        .is_err());
    let sha = format!("{:x}", Sha256::digest(b"abc"));
    let upload = client
        .start_upload_keyed(key("upload"), "data", 3, &sha, true)
        .unwrap();
    assert_eq!(
        upload.identity.operation_id,
        client
            .start_upload_keyed(key("upload"), "data", 3, &sha, true)
            .unwrap()
            .identity
            .operation_id
    );
    assert!(client
        .start_upload_keyed(key("upload"), "data", 3, &sha, false)
        .is_err());
    let mut foreign_epoch = key("epoch");
    foreign_epoch.epoch += 1;
    assert!(client
        .start_file_read_keyed(foreign_epoch, "data", 0, 3)
        .is_err());
    let mut other_caller = key("read");
    other_caller.api_key_sha256 = [8; 32];
    let other = client
        .start_file_read_keyed(other_caller, "data", 0, 3)
        .unwrap();
    assert_ne!(other.identity.operation_id, read.identity.operation_id);
    let Some(NativeKeyedHandle::File(recovered_read)) = client.keyed_handle(&key("read")).unwrap()
    else {
        panic!("original file owner")
    };
    assert_eq!(
        recovered_read.identity.operation_id,
        read.identity.operation_id
    );
    let Some(NativeKeyedHandle::Upload(recovered_upload)) =
        client.keyed_handle(&key("upload")).unwrap()
    else {
        panic!("original upload owner")
    };
    assert_eq!(
        recovered_upload.identity.operation_id,
        upload.identity.operation_id
    );
    let state = client.state.lock().unwrap();
    assert_eq!(state.records.len(), 4);
    assert_eq!(state.lifetime_admissions, 4);
    assert!(state.bytes > UPLOAD_RECEIPTS);
    drop(state);
    client.close();
}
#[tokio::test]
async fn keyed_and_sdk_admission_share_lifetime_limit_without_duplicate_charge() {
    let (client, _reader, _writer) = fixture(None);
    let first = client
        .start_keyed(key("original"), "/bin/echo", &[], &ProcessOpts::default())
        .unwrap();
    for _ in 1..32 {
        client
            .start("/bin/echo", &[], &ProcessOpts::default())
            .unwrap();
    }
    let before = {
        let s = client.state.lock().unwrap();
        (s.bytes, s.lifetime_admissions, s.records.len())
    };
    assert_eq!(
        client
            .start_keyed(key("original"), "/bin/echo", &[], &ProcessOpts::default())
            .unwrap()
            .identity
            .operation_id,
        first.identity.operation_id
    );
    assert!(client
        .start_keyed(key("new"), "/bin/echo", &[], &ProcessOpts::default())
        .is_err());
    assert_eq!(before, {
        let s = client.state.lock().unwrap();
        (s.bytes, s.lifetime_admissions, s.records.len())
    });
    client.close();
}
#[tokio::test]
async fn keyed_metadata_exhaustion_refuses_before_identity_or_dispatch() {
    let (client, mut reader, _writer) = fixture(None);
    // A full retained actor budget is a legitimate boundary independent of
    // record slots. No new budget is granted for the public caller partition.
    client.state.lock().unwrap().bytes = OUTPUT;
    assert!(client
        .start_file_read_keyed(key("read"), "data", 0, 1)
        .is_err());
    {
        let s = client.state.lock().unwrap();
        assert!(s.records.is_empty());
        assert_eq!(s.lifetime_admissions, 0);
        assert_eq!(s.bytes, OUTPUT);
        assert!(s.caller_epoch.is_none());
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), receive(&mut reader))
            .await
            .is_err()
    );
    client.close();
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn keyed_download_duplicate_uses_one_actual_spool_and_one_begin() {
    let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
        return;
    };
    let spool = super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
    let (client, mut reader, _writer) = fixture(Some(spool.clone()));
    let first = client
        .start_download_keyed(key("download"), "data", 16384)
        .await
        .unwrap();
    let begin = receive(&mut reader).await;
    let Some(NativeKeyedHandle::Download(recovered)) =
        client.keyed_handle(&key("download")).unwrap()
    else {
        panic!("original download owner")
    };
    let recovered_same = recovered.identity.operation_id == first.identity.operation_id;
    let second = client
        .start_download_keyed(key("download"), "data", 16384)
        .await
        .unwrap();
    let same = first.identity.operation_id == second.identity.operation_id
        && begin.operation_id == first.identity.operation_id;
    let unchanged = {
        let s = client.state.lock().unwrap();
        s.records.len() == 1 && s.lifetime_admissions == 1 && s.bytes > DOWNLOAD_RECEIPTS
    };
    let quota = spool.reserved_bytes();
    let drift = client
        .start_download_keyed(key("download"), "data", 16383)
        .await
        .is_err();
    let absent = tokio::time::timeout(std::time::Duration::from_millis(10), receive(&mut reader))
        .await
        .is_err();
    client.retire_downloads().await.unwrap();
    assert!(same && recovered_same && unchanged && drift && absent);
    assert_eq!(quota, 16384);
    assert_eq!(spool.reserved_bytes(), 0);
}
#[cfg(target_os = "linux")]
async fn pending_download_retirement(explicit_cancel: bool, api_projection: bool) {
    let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
        return;
    };
    let spool = super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
    let (client, mut reader, _writer) = fixture(Some(spool.clone()));
    let control = api_projection.then(|| {
        super::super::NativeControl::new(client.clone())
            .publish(41)
            .unwrap()
    });
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel::<()>();
    let owned = client.clone();
    let original_key = key("pending");
    let admission_key = original_key.clone();
    let mut admission = Some(tokio::spawn(async move {
        owned
            .start_download_keyed_inner(admission_key, "data", 16384, move || {
                let _ = entered.send(());
                let _ = gate.recv_timeout(std::time::Duration::from_secs(2));
            })
            .await
    }));
    observed.await.unwrap();
    let original = client.keyed_identity(&original_key).unwrap().unwrap();
    let pending_identity = match client.keyed_handle(&original_key).unwrap() {
        Some(NativeKeyedHandle::Pending(identity)) => {
            identity.operation_id == original.operation_id
        }
        _ => false,
    };
    let pending_projection = if let Some(control) = &control {
        let result = control
            .dispatch(
                original_key.api_key_sha256,
                control.epoch(),
                original_key.operation_id.clone(),
                super::super::NativeControlRequest::Query {},
            )
            .await;
        result.is_ok_and(|v| {
            v["result"]["kind"] == "pending" && v["result"]["operation_id"] == original.operation_id
        })
    } else {
        true
    };
    let pending = {
        let s = client.state.lock().unwrap();
        let r = &s.records[&original.operation_id];
        r.backing_pending && !r.dispatched && s.lifetime_admissions == 1
    };
    let duplicate_client = client.clone();
    let duplicate_key = original_key.clone();
    let duplicate = tokio::spawn(async move {
        duplicate_client
            .start_download_keyed(duplicate_key, "data", 16384)
            .await
    });
    let cancelled = if explicit_cancel {
        client
            .cancel_keyed(&original_key)
            .await
            .unwrap()
            .operation_id
            == original.operation_id
    } else {
        let owned = admission.take().unwrap();
        owned.abort();
        matches!(owned.await,Err(error) if error.is_cancelled())
    };
    drop(release);
    let result = duplicate.await.unwrap();
    let explicit_result = match admission.take() {
        Some(owned) => owned.await.unwrap().is_err(),
        None => true,
    };
    let before_query = {
        let state = client.state.lock().unwrap();
        (state.records.len(), state.bytes, state.lifetime_admissions)
    };
    let unknown_projection = if let Some(control) = &control {
        let result = control
            .dispatch(
                original_key.api_key_sha256,
                control.epoch(),
                original_key.operation_id.clone(),
                super::super::NativeControlRequest::Query {},
            )
            .await;
        result.is_ok_and(|v| {
            v["result"]["kind"] == "status"
                && v["result"]["state"] == "unknown"
                && v["result"]["operation_id"] == original.operation_id
                && v["result"].get("process_absent").is_none()
        })
    } else {
        true
    };
    let query_no_change = {
        let state = client.state.lock().unwrap();
        (state.records.len(), state.bytes, state.lifetime_admissions) == before_query
    };
    let failed_original = {
        let state = client.state.lock().unwrap();
        let r = &state.records[&original.operation_id];
        r.backing_failed && !r.backing_pending && r.unknown
    };
    client.retire_downloads().await.unwrap();
    let stable = client
        .keyed_identity(&original_key)
        .unwrap()
        .unwrap()
        .operation_id
        == original.operation_id;
    let tombstone = {
        let s = client.state.lock().unwrap();
        s.records.len() == 1
            && s.lifetime_admissions == 1
            && s.records[&original.operation_id].unknown
    };
    let absent = tokio::time::timeout(std::time::Duration::from_millis(10), receive(&mut reader))
        .await
        .is_err();
    assert!(
        pending
            && pending_identity
            && explicit_result
            && cancelled
            && result.is_err()
            && stable
            && tombstone
            && absent
            && pending_projection
            && unknown_projection
            && query_no_change
            && failed_original,
        "pending={pending} pending_identity={pending_identity} explicit_result={explicit_result} cancelled={cancelled} result_err={} stable={stable} tombstone={tombstone} absent={absent} pending_projection={pending_projection} unknown_projection={unknown_projection} query_no_change={query_no_change} failed_original={failed_original}",
        result.is_err()
    );
    assert_eq!(spool.reserved_bytes(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn keyed_download_dropped_pending_keeps_original_tombstone_and_joins_actual_backing() {
    pending_download_retirement(false, false).await;
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn keyed_download_explicit_pending_cancel_never_dispatches_or_allocates_a_retry() {
    pending_download_retirement(true, false).await;
}

#[tokio::test]
async fn upload_chunk_waits_for_exact_prefix_after_previous_heartbeat_without_resend() {
    let (client, mut reader, mut writer) = fixture(None);
    let digest = format!("{:x}", Sha256::digest(b"abc"));
    let upload = Arc::new(client.start_upload("pending", 3, &digest, false).unwrap());
    let begin = receive(&mut reader).await;
    let progress = |received: u64, next: u64| Envelope {
        kind: "upload_progress".into(),
        session_id: begin.session_id.clone(),
        operation_id: begin.operation_id.clone(),
        payload: json!({"path":"pending","size":3,"sha256":digest,
            "received":received,"next_sequence":next}),
    };
    let mut raw = serde_json::to_vec(&progress(0, 0)).unwrap();
    raw.push(b'\n');
    writer.write_all(&raw).await.unwrap();
    upload.wait_ready().await.unwrap();
    let owner = upload.clone();
    let mut chunk = tokio::spawn(async move { owner.write_chunk(b"abc").await });
    let sent = receive(&mut reader).await;
    let actual_original = sent.kind == "upload_chunk"
        && sent.operation_id == begin.operation_id
        && sent.payload["sequence"] == 0;
    // A valid duplicate previous prefix can arrive from an earlier heartbeat
    // after the actual original chunk was sent. It is not the chunk receipt.
    writer.write_all(&raw).await.unwrap();
    let early = tokio::time::timeout(std::time::Duration::from_millis(50), &mut chunk).await;
    let remained_pending = early.is_err();
    let mut target = serde_json::to_vec(&progress(3, 1)).unwrap();
    target.push(b'\n');
    writer.write_all(&target).await.unwrap();
    let completion = match early {
        Ok(result) => result.unwrap(),
        Err(_) => chunk.await.unwrap(),
    };
    let confirmed = completion
        .as_ref()
        .is_ok_and(|p| p.received == 3 && p.next_sequence == 1);
    let original_retained = {
        let state = client.state.lock().unwrap();
        let record = &state.records[&begin.operation_id];
        let transfer = record.upload.as_ref().unwrap();
        state.records.len() == 1
            && state.lifetime_admissions == 1
            && transfer.receipts.len() == 1
            && transfer.sent_chunks == 1
    };
    // FIFO control barrier makes a duplicate chunk visible if waiting requeues
    // the mutation; no automatic Query or write is allowed during the wait.
    let control = NativeHandle {
        client: client.clone(),
        identity: upload.identity.clone(),
    };
    control.control("query").await.unwrap();
    let barrier = receive(&mut reader).await;
    let no_resend = barrier.kind == "query" && barrier.operation_id == begin.operation_id;
    client.close();
    assert!(
        actual_original && remained_pending && confirmed && original_retained && no_resend,
        "original chunk heartbeat race: pending={remained_pending} confirmed={confirmed} completion_failed={}",
        completion.is_err()
    );
}

async fn heartbeat_then_uncertainty(cancel: bool) {
    let (client, mut reader, mut writer) = fixture(None);
    let digest = format!("{:x}", Sha256::digest(b"abc"));
    let upload = Arc::new(client.start_upload("uncertain", 3, &digest, false).unwrap());
    let begin = receive(&mut reader).await;
    let event = Envelope {
        kind: "upload_progress".into(),
        session_id: begin.session_id.clone(),
        operation_id: begin.operation_id.clone(),
        payload: json!({"path":"uncertain","size":3,"sha256":digest,"received":0,"next_sequence":0}),
    };
    let mut raw = serde_json::to_vec(&event).unwrap();
    raw.push(b'\n');
    writer.write_all(&raw).await.unwrap();
    upload.wait_ready().await.unwrap();
    let owned = upload.clone();
    let chunk = tokio::spawn(async move { owned.write_chunk(b"abc").await });
    let sent = receive(&mut reader).await;
    writer.write_all(&raw).await.unwrap();
    if cancel {
        upload.cancel().await.unwrap();
        let cancelled = receive(&mut reader).await;
        assert_eq!(cancelled.kind, "cancel");
        assert_eq!(cancelled.operation_id, begin.operation_id);
    } else {
        let unknown = Envelope {
            kind: "status".into(),
            session_id: begin.session_id.clone(),
            operation_id: begin.operation_id.clone(),
            payload: json!({"state":"unknown"}),
        };
        let mut raw = serde_json::to_vec(&unknown).unwrap();
        raw.push(b'\n');
        writer.write_all(&raw).await.unwrap();
    }
    let rejected = chunk.await.unwrap().is_err();
    let unchanged = {
        let s = client.state.lock().unwrap();
        let r = &s.records[&begin.operation_id];
        let u = r.upload.as_ref().unwrap();
        s.records.len() == 1
            && u.receipts.len() == 1
            && u.sent_chunks == 1
            && u.result.is_none()
            && (r.unknown || u.cancelled)
    };
    let blocked = upload.write_chunk(b"abc").await.is_err() && upload.commit().await.is_err();
    client.close();
    assert!(sent.kind == "upload_chunk" && rejected && unchanged && blocked);
}
#[tokio::test]
async fn prior_upload_heartbeat_never_hides_unknown_or_authorizes_chunk_replay() {
    heartbeat_then_uncertainty(false).await;
}
#[tokio::test]
async fn prior_upload_heartbeat_never_hides_original_cancel_intent() {
    heartbeat_then_uncertainty(true).await;
}

#[tokio::test]
async fn repeated_previous_upload_heartbeat_cannot_extend_original_incarnation_expiry() {
    let (host, peer) = tokio::io::duplex(131072);
    let (read, write) = split(host);
    let (peer_read, mut peer_write) = split(peer);
    let expires = Instant::now() + std::time::Duration::from_millis(200);
    let client = NativeClient::install(BufReader::new(read), write, expires, minimum_framing());
    let mut reader = BufReader::new(peer_read);
    let sha = format!("{:x}", Sha256::digest(b"abc"));
    let upload = Arc::new(client.start_upload("deadline", 3, &sha, false).unwrap());
    let begin = receive(&mut reader).await;
    let event = Envelope {
        kind: "upload_progress".into(),
        session_id: begin.session_id.clone(),
        operation_id: begin.operation_id.clone(),
        payload: json!({"path":"deadline","size":3,"sha256":sha,"received":0,"next_sequence":0}),
    };
    let mut raw = serde_json::to_vec(&event).unwrap();
    raw.push(b'\n');
    peer_write.write_all(&raw).await.unwrap();
    upload.wait_ready().await.unwrap();
    let owned = upload.clone();
    let chunk = tokio::spawn(async move { owned.write_chunk(b"abc").await });
    assert_eq!(receive(&mut reader).await.kind, "upload_chunk");
    let pulses = tokio::spawn(async move {
        let mut emitted = 0;
        for _ in 0..12 {
            if peer_write.write_all(&raw).await.is_err() {
                break;
            }
            emitted += 1;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        emitted
    });
    let rejected = chunk.await.unwrap().is_err();
    let observed_at = Instant::now();
    let heartbeat_count = pulses.await.unwrap();
    let original = {
        let s = client.state.lock().unwrap();
        let r = &s.records[&begin.operation_id];
        let u = r.upload.as_ref().unwrap();
        s.records.len() == 1
            && u.receipts.len() == 1
            && u.sent_chunks == 1
            && u.result.is_none()
            && r.unknown
    };
    client.close();
    assert!(
        rejected
            && original
            && heartbeat_count > 1
            && observed_at >= expires
            && observed_at.duration_since(expires) < std::time::Duration::from_secs(1)
    );
}

#[tokio::test]
async fn already_confirmed_upload_prefix_cannot_succeed_after_absolute_chunk_deadline() {
    let (client, mut reader, mut writer) = fixture(None);
    let sha = format!("{:x}", Sha256::digest(b"abc"));
    let upload = Arc::new(client.start_upload("late", 3, &sha, false).unwrap());
    let begin = receive(&mut reader).await;
    let progress = |bytes: u64, cursor: u64| Envelope {
        kind: "upload_progress".into(),
        session_id: begin.session_id.clone(),
        operation_id: begin.operation_id.clone(),
        payload: json!({"path":"late","size":3,"sha256":sha,"received":bytes,"next_sequence":cursor}),
    };
    let mut raw = serde_json::to_vec(&progress(0, 0)).unwrap();
    raw.push(b'\n');
    writer.write_all(&raw).await.unwrap();
    upload.wait_ready().await.unwrap();
    let owned = upload.clone();
    let chunk = tokio::spawn(async move { owned.write_chunk(b"abc").await });
    let actual = receive(&mut reader).await;
    let mut raw = serde_json::to_vec(&progress(3, 1)).unwrap();
    raw.push(b'\n');
    writer.write_all(&raw).await.unwrap();
    let established = chunk.await.unwrap().unwrap();
    let confirmed = established.received == 3
        && established.next_sequence == 1
        && actual.kind == "upload_chunk"
        && actual.operation_id == begin.operation_id;
    // Exercise an already-ready target using retained truth established through
    // actual actor IPC. The expired waiter must not return that cached prefix.
    let expired = Instant::now() - std::time::Duration::from_millis(1);
    let refused = upload.wait_chunk_prefix(0, 1, 3, expired).await.is_err();
    let retained = {
        let s = client.state.lock().unwrap();
        let r = &s.records[&begin.operation_id];
        let u = r.upload.as_ref().unwrap();
        r.unknown && !u.observed && u.receipts.len() == 1 && u.confirmed == 1 && u.result.is_none()
    };
    let no_advance = upload.write_chunk(b"abc").await.is_err() && upload.commit().await.is_err();
    client.close();
    assert!(confirmed && refused && retained && no_advance);
}

#[tokio::test]
async fn keyed_lifecycle_closure_keeps_original_owner_and_blocks_new_dispatch() {
    let (client, mut reader, _writer) = fixture(None);
    client.bind_caller_epoch(41).unwrap();
    let first = client
        .start_keyed(key("original"), "/bin/echo", &[], &ProcessOpts::default())
        .unwrap();
    client.close_caller_admission();
    let original = client
        .start_keyed(key("original"), "/bin/echo", &[], &ProcessOpts::default())
        .unwrap();
    let denied = client
        .start_keyed(key("second"), "/bin/echo", &[], &ProcessOpts::default())
        .is_err();
    let drift = client.bind_caller_epoch(42).is_err();
    let no_effect =
        tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut reader))
            .await
            .is_err();
    let state = client.state.lock().unwrap();
    let unchanged = state.records.len() == 1
        && state.lifetime_admissions == 1
        && state.records[&first.identity.operation_id].unknown;
    drop(state);
    client.close();
    assert!(denied && drift && no_effect && unchanged);
    assert_eq!(first.identity.operation_id, original.identity.operation_id);
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn keyed_download_unpolled_future_cannot_cross_lifecycle_closure() {
    let Some(namespace) = super::super::native_download::tests::RootFixture::new() else {
        return;
    };
    let spool = super::super::native_download::NativeDownloadSpool::admit(&namespace.path).unwrap();
    let (client, mut reader, _writer) = fixture(Some(spool.clone()));
    client.bind_caller_epoch(41).unwrap();
    let admission = client.start_download_keyed(key("unpolled"), "data", 16384);
    client.close_caller_admission();
    let denied = admission.await.is_err();
    let no_record = {
        let state = client.state.lock().unwrap();
        state.records.is_empty() && state.lifetime_admissions == 0
    };
    let no_effect =
        tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut reader))
            .await
            .is_err();
    let no_backing = spool.reserved_bytes() == 0;
    client.retire_downloads().await.unwrap();
    assert!(denied && no_record && no_effect && no_backing);
}

#[tokio::test]
async fn keyed_upload_duplicate_phase_queries_original_and_changed_bytes_never_write() {
    let (client, mut reader, mut writer) = fixture(None);
    let sha = format!("{:x}", Sha256::digest(b"abc"));
    let upload = Arc::new(
        client
            .start_upload_keyed(key("public-upload"), "data", 3, &sha, false)
            .unwrap(),
    );
    let begin = receive(&mut reader).await;
    let progress = |received, next| Envelope {
        kind: "upload_progress".into(),
        session_id: begin.session_id.clone(),
        operation_id: begin.operation_id.clone(),
        payload: json!({"path":"data","size":3,"sha256":sha,"received":received,"next_sequence":next}),
    };
    let mut raw = serde_json::to_vec(&progress(0, 0)).unwrap();
    raw.push(b'\n');
    writer.write_all(&raw).await.unwrap();
    upload.wait_ready().await.unwrap();
    let owner = upload.clone();
    let first = tokio::spawn(async move { owner.write_chunk_at(0, b"abc").await });
    let chunk = receive(&mut reader).await;
    let mut raw = serde_json::to_vec(&progress(3, 1)).unwrap();
    raw.push(b'\n');
    writer.write_all(&raw).await.unwrap();
    first.await.unwrap().unwrap();
    let owner = upload.clone();
    let duplicate = tokio::spawn(async move { owner.write_chunk_at(0, b"abc").await });
    let query = receive(&mut reader).await;
    writer.write_all(&raw).await.unwrap();
    let duplicate_ok = duplicate.await.unwrap().is_ok();
    let drift = upload.write_chunk_at(0, b"abd").await.is_err();
    let no_write = tokio::time::timeout(std::time::Duration::from_millis(20), receive(&mut reader))
        .await
        .is_err();
    client.close();
    assert!(duplicate_ok && drift && no_write);
    assert_eq!(chunk.kind, "upload_chunk");
    assert_eq!(query.kind, "query");
    assert_eq!(chunk.operation_id, query.operation_id);
    assert_eq!(client.state.lock().unwrap().records.len(), 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn keyed_download_cancelled_tombstone_query_reports_unknown_not_pending() {
    pending_download_retirement(true, true).await;
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn keyed_download_dropped_admission_tombstone_query_reports_unknown_not_pending() {
    pending_download_retirement(false, true).await;
}
