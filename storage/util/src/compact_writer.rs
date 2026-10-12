use anyhow::Result;
use std::{any::Any, future::Future, pin::Pin};

/// Send future returned by the object-safe compact writer methods.
pub type CompactFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A buffer obtained from a [`CompactWriter`].
///
/// Implementations must be fillable as a mutable byte slice. For the
/// default `VirtualFileWriter` this is a plain `Vec<u8>`. For a
/// usrbio/copyd-backed writer this would be an `IovBuffer` pointing into
/// pre-registered shared memory.
pub trait CompactBuffer: AsMut<[u8]> + AsRef<[u8]> + Any + Send {
    /// Access the concrete buffer type for writers that can consume a specific
    /// owned representation without copying.
    fn as_any(&self) -> &dyn Any;

    /// Convert the boxed buffer into [`Any`] so callers can downcast and take
    /// ownership of concrete buffer implementations.
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send>;
}

impl<T> CompactBuffer for T
where
    T: AsMut<[u8]> + AsRef<[u8]> + Any + Send,
{
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

/// Abstraction over the destination writer used by the compact / commit path.
///
/// The write model has two phases (to support zero-copy with shared-memory
/// buffers such as usrbio):
///
/// 1. **`alloc_buffer()`** – obtain a writable buffer.  For shared-memory
///    implementations the returned buffer lives inside a pre-registered
///    memory region.
/// 2. **Fill** the buffer via `buf.as_mut()[..len]` (e.g. read source data
///    directly into the buffer).
/// 3. **`write()`** – submit the filled buffer for writing at the given file
///    offset. The buffer is consumed (and returned to the pool for pooled
///    implementations).
///
/// For small, caller-owned metadata blobs (header, index entries, trailer)
/// use [`write_all_at`](CompactWriter::write_all_at).
pub trait CompactWriter: Send + Sync {
    /// Allocate a writable buffer whose capacity is at least
    /// [`buffer_size()`](CompactWriter::buffer_size) bytes.
    fn alloc_buffer<'life0, 'async_trait>(
        &'life0 self,
    ) -> CompactFuture<'async_trait, Result<Box<dyn CompactBuffer>>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    /// Preferred / fixed buffer size in bytes returned by
    /// [`alloc_buffer`](CompactWriter::alloc_buffer).
    /// The buffer size should align at ALIGNMENT (currently this is 512 B)
    fn buffer_size(&self) -> usize;

    /// Whether writes must use strictly increasing, contiguous logical offsets.
    ///
    /// When this returns `true`, each write must start at the logical end of the
    /// preceding write. The default permits random writes.
    fn requires_ordered_writes(&self) -> bool {
        false
    }

    /// Write the first `len` bytes of `buf` at `offset` in the destination
    /// file. Consumes the buffer (pooled implementations return it on drop).
    /// The `len` param helps if only want to write partial content in `buf`.
    /// If `len` > `buf` size, will return error.
    fn write<'life0, 'async_trait>(
        &'life0 self,
        buf: Box<dyn CompactBuffer>,
        offset: u64,
        len: usize,
    ) -> CompactFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    /// Write a caller-owned byte slice at `offset`. Intended for small
    /// metadata writes (header, index entries, trailer).
    ///
    /// The default implementation chunks the data into buffers obtained from
    /// [`alloc_buffer`](CompactWriter::alloc_buffer) and writes them
    /// sequentially.
    fn write_all_at<'life0, 'life1, 'async_trait>(
        &'life0 self,
        data: &'life1 [u8],
        offset: u64,
    ) -> CompactFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let buf_size = self.buffer_size();
            let mut off = offset;
            for chunk in data.chunks(buf_size) {
                let mut buf = self.alloc_buffer().await?;
                buf.as_mut().as_mut()[..chunk.len()].copy_from_slice(chunk);
                self.write(buf, off, chunk.len()).await?;
                off += chunk.len() as u64;
            }
            Ok(())
        })
    }

    /// Complete format-level output after all writes have finished.
    ///
    /// This does not imply flushing or syncing data to durable storage. The
    /// default implementation is a no-op.
    fn finalize<'life0, 'async_trait>(&'life0 self) -> CompactFuture<'async_trait, Result<()>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { Ok(()) })
    }
}
