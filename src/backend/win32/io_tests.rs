use std::fs::File;
use std::io::Read;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};

use futures_lite::future::{block_on, poll_once};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_INBOUND;
use windows::Win32::System::Pipes::{CreateNamedPipeW, DisconnectNamedPipe, PIPE_TYPE_BYTE, PIPE_WAIT};
use windows::Win32::System::Threading::WaitForSingleObject;

use super::*;

const REPORT_SIZE: usize = 65_536;

fn pipe() -> (File, Arc<Device>) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name: Vec<u16> = format!(
        "\\\\.\\pipe\\openlogi-write-regression-{}-{}\0",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
    .encode_utf16()
    .collect();
    // SAFETY: name is NUL-terminated and live for this call. The returned
    // server handle is owned by File and closed once when that File drops.
    let handle = unsafe { CreateNamedPipeW(PCWSTR(name.as_ptr()), PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 1, 1, 0, None) };
    assert!(!handle.is_invalid(), "create test pipe: {}", windows::core::Error::from_win32());
    // SAFETY: ownership of the valid, unique handle is transferred to File.
    let server = unsafe { File::from_raw_handle(handle.0) };
    let client = Arc::new(Device::open(PCWSTR(name.as_ptr()), false, true).expect("open pipe writer"));
    (server, client)
}

fn disconnect<T>(server: &File, buffer: &IoBuffer<T>) {
    // SAFETY: server owns this live named-pipe handle. No server read is active.
    unsafe { DisconnectNamedPipe(HANDLE(server.as_raw_handle())) }.expect("disconnect test server");
    // SAFETY: the buffer and its OVERLAPPED/event remain live. A bounded wait
    // observes kernel completion without timing sleeps or mutating I/O state.
    let result = unsafe { WaitForSingleObject((*buffer.overlapped.as_raw()).hEvent, 5_000) };
    assert_eq!(result, WAIT_OBJECT_0, "abandoned I/O must finish after disconnect");
}

#[test]
fn abandoned_write_disconnect_allows_next_operation_without_panicking() {
    let (server, device) = pipe();
    let mut buffer = IoBuffer::<Writable>::new(device, REPORT_SIZE).expect("allocate write buffer");
    let first = vec![0x51; REPORT_SIZE];
    assert!(block_on(poll_once(buffer.write(&first))).is_none(), "write must await the unread pipe");
    assert!(buffer.pending);
    disconnect(&server, &buffer);

    let result = catch_unwind(AssertUnwindSafe(|| block_on(buffer.write(&[0xA7]))));
    result
        .expect("a new write on a disconnected transport must return an error, not panic")
        .expect_err("disconnected transport");
    assert!(!buffer.pending, "terminal failure must not leave stale pending state");
    assert_eq!(buffer.buffer[0], 0xA7, "the new write was attempted");
}

#[test]
fn abandoned_feature_write_disconnect_allows_next_ioctl_without_panicking() {
    let (server, device) = pipe();
    let mut buffer = IoBuffer::<Feature>::new(device, REPORT_SIZE).expect("allocate feature buffer");
    buffer.buffer.fill(0x52);
    // Exercise the shared OVERLAPPED owner with a real pending Windows operation.
    // A pipe cannot accept HID feature IOCTLs; the new call should reach that
    // IOCTL and return its error after consuming the abandoned operation.
    buffer
        .start_io(|device, data, overlapped| {
            // SAFETY: start_io retains the device, buffer, and OVERLAPPED until
            // completion, exactly as the production output-report path does.
            unsafe { WriteFile(device.handle(), Some(data), None, Some(overlapped.as_raw_mut())) }
        })
        .expect("start overlapped operation");
    assert!(buffer
        .get_result()
        .expect("query pending operation")
        .is_none());
    disconnect(&server, &buffer);

    let result = catch_unwind(AssertUnwindSafe(|| block_on(buffer.write_feature_report(&[0xA7]))));
    result
        .expect("a new feature report must return an IOCTL error, not panic")
        .expect_err("disconnected transport");
    assert!(!buffer.pending, "the next failed IOCTL must leave no pending operation");
    assert_eq!(buffer.buffer[0], 0xA7, "the new feature report was attempted");
}

#[test]
fn abandoned_successful_write_allows_next_write_without_losing_data() {
    let (mut server, device) = pipe();
    let mut buffer = IoBuffer::<Writable>::new(device, REPORT_SIZE).expect("allocate write buffer");
    let first = vec![0x31; REPORT_SIZE];
    assert!(block_on(poll_once(buffer.write(&first))).is_none(), "write must await the unread pipe");
    let reader = std::thread::spawn(move || {
        let mut received = vec![0; REPORT_SIZE * 2];
        server
            .read_exact(&mut received)
            .expect("read both output reports");
        received
    });
    let second = vec![0x32; REPORT_SIZE];
    block_on(buffer.write(&second)).expect("complete abandoned write and submit next report");
    let received = reader.join().expect("reader finished");
    assert_eq!(&received[..REPORT_SIZE], first.as_slice());
    assert_eq!(&received[REPORT_SIZE..], second.as_slice());
    assert!(!buffer.pending);
}
