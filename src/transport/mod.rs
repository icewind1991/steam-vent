use bytes::BytesMut;

#[allow(dead_code)]
pub mod tcp;
pub mod websocket;

/// Assert that two BytesMut can be unsplit without allocations
#[track_caller]
fn assert_can_unsplit(head: &BytesMut, tail: &BytesMut) {
    let ptr = unsafe { head.as_ref().as_ptr().add(head.len()) };
    debug_assert_eq!(ptr, tail.as_ref().as_ptr());
}
