mod generated;

pub use generated::*;

impl steam_vent_proto_common::JobMultiple
    for steammessages_clientserver_appinfo::CMsgClientPICSProductInfoResponse
{
    fn completed(&self) -> bool {
        !self.response_pending.unwrap_or(false)
    }
}
