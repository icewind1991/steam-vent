use crate::message::ServiceMethodNotification;
use crate::net::{JobId, RawNetMessage};
use dashmap::DashMap;
use futures_util::Stream;
use std::sync::Arc;
use steam_vent_proto::enums_clientserver::EMsg;
use steam_vent_proto::MsgKind;
use tokio::spawn;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_stream::StreamExt;
use tracing::debug;

#[derive(Clone)]
pub struct MessageFilter {
    job_id_filters: Arc<DashMap<JobId, oneshot::Sender<RawNetMessage>>>,
    notification_filters: Arc<DashMap<&'static str, broadcast::Sender<ServiceMethodNotification>>>,
    kind_filters: Arc<DashMap<MsgKind, broadcast::Sender<RawNetMessage>>>,
    oneshot_kind_filters: Arc<DashMap<MsgKind, oneshot::Sender<RawNetMessage>>>,
}

impl MessageFilter {
    pub fn new<
        Input: Stream<Item = crate::connection::Result<RawNetMessage>> + Send + Unpin + 'static,
    >(
        mut source: Input,
    ) -> (
        Self,
        mpsc::Receiver<crate::connection::Result<RawNetMessage>>,
    ) {
        let (rest_tx, rx) = mpsc::channel(16);
        let filter = MessageFilter {
            job_id_filters: Default::default(),
            kind_filters: Default::default(),
            notification_filters: Default::default(),
            oneshot_kind_filters: Default::default(),
        };

        let filter_send = filter.clone();
        spawn(async move {
            while let Some(res) = source.next().await {
                if let Ok(message) = res {
                    debug!(job_id = message.header.target_job_id.0, kind = ?message.kind, "processing message");
                    if let Some((_, tx)) = filter_send
                        .job_id_filters
                        .remove(&message.header.target_job_id)
                    {
                        tx.send(message).ok();
                    } else if let Some((_, tx)) =
                        filter_send.oneshot_kind_filters.remove(&message.kind)
                    {
                        tx.send(message).ok();
                    } else if message.kind == EMsg::k_EMsgServiceMethod {
                        if let Ok(notification) =
                            message.into_message::<ServiceMethodNotification>()
                        {
                            debug!(
                                job_name = notification.job_name.as_str(),
                                "processing notification"
                            );
                            if let Some(tx) = filter_send
                                .notification_filters
                                .get(notification.job_name.as_str())
                            {
                                tx.send(notification).ok();
                            }
                        }
                    } else if let Some(tx) = filter_send.kind_filters.get(&message.kind) {
                        tx.send(message).ok();
                    } else {
                        rest_tx.send(Ok(message)).await.ok();
                    }
                } else {
                    rest_tx.send(res).await.ok();
                }
            }
        });
        (filter, rx)
    }

    pub fn on_job_id(&self, id: JobId) -> oneshot::Receiver<RawNetMessage> {
        let (tx, rx) = oneshot::channel();
        self.job_id_filters.insert(id, tx);
        rx
    }

    pub fn on_notification(
        &self,
        job_name: &'static str,
    ) -> broadcast::Receiver<ServiceMethodNotification> {
        let tx = self
            .notification_filters
            .entry(job_name)
            .or_insert_with(|| broadcast::channel(16).0);
        tx.subscribe()
    }

    pub fn on_kind<K: Into<MsgKind>>(&self, kind: K) -> broadcast::Receiver<RawNetMessage> {
        let tx = self
            .kind_filters
            .entry(kind.into())
            .or_insert_with(|| broadcast::channel(16).0);
        tx.subscribe()
    }

    pub fn one_kind<K: Into<MsgKind>>(&self, kind: K) -> oneshot::Receiver<RawNetMessage> {
        let (tx, rx) = oneshot::channel();
        self.oneshot_kind_filters.insert(kind.into(), tx);
        rx
    }
}
