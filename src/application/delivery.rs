use super::{State, ports::Notifier};
use anyhow::Result;

pub async fn deliver(state: &mut State, notifier: &impl Notifier, now: u64) -> Result<bool> {
    let Some(first) = state.notification_due(now) else {
        return Ok(false);
    };
    let id = first.id;
    let success = notifier.publish(&first.text).await.is_ok();
    state.complete_notification(id, success, now);
    Ok(true)
}
