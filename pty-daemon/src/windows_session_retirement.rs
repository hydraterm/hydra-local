//! Exact Windows map ownership across asynchronous Job retirement. A cancelled request drops
//! only its waiter; the published worker keeps the same Session mapped until final proof.

use crate::daemon::{SharedDaemon, ShutdownReport};
use crate::ids::SessionId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

type Outcome = Result<(), String>;
type Completion = watch::Receiver<Option<Outcome>>;

pub(crate) struct Retirement {
    completed: watch::Sender<Option<Outcome>>,
}

pub(crate) async fn kill(shared: &SharedDaemon, id: &SessionId, generation: &str) -> Outcome {
    match admit(
        shared,
        id,
        generation,
        false,
        #[cfg(test)]
        None,
    )
    .await?
    {
        Some(completion) => wait(completion).await,
        None => Ok(()),
    }
}

async fn wait(mut completion: Completion) -> Outcome {
    loop {
        if let Some(result) = completion.borrow().clone() {
            return result;
        }
        completion
            .changed()
            .await
            .map_err(|_| "retirement owner stopped without a result".to_owned())?;
    }
}

async fn admit(
    shared: &SharedDaemon,
    id: &SessionId,
    generation: &str,
    shutdown: bool,
    #[cfg(test)] control: Option<TestControl>,
) -> Result<Option<Completion>, String> {
    let mut daemon = shared.lock().await;
    let Some(session) = daemon.retirement_target(id, generation, shutdown)? else {
        return Ok(None);
    };
    if let Some(owner) = &session.retirement {
        return Ok(Some(owner.completed.subscribe()));
    }
    let (completed, completion) = watch::channel(None);
    let owner = Arc::new(Retirement { completed });
    let lifetime = session.native_lifetime();
    // Subscribe before checking the latch, so an exit between those operations cannot be lost.
    let mut exit = session.exit_tx.subscribe();
    let grid = session.grid_handle();
    session.retirement = Some(owner.clone());
    #[cfg(test)]
    let TestControl {
        before_signal,
        before_finish,
        fail_signal,
        panic_signal,
    } = control.unwrap_or_default();
    // No await separates installing the map owner from publishing both owned tasks. The inner
    // task owns native work; its supervisor converts panic/join failure into retained ownership.
    let worker = tokio::spawn(async move {
        #[cfg(test)]
        pause(before_signal).await;
        if grid.exit_state().is_none() {
            let signalled = tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                if panic_signal {
                    // Exercise JoinError without emitting an inherited backtrace that could fill
                    // the exact owned fixture child's captured stdout pipe before parent readback.
                    std::panic::resume_unwind(Box::new("injected native worker panic"));
                }
                #[cfg(test)]
                if fail_signal {
                    return Err(std::io::Error::other("injected native termination failure"));
                }
                lifetime.terminate()
            })
            .await
            .map_err(|error| format!("native termination worker failed: {error}"))?;
            signalled.map_err(|error| error.to_string())?;
        }
        loop {
            if grid.exit_state().is_some() {
                return Ok(());
            }
            match exit.recv().await {
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Err(
                        "terminal output owner stopped before final retirement proof".into(),
                    );
                }
            }
        }
    });
    let shared = shared.clone();
    let id = id.clone();
    let generation = generation.to_owned();
    tokio::spawn(async move {
        let result = worker
            .await
            .unwrap_or_else(|error| Err(format!("retirement observer failed: {error}")));
        #[cfg(test)]
        pause(before_finish).await;
        let result = shared
            .lock()
            .await
            .finish_retirement(&id, &generation, &owner, result);
        let result = result.map(|retired| {
            // Final Job/EOF proof permits removal; resource destruction must still run outside
            // the daemon lock and off its asynchronous worker thread.
            tokio::task::spawn_blocking(move || drop(retired));
        });
        if let Err(error) = &result {
            tracing::error!(session = %id, %error, "Windows retirement unconfirmed; retaining exact session");
        }
        // Store the result even when every request waiter disconnected. No replay is scheduled.
        owner.completed.send_replace(Some(result));
    });
    Ok(Some(completion))
}

pub(crate) async fn shutdown(shared: &SharedDaemon) -> ShutdownReport {
    shutdown_with_budget(shared, Duration::from_secs(2)).await
}

async fn shutdown_with_budget(shared: &SharedDaemon, budget: Duration) -> ShutdownReport {
    // Closing admission and capturing identities use one lock. A late Start cannot publish
    // after the captured shutdown cohort. Confirmation timeouts never erase its live mappings.
    let cohort = shared.lock().await.begin_shutdown();
    let mut report = ShutdownReport {
        total: cohort.len(),
        reaped: 0,
        unconfirmed: Vec::new(),
    };
    for (id, generation) in cohort {
        let result = match admit(
            shared,
            &id,
            &generation,
            true,
            #[cfg(test)]
            None,
        )
        .await
        {
            Ok(Some(completion)) => tokio::time::timeout(budget, wait(completion))
                .await
                .unwrap_or_else(|_| Err("shutdown retirement confirmation budget elapsed".into())),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        };
        match result {
            Ok(()) => report.reaped += 1,
            Err(error) => {
                tracing::error!(session = %id, %error, "Windows shutdown could not confirm session retirement");
                report.unconfirmed.push(id);
            }
        }
    }
    report
}

/// Hold every real retirement worker before signalling so a zero-budget shutdown assertion is
/// deterministic. The caller observes retained mapped owners, then this fixture releases and
/// confirms those same workers; production admission/finalization are never replaced by mocks.
#[cfg(test)]
pub(crate) async fn shutdown_held_for_test(
    shared: &SharedDaemon,
    verify: impl FnOnce(&mut crate::daemon::Daemon, &ShutdownReport),
) -> ShutdownReport {
    let cohort = shared.lock().await.begin_shutdown();
    let mut pending = Vec::new();
    for (id, generation) in cohort {
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, resumed) = tokio::sync::oneshot::channel();
        let completion = admit(
            shared,
            &id,
            &generation,
            true,
            Some(TestControl {
                before_signal: Some((entered, resumed)),
                ..TestControl::default()
            }),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), observed)
            .await
            .unwrap()
            .unwrap();
        pending.push((release, completion));
    }
    let report = shutdown_with_budget(shared, Duration::ZERO).await;
    verify(&mut *shared.lock().await, &report);
    for (release, completion) in pending {
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), wait(completion))
            .await
            .unwrap()
            .unwrap();
    }
    report
}

#[cfg(test)]
type Pause = Option<(
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
)>;

#[cfg(test)]
#[derive(Default)]
struct TestControl {
    before_signal: Pause,
    before_finish: Pause,
    fail_signal: bool,
    panic_signal: bool,
}

#[cfg(test)]
async fn pause(gate: Pause) {
    if let Some((entered, release)) = gate {
        let _ = entered.send(());
        let _ = release.await;
    }
}

#[cfg(test)]
#[path = "windows_retirement_tests.rs"]
mod tests;
