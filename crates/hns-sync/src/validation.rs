use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use hns_p2p::PeerId;
use hns_primitives::{Block, Height};
use tokio::sync::{mpsc, Semaphore};

use crate::SyncError;

#[derive(Clone, Debug)]
pub struct ValidationRequest {
    pub peer: PeerId,
    pub height: Height,
    pub block: Block,
}

#[derive(Clone, Debug)]
pub struct ValidatedBlock {
    pub sequence: u64,
    pub peer: PeerId,
    pub height: Height,
    pub block: Block,
}

#[derive(Clone, Debug)]
pub struct ValidationFailure {
    pub sequence: u64,
    pub peer: PeerId,
    pub height: Height,
    pub block: Block,
    pub reason: String,
}

pub type OrderedValidationResult = Result<ValidatedBlock, ValidationFailure>;

pub trait StatelessBlockValidator: Send + Sync + 'static {
    fn validate(&self, block: &Block, height: Height) -> Result<(), String>;
}

#[derive(Clone, Debug)]
pub struct ValidationSubmitter {
    input: mpsc::Sender<(u64, ValidationRequest)>,
    next_sequence: Arc<AtomicU64>,
    queue_capacity: usize,
}

impl ValidationSubmitter {
    pub async fn submit(&self, request: ValidationRequest) -> Result<u64, SyncError> {
        let permit = self
            .input
            .reserve()
            .await
            .map_err(|_| SyncError::ValidationPipelineClosed)?;
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        permit.send((sequence, request));
        Ok(sequence)
    }

    pub fn try_submit(&self, request: ValidationRequest) -> Result<u64, SyncError> {
        let permit = self.input.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => SyncError::LimitExceeded {
                context: "validation input queue",
                limit: self.queue_capacity,
                actual: self.queue_capacity.saturating_add(1),
            },
            mpsc::error::TrySendError::Closed(_) => SyncError::ValidationPipelineClosed,
        })?;
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        permit.send((sequence, request));
        Ok(sequence)
    }
}

pub fn spawn_validation_pipeline<V>(
    validator: Arc<V>,
    workers: usize,
    queue_capacity: usize,
) -> Result<(ValidationSubmitter, mpsc::Receiver<OrderedValidationResult>), SyncError>
where
    V: StatelessBlockValidator,
{
    if workers == 0 || queue_capacity == 0 {
        return Err(SyncError::Configuration(
            "validation workers and queue capacity must be non-zero".to_owned(),
        ));
    }
    let (input_tx, mut input_rx) = mpsc::channel::<(u64, ValidationRequest)>(queue_capacity);
    let (unordered_tx, mut unordered_rx) =
        mpsc::channel::<(u64, OrderedValidationResult)>(queue_capacity);
    let (ordered_tx, ordered_rx) = mpsc::channel::<OrderedValidationResult>(queue_capacity);
    let permits = Arc::new(Semaphore::new(workers));

    tokio::spawn({
        let validator = Arc::clone(&validator);
        let permits = Arc::clone(&permits);
        async move {
            while let Some((sequence, request)) = input_rx.recv().await {
                let permit = match Arc::clone(&permits).acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                let validator = Arc::clone(&validator);
                let unordered_tx = unordered_tx.clone();
                tokio::spawn(async move {
                    let peer = request.peer;
                    let height = request.height;
                    let block = request.block;
                    let validation_block = block.clone();
                    let outcome = tokio::task::spawn_blocking(move || {
                        validator.validate(&validation_block, height)
                    })
                    .await;
                    let result = match outcome {
                        Ok(Ok(())) => Ok(ValidatedBlock {
                            sequence,
                            peer,
                            height,
                            block,
                        }),
                        Ok(Err(reason)) => Err(ValidationFailure {
                            sequence,
                            peer,
                            height,
                            block,
                            reason,
                        }),
                        Err(error) => Err(ValidationFailure {
                            sequence,
                            peer,
                            height,
                            block,
                            reason: format!("validation worker failed: {error}"),
                        }),
                    };
                    drop(permit);
                    let _ = unordered_tx.send((sequence, result)).await;
                });
            }
        }
    });

    tokio::spawn(async move {
        let mut next = 0u64;
        let mut buffered = BTreeMap::<u64, OrderedValidationResult>::new();
        while let Some((sequence, result)) = unordered_rx.recv().await {
            buffered.insert(sequence, result);
            while let Some(result) = buffered.remove(&next) {
                if ordered_tx.send(result).await.is_err() {
                    return;
                }
                next = next.saturating_add(1);
            }
        }
    });

    Ok((
        ValidationSubmitter {
            input: input_tx,
            next_sequence: Arc::new(AtomicU64::new(0)),
            queue_capacity,
        },
        ordered_rx,
    ))
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;
    use hns_primitives::Header;

    #[derive(Clone, Debug)]
    struct DelayedValidator;

    impl StatelessBlockValidator for DelayedValidator {
        fn validate(&self, block: &Block, _height: Height) -> Result<(), String> {
            let delay = 3u64.saturating_sub(u64::from(block.header.nonce));
            thread::sleep(Duration::from_millis(delay * 10));
            Ok(())
        }
    }

    #[tokio::test]
    async fn validation_results_are_emitted_in_submission_order() {
        let (submitter, mut output) =
            spawn_validation_pipeline(Arc::new(DelayedValidator), 3, 8).expect("pipeline");
        for nonce in 0..3 {
            let header = Header {
                nonce,
                ..Header::default()
            };
            submitter
                .submit(ValidationRequest {
                    peer: PeerId(1),
                    height: nonce,
                    block: Block {
                        header,
                        transactions: Vec::new(),
                    },
                })
                .await
                .expect("submit");
        }
        let mut sequences = Vec::new();
        for _ in 0..3 {
            sequences.push(
                output
                    .recv()
                    .await
                    .expect("result")
                    .expect("valid")
                    .sequence,
            );
        }
        assert_eq!(sequences, vec![0, 1, 2]);
    }
}
