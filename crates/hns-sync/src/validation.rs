use std::{
    any::Any,
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use hns_p2p::PeerId;
use hns_primitives::{Block, Height};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};

use crate::SyncError;

/// One successfully completed item from a bounded ordered work pipeline.
///
/// The original input is retained behind an [`Arc`] so callers can bind a
/// prepared result to the exact request which produced it without cloning a
/// potentially large request into the blocking worker.
#[derive(Debug)]
pub struct OrderedWorkSuccess<I, O> {
    pub sequence: u64,
    pub input: Arc<I>,
    pub output: O,
}

/// The reason one ordered work item did not produce an output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrderedWorkError<E> {
    Work(E),
    Panicked(String),
    Cancelled,
}

/// One failed item from a bounded ordered work pipeline.
///
/// Worker panics and executor cancellation retain both the admission sequence
/// and original input identity, just like ordinary work errors.
#[derive(Debug)]
pub struct OrderedWorkFailure<I, E> {
    pub sequence: u64,
    pub input: Arc<I>,
    pub error: OrderedWorkError<E>,
}

pub type OrderedWorkResult<I, O, E> = Result<OrderedWorkSuccess<I, O>, OrderedWorkFailure<I, E>>;
pub type OrderedWorkPipeline<I, O, E> = (
    OrderedWorkSubmitter<I>,
    mpsc::Receiver<OrderedWorkResult<I, O, E>>,
);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OrderedWorkPipelineError {
    #[error(
        "ordered work workers and queue capacity must be non-zero (workers={workers}, queue_capacity={queue_capacity})"
    )]
    InvalidConfiguration {
        workers: usize,
        queue_capacity: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OrderedWorkSubmitError {
    #[error("ordered work input queue is full at capacity {capacity}")]
    Full { capacity: usize },
    #[error("ordered work input channel is closed")]
    Closed,
    #[error("ordered work pipeline was cancelled")]
    Cancelled,
    #[error("ordered work admission sequence is exhausted")]
    SequenceExhausted,
}

#[derive(Clone, Debug)]
struct OrderedWorkCancellation {
    signal: watch::Sender<bool>,
}

impl OrderedWorkCancellation {
    fn new() -> Self {
        let (signal, _receiver) = watch::channel(false);
        Self { signal }
    }

    fn cancel(&self) {
        self.signal.send_replace(true);
    }

    fn is_cancelled(&self) -> bool {
        *self.signal.borrow()
    }

    async fn cancelled(&self) {
        let mut signal = self.signal.subscribe();
        if *signal.borrow() {
            return;
        }
        while signal.changed().await.is_ok() {
            if *signal.borrow() {
                return;
            }
        }
    }
}

/// Cloneable admission handle for a bounded ordered work pipeline.
///
/// The input channel admits at most `queue_capacity` items while a semaphore
/// independently limits running or reorder-buffered items to the configured
/// worker count. A sequence is allocated only after channel admission succeeds,
/// so rejected submissions cannot leave a gap which would stall ordered output.
#[derive(Debug)]
pub struct OrderedWorkSubmitter<I> {
    input: mpsc::Sender<(u64, Arc<I>)>,
    next_sequence: Arc<AtomicU64>,
    queue_capacity: usize,
    cancellation: OrderedWorkCancellation,
}

impl<I> Clone for OrderedWorkSubmitter<I> {
    fn clone(&self) -> Self {
        Self {
            input: self.input.clone(),
            next_sequence: Arc::clone(&self.next_sequence),
            queue_capacity: self.queue_capacity,
            cancellation: self.cancellation.clone(),
        }
    }
}

impl<I> OrderedWorkSubmitter<I> {
    pub async fn submit(&self, input: I) -> Result<u64, OrderedWorkSubmitError> {
        if self.cancellation.is_cancelled() {
            return Err(OrderedWorkSubmitError::Cancelled);
        }
        let permit = tokio::select! {
            _ = self.cancellation.cancelled() => {
                return Err(OrderedWorkSubmitError::Cancelled);
            }
            permit = self.input.reserve() => {
                permit.map_err(|_| self.closed_submit_error())?
            }
        };
        if self.cancellation.is_cancelled() {
            drop(permit);
            return Err(OrderedWorkSubmitError::Cancelled);
        }
        let sequence = self.allocate_sequence()?;
        permit.send((sequence, Arc::new(input)));
        Ok(sequence)
    }

    pub fn try_submit(&self, input: I) -> Result<u64, OrderedWorkSubmitError> {
        if self.cancellation.is_cancelled() {
            return Err(OrderedWorkSubmitError::Cancelled);
        }
        let permit = self.input.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => OrderedWorkSubmitError::Full {
                capacity: self.queue_capacity,
            },
            mpsc::error::TrySendError::Closed(_) => self.closed_submit_error(),
        })?;
        if self.cancellation.is_cancelled() {
            drop(permit);
            return Err(OrderedWorkSubmitError::Cancelled);
        }
        let sequence = self.allocate_sequence()?;
        permit.send((sequence, Arc::new(input)));
        Ok(sequence)
    }

    /// Stop accepting work and discard queued or subsequently completed items.
    /// Already-running blocking functions cannot be preempted, but their output
    /// is dropped and every pipeline task terminates once those functions return.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn allocate_sequence(&self) -> Result<u64, OrderedWorkSubmitError> {
        self.next_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| {
                self.cancellation.cancel();
                OrderedWorkSubmitError::SequenceExhausted
            })
    }

    fn closed_submit_error(&self) -> OrderedWorkSubmitError {
        if self.cancellation.is_cancelled() {
            OrderedWorkSubmitError::Cancelled
        } else {
            OrderedWorkSubmitError::Closed
        }
    }
}

struct CompletedOrderedWork<I, O, E> {
    sequence: u64,
    result: OrderedWorkResult<I, O, E>,
    // Retaining the permit through the reorder buffer prevents one slow early
    // item from allowing an unbounded number of later completions to accumulate.
    _permit: OwnedSemaphorePermit,
}

/// Spawn bounded blocking work whose results are emitted in admission order.
///
/// `work` may execute concurrently on at most `workers` blocking threads. Both
/// successes and failures are reordered by their gap-free admission sequence,
/// allowing a consumer to select the deterministic earliest failure regardless
/// of completion order.
///
/// Submission and result consumption must make progress concurrently whenever a
/// producer may submit more than the bounded input/output capacities. A caller
/// which first awaits an arbitrarily long submission loop and only then drains
/// output can correctly backpressure itself. Run that producer in a separate
/// task, or interleave `submit` and `recv`, as the one-worker equivalence test
/// demonstrates.
pub fn spawn_ordered_work_pipeline<I, O, E, F>(
    work: Arc<F>,
    workers: usize,
    queue_capacity: usize,
) -> Result<OrderedWorkPipeline<I, O, E>, OrderedWorkPipelineError>
where
    I: Send + Sync + 'static,
    O: Send + 'static,
    E: Send + 'static,
    F: Fn(&I) -> Result<O, E> + Send + Sync + 'static + ?Sized,
{
    if workers == 0 || queue_capacity == 0 {
        return Err(OrderedWorkPipelineError::InvalidConfiguration {
            workers,
            queue_capacity,
        });
    }

    let (input_tx, mut input_rx) = mpsc::channel::<(u64, Arc<I>)>(queue_capacity);
    let (unordered_tx, mut unordered_rx) = mpsc::channel::<CompletedOrderedWork<I, O, E>>(workers);
    let (ordered_tx, ordered_rx) = mpsc::channel::<OrderedWorkResult<I, O, E>>(queue_capacity);
    let permits = Arc::new(Semaphore::new(workers));
    let cancellation = OrderedWorkCancellation::new();

    tokio::spawn({
        let cancellation = cancellation.clone();
        let permits = Arc::clone(&permits);
        let output_observer = ordered_tx.clone();
        async move {
            loop {
                // Acquire capacity before removing an admitted item. This leaves
                // no hidden dispatcher slot beyond the declared input bound.
                let permit = tokio::select! {
                    _ = cancellation.cancelled() => {
                        input_rx.close();
                        break;
                    }
                    _ = output_observer.closed() => {
                        cancellation.cancel();
                        input_rx.close();
                        break;
                    }
                    permit = Arc::clone(&permits).acquire_owned() => {
                        match permit {
                            Ok(permit) => permit,
                            Err(_) => break,
                        }
                    }
                };

                let admitted = tokio::select! {
                    _ = cancellation.cancelled() => {
                        input_rx.close();
                        drop(permit);
                        break;
                    }
                    _ = output_observer.closed() => {
                        cancellation.cancel();
                        input_rx.close();
                        drop(permit);
                        break;
                    }
                    admitted = input_rx.recv() => admitted,
                };
                let Some((sequence, input)) = admitted else {
                    drop(permit);
                    break;
                };

                let work = Arc::clone(&work);
                let unordered_tx = unordered_tx.clone();
                let cancellation = cancellation.clone();
                tokio::spawn(async move {
                    let worker_input = Arc::clone(&input);
                    let outcome = tokio::task::spawn_blocking(move || work(&worker_input)).await;
                    let result = match outcome {
                        Ok(Ok(output)) => Ok(OrderedWorkSuccess {
                            sequence,
                            input,
                            output,
                        }),
                        Ok(Err(error)) => Err(OrderedWorkFailure {
                            sequence,
                            input,
                            error: OrderedWorkError::Work(error),
                        }),
                        Err(error) if error.is_panic() => Err(OrderedWorkFailure {
                            sequence,
                            input,
                            error: OrderedWorkError::Panicked(panic_message(error.into_panic())),
                        }),
                        Err(_) => Err(OrderedWorkFailure {
                            sequence,
                            input,
                            error: OrderedWorkError::Cancelled,
                        }),
                    };
                    if cancellation.is_cancelled() {
                        return;
                    }
                    let _ = unordered_tx
                        .send(CompletedOrderedWork {
                            sequence,
                            result,
                            _permit: permit,
                        })
                        .await;
                });
            }
        }
    });

    tokio::spawn({
        let cancellation = cancellation.clone();
        async move {
            let mut next = 0u64;
            let mut buffered = BTreeMap::<u64, CompletedOrderedWork<I, O, E>>::new();
            loop {
                let completed = tokio::select! {
                    _ = cancellation.cancelled() => return,
                    completed = unordered_rx.recv() => completed,
                };
                let Some(completed) = completed else {
                    return;
                };
                let sequence = completed.sequence;
                if buffered.insert(sequence, completed).is_some() {
                    cancellation.cancel();
                    return;
                }
                while let Some(completed) = buffered.remove(&next) {
                    let send = tokio::select! {
                        _ = cancellation.cancelled() => return,
                        send = ordered_tx.send(completed.result) => send,
                    };
                    if send.is_err() {
                        cancellation.cancel();
                        return;
                    }
                    let Some(following) = next.checked_add(1) else {
                        cancellation.cancel();
                        return;
                    };
                    next = following;
                }
            }
        }
    });

    Ok((
        OrderedWorkSubmitter {
            input: input_tx,
            next_sequence: Arc::new(AtomicU64::new(0)),
            queue_capacity,
            cancellation,
        },
        ordered_rx,
    ))
}

fn panic_message(payload: Box<dyn Any + Send + 'static>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_owned(),
            Err(_) => "non-string worker panic".to_owned(),
        },
    }
}

#[derive(Clone, Debug)]
pub struct ValidationRequest {
    pub peer: PeerId,
    pub height: Height,
    pub attempt: u8,
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
    pub attempt: u8,
    pub block: Block,
    pub kind: ValidationFailureKind,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationFailureKind {
    InvalidBlock,
    InvalidResponse,
    WorkerFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationRejection {
    pub kind: ValidationFailureKind,
    pub reason: String,
}

impl ValidationRejection {
    pub fn invalid_block(reason: impl Into<String>) -> Self {
        Self {
            kind: ValidationFailureKind::InvalidBlock,
            reason: reason.into(),
        }
    }

    pub fn invalid_response(reason: impl Into<String>) -> Self {
        Self {
            kind: ValidationFailureKind::InvalidResponse,
            reason: reason.into(),
        }
    }
}

pub type OrderedValidationResult = Result<ValidatedBlock, ValidationFailure>;

pub trait StatelessBlockValidator: Send + Sync + 'static {
    fn validate(&self, block: &Block, height: Height) -> Result<(), ValidationRejection>;
}

#[derive(Clone, Debug)]
pub struct ValidationSubmitter {
    inner: OrderedWorkSubmitter<ValidationRequest>,
    queue_capacity: usize,
}

impl ValidationSubmitter {
    pub async fn submit(&self, request: ValidationRequest) -> Result<u64, SyncError> {
        self.inner
            .submit(request)
            .await
            .map_err(|error| map_validation_submit_error(error, self.queue_capacity))
    }

    pub fn try_submit(&self, request: ValidationRequest) -> Result<u64, SyncError> {
        self.inner
            .try_submit(request)
            .map_err(|error| map_validation_submit_error(error, self.queue_capacity))
    }
}

fn map_validation_submit_error(error: OrderedWorkSubmitError, queue_capacity: usize) -> SyncError {
    match error {
        OrderedWorkSubmitError::Full { .. } => SyncError::LimitExceeded {
            context: "validation input queue",
            limit: queue_capacity,
            actual: queue_capacity.saturating_add(1),
        },
        OrderedWorkSubmitError::Closed
        | OrderedWorkSubmitError::Cancelled
        | OrderedWorkSubmitError::SequenceExhausted => SyncError::ValidationPipelineClosed,
    }
}

pub fn spawn_validation_pipeline<V>(
    validator: Arc<V>,
    workers: usize,
    queue_capacity: usize,
) -> Result<(ValidationSubmitter, mpsc::Receiver<OrderedValidationResult>), SyncError>
where
    V: StatelessBlockValidator + ?Sized,
{
    if workers == 0 || queue_capacity == 0 {
        return Err(SyncError::Configuration(
            "validation workers and queue capacity must be non-zero".to_owned(),
        ));
    }
    let work = Arc::new(move |request: &ValidationRequest| {
        validator.validate(&request.block, request.height)
    });
    let (inner, mut work_output) = spawn_ordered_work_pipeline(work, workers, queue_capacity)
        .map_err(|_| {
            SyncError::Configuration(
                "validation workers and queue capacity must be non-zero".to_owned(),
            )
        })?;
    let cancellation = inner.cancellation.clone();
    let (validation_tx, validation_rx) = mpsc::channel::<OrderedValidationResult>(queue_capacity);

    tokio::spawn(async move {
        loop {
            let result = tokio::select! {
                _ = validation_tx.closed() => {
                    cancellation.cancel();
                    return;
                }
                result = work_output.recv() => result,
            };
            let Some(result) = result else {
                return;
            };
            let result = match result {
                Ok(OrderedWorkSuccess {
                    sequence, input, ..
                }) => {
                    let request = take_validation_request(input);
                    Ok(ValidatedBlock {
                        sequence,
                        peer: request.peer,
                        height: request.height,
                        block: request.block,
                    })
                }
                Err(OrderedWorkFailure {
                    sequence,
                    input,
                    error,
                }) => {
                    let request = take_validation_request(input);
                    let (kind, reason) = match error {
                        OrderedWorkError::Work(rejection) => (rejection.kind, rejection.reason),
                        OrderedWorkError::Panicked(reason) => (
                            ValidationFailureKind::WorkerFailure,
                            format!("validation worker failed: {reason}"),
                        ),
                        OrderedWorkError::Cancelled => (
                            ValidationFailureKind::WorkerFailure,
                            "validation worker failed: blocking task was cancelled".to_owned(),
                        ),
                    };
                    Err(ValidationFailure {
                        sequence,
                        peer: request.peer,
                        height: request.height,
                        attempt: request.attempt,
                        block: request.block,
                        kind,
                        reason,
                    })
                }
            };
            if validation_tx.send(result).await.is_err() {
                cancellation.cancel();
                return;
            }
        }
    });

    Ok((
        ValidationSubmitter {
            inner,
            queue_capacity,
        },
        validation_rx,
    ))
}

fn take_validation_request(input: Arc<ValidationRequest>) -> ValidationRequest {
    Arc::try_unwrap(input).unwrap_or_else(|input| (*input).clone())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            Condvar, Mutex as StdMutex,
        },
        thread,
        time::Duration,
    };

    use super::*;
    use hns_primitives::Header;

    #[derive(Clone, Debug)]
    struct DelayedValidator;

    impl StatelessBlockValidator for DelayedValidator {
        fn validate(&self, block: &Block, _height: Height) -> Result<(), ValidationRejection> {
            let delay = 3u64.saturating_sub(u64::from(block.header.nonce));
            thread::sleep(Duration::from_millis(delay * 10));
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct RejectingValidator;

    impl StatelessBlockValidator for RejectingValidator {
        fn validate(&self, _block: &Block, _height: Height) -> Result<(), ValidationRejection> {
            Err(ValidationRejection::invalid_block(
                "deterministic rejection",
            ))
        }
    }

    #[derive(Clone, Debug)]
    struct PanickingValidator;

    impl StatelessBlockValidator for PanickingValidator {
        fn validate(&self, _block: &Block, _height: Height) -> Result<(), ValidationRejection> {
            panic!("validator panic")
        }
    }

    #[derive(Clone, Debug)]
    struct ResponseRejectingValidator;

    impl StatelessBlockValidator for ResponseRejectingValidator {
        fn validate(&self, _block: &Block, _height: Height) -> Result<(), ValidationRejection> {
            Err(ValidationRejection::invalid_response(
                "body/header mismatch",
            ))
        }
    }

    async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while counter.load(AtomicOrdering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker count reached before timeout");
    }

    fn release_workers(gate: &Arc<(StdMutex<bool>, Condvar)>) {
        let (released, wake) = &**gate;
        *released.lock().expect("release gate lock") = true;
        wake.notify_all();
    }

    #[tokio::test]
    async fn ordered_work_enforces_worker_bound_with_real_overlap() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum_active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let work = Arc::new({
            let active = Arc::clone(&active);
            let maximum_active = Arc::clone(&maximum_active);
            let started = Arc::clone(&started);
            let gate = Arc::clone(&gate);
            move |input: &usize| -> Result<usize, ()> {
                let now = active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                maximum_active.fetch_max(now, AtomicOrdering::SeqCst);
                started.fetch_add(1, AtomicOrdering::SeqCst);
                let (released, wake) = &*gate;
                let mut released = released.lock().expect("worker gate lock");
                while !*released {
                    released = wake.wait(released).expect("worker gate wait");
                }
                active.fetch_sub(1, AtomicOrdering::SeqCst);
                Ok(*input * 2)
            }
        });
        let (submitter, mut output) =
            spawn_ordered_work_pipeline(work, 3, 8).expect("ordered pipeline");
        for input in 0..6 {
            submitter.submit(input).await.expect("admit input");
        }

        wait_for_count(&started, 3).await;
        assert_eq!(started.load(AtomicOrdering::SeqCst), 3);
        assert_eq!(maximum_active.load(AtomicOrdering::SeqCst), 3);
        release_workers(&gate);

        for expected in 0..6 {
            let completed = output
                .recv()
                .await
                .expect("ordered result")
                .expect("successful work");
            assert_eq!(completed.sequence, expected as u64);
            assert_eq!(*completed.input, expected);
            assert_eq!(completed.output, expected * 2);
        }
        assert!(maximum_active.load(AtomicOrdering::SeqCst) <= 3);
    }

    #[tokio::test]
    async fn ordered_work_admission_queue_is_exactly_bounded() {
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let work = Arc::new({
            let started = Arc::clone(&started);
            let gate = Arc::clone(&gate);
            move |input: &usize| -> Result<usize, ()> {
                started.fetch_add(1, AtomicOrdering::SeqCst);
                let (released, wake) = &*gate;
                let mut released = released.lock().expect("worker gate lock");
                while !*released {
                    released = wake.wait(released).expect("worker gate wait");
                }
                Ok(*input)
            }
        });
        let (submitter, mut output) =
            spawn_ordered_work_pipeline(work, 1, 2).expect("ordered pipeline");
        submitter.submit(0).await.expect("running item");
        wait_for_count(&started, 1).await;

        assert_eq!(submitter.try_submit(1), Ok(1));
        assert_eq!(submitter.try_submit(2), Ok(2));
        assert_eq!(
            submitter.try_submit(3),
            Err(OrderedWorkSubmitError::Full { capacity: 2 })
        );
        assert_eq!(started.load(AtomicOrdering::SeqCst), 1);

        release_workers(&gate);
        for expected in 0..3 {
            let completed = output
                .recv()
                .await
                .expect("ordered result")
                .expect("successful work");
            assert_eq!(*completed.input, expected);
        }
    }

    #[tokio::test]
    async fn ordered_work_emits_successes_and_errors_in_input_order() {
        let work = Arc::new(|input: &u64| -> Result<u64, &'static str> {
            thread::sleep(Duration::from_millis((4 - *input) * 10));
            match input {
                1 => Err("earliest failure"),
                2 => Err("later failure"),
                _ => Ok(*input * 10),
            }
        });
        let (submitter, mut output) =
            spawn_ordered_work_pipeline(work, 4, 4).expect("ordered pipeline");
        for input in 0..4 {
            submitter.submit(input).await.expect("admit input");
        }

        let mut sequences = Vec::new();
        let mut failures = Vec::new();
        for _ in 0..4 {
            match output.recv().await.expect("ordered result") {
                Ok(completed) => sequences.push(completed.sequence),
                Err(failure) => {
                    sequences.push(failure.sequence);
                    failures.push((failure.sequence, failure.error));
                }
            }
        }
        assert_eq!(sequences, vec![0, 1, 2, 3]);
        assert_eq!(
            failures,
            vec![
                (1, OrderedWorkError::Work("earliest failure")),
                (2, OrderedWorkError::Work("later failure")),
            ]
        );
    }

    #[tokio::test]
    async fn ordered_work_panic_retains_sequence_and_input_identity() {
        let work = Arc::new(|input: &u64| -> Result<(), ()> {
            assert_ne!(*input, 42, "identified worker panic");
            Ok(())
        });
        let (submitter, mut output) =
            spawn_ordered_work_pipeline(work, 1, 1).expect("ordered pipeline");
        submitter.submit(42).await.expect("admit panic input");

        let failure = output
            .recv()
            .await
            .expect("ordered result")
            .expect_err("worker panic");
        assert_eq!(failure.sequence, 0);
        assert_eq!(*failure.input, 42);
        let OrderedWorkError::Panicked(message) = failure.error else {
            panic!("panic must retain its typed classification");
        };
        assert!(message.contains("identified worker panic"));
    }

    #[tokio::test]
    async fn ordered_work_one_worker_matches_serial_execution_exactly() {
        fn calculate(input: &u32) -> Result<u32, &'static str> {
            if input.is_multiple_of(3) {
                Err("multiple of three")
            } else {
                Ok(input * input)
            }
        }

        let inputs = (0..12).collect::<Vec<_>>();
        let serial = inputs.iter().map(calculate).collect::<Vec<_>>();
        let (submitter, mut output) =
            spawn_ordered_work_pipeline(Arc::new(calculate), 1, 3).expect("ordered pipeline");
        let producer = tokio::spawn(async move {
            for input in inputs {
                submitter.submit(input).await.expect("admit input");
            }
        });

        let mut parallel = Vec::new();
        while let Some(result) = output.recv().await {
            parallel.push(match result {
                Ok(completed) => Ok(completed.output),
                Err(failure) => match failure.error {
                    OrderedWorkError::Work(error) => Err(error),
                    other => panic!("unexpected worker failure: {other:?}"),
                },
            });
        }
        producer.await.expect("producer task");
        assert_eq!(parallel, serial);
    }

    #[tokio::test]
    async fn ordered_work_cancellation_and_channel_closure_do_not_hang() {
        let (submitter, output) = spawn_ordered_work_pipeline(
            Arc::new(|input: &u64| -> Result<u64, ()> { Ok(*input) }),
            2,
            2,
        )
        .expect("ordered pipeline");
        drop(output);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match submitter.try_submit(1) {
                    Err(OrderedWorkSubmitError::Cancelled | OrderedWorkSubmitError::Closed) => {
                        break;
                    }
                    Ok(_) | Err(OrderedWorkSubmitError::Full { .. }) => {
                        tokio::task::yield_now().await;
                    }
                    Err(OrderedWorkSubmitError::SequenceExhausted) => {
                        panic!("test cannot exhaust the admission sequence");
                    }
                }
            }
        })
        .await
        .expect("output closure propagated");

        let (submitter, mut output) = spawn_ordered_work_pipeline(
            Arc::new(|input: &u64| -> Result<u64, ()> { Ok(*input) }),
            1,
            1,
        )
        .expect("ordered pipeline");
        submitter.submit(7).await.expect("admit before cancel");
        submitter.cancel();
        assert_eq!(
            submitter.submit(8).await,
            Err(OrderedWorkSubmitError::Cancelled)
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while output.recv().await.is_some() {}
        })
        .await
        .expect("cancelled output closed");
    }

    #[tokio::test]
    async fn ordered_work_cancellation_wakes_a_blocked_producer() {
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((StdMutex::new(false), Condvar::new()));
        let work = Arc::new({
            let started = Arc::clone(&started);
            let gate = Arc::clone(&gate);
            move |input: &u64| -> Result<u64, ()> {
                started.fetch_add(1, AtomicOrdering::SeqCst);
                let (released, wake) = &*gate;
                let mut released = released.lock().expect("worker gate lock");
                while !*released {
                    released = wake.wait(released).expect("worker gate wait");
                }
                Ok(*input)
            }
        });
        let (submitter, mut output) =
            spawn_ordered_work_pipeline(work, 1, 1).expect("ordered pipeline");
        submitter.submit(0).await.expect("running input");
        wait_for_count(&started, 1).await;
        submitter.submit(1).await.expect("queued input");

        let blocked_submitter = submitter.clone();
        let producer = tokio::spawn(async move { blocked_submitter.submit(2).await });
        tokio::task::yield_now().await;
        assert!(!producer.is_finished());
        submitter.cancel();
        let producer_result = tokio::time::timeout(Duration::from_secs(2), producer).await;
        release_workers(&gate);
        assert_eq!(
            producer_result
                .expect("blocked producer woke")
                .expect("producer task"),
            Err(OrderedWorkSubmitError::Cancelled)
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while output.recv().await.is_some() {}
        })
        .await
        .expect("cancelled pipeline closed");
    }

    #[tokio::test]
    async fn ordered_work_sequence_exhaustion_fails_closed_without_a_gap() {
        let (submitter, mut output) = spawn_ordered_work_pipeline(
            Arc::new(|input: &u64| -> Result<u64, ()> { Ok(*input) }),
            1,
            1,
        )
        .expect("ordered pipeline");
        submitter
            .next_sequence
            .store(u64::MAX, AtomicOrdering::Relaxed);
        assert_eq!(
            submitter.try_submit(1),
            Err(OrderedWorkSubmitError::SequenceExhausted)
        );
        assert!(submitter.is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            while output.recv().await.is_some() {}
        })
        .await
        .expect("exhausted pipeline closed");
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
                    attempt: 1,
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

    #[tokio::test]
    async fn validation_distinguishes_consensus_rejection_from_worker_failure() {
        for (validator, expected) in [
            (
                Arc::new(RejectingValidator) as Arc<dyn StatelessBlockValidator>,
                ValidationFailureKind::InvalidBlock,
            ),
            (
                Arc::new(PanickingValidator) as Arc<dyn StatelessBlockValidator>,
                ValidationFailureKind::WorkerFailure,
            ),
            (
                Arc::new(ResponseRejectingValidator) as Arc<dyn StatelessBlockValidator>,
                ValidationFailureKind::InvalidResponse,
            ),
        ] {
            let (submitter, mut output) =
                spawn_validation_pipeline(validator, 1, 1).expect("validation pipeline");
            submitter
                .submit(ValidationRequest {
                    peer: PeerId(7),
                    height: 9,
                    attempt: 3,
                    block: Block {
                        header: Header::default(),
                        transactions: Vec::new(),
                    },
                })
                .await
                .expect("submit");
            let failure = output.recv().await.expect("result").expect_err("failure");
            assert_eq!(failure.kind, expected);
            assert_eq!(failure.attempt, 3);
        }
    }
}
