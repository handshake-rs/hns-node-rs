//! Node-owned handle and typed name-market adapter for the bounded Denuo relay.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use hns_denuo_market_relay::{
    Announcement, AnnouncementAdmission, ObjectAdmission, ObjectHash, PeerIdentity, RelayError,
    RelayKind, RelayLimits, RelayObject, RelayRoles, RelayStatus, RelayStore, SignerIdentity,
    SignerPolicy,
};
use hns_marketplace_protocol::{
    sign_denuo_publication_acceptance, DenuoPublicationAcceptanceExpectation,
    DenuoPublicationAcceptancePolicy, DenuoPublicationMessageKind, DenuoRegistryVersion,
    NameMarketHello, NameMarketMessage, MAX_DENUO_MARKET_PAYLOAD, MAX_NAME_OFFERS_PER_MESSAGE,
};
use hns_p2p::PeerId;
use hns_primitives::blake2b_256;
use hns_swap::{FixedPriceListing, ListingCancellation};
use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum live seller/name rows in the process-local typed adapter.
pub const MAX_DENUO_NAME_MARKET_RECORDS: usize = 4_096;
/// Maximum durable-consumer events retained by the process-local adapter.
pub const MAX_DENUO_NAME_MARKET_EVENTS: usize = 8_192;
/// Maximum events exposed by one authenticated local wallet RPC call.
pub const MAX_DENUO_NAME_MARKET_EVENT_PAGE: usize = 256;
/// Maximum latest-state records exposed by one authenticated snapshot page.
pub const MAX_DENUO_NAME_MARKET_SNAPSHOT_PAGE: usize = 256;
/// Maximum correlated peer requests retained at once.
const MAX_DENUO_NAME_MARKET_PENDING_REQUESTS: usize = 1_024;
const DENUO_NAME_MARKET_REQUEST_LIFETIME_SECONDS: u64 = 15;
const LOCAL_WALLET_RELAY_PEER: [u8; 32] = [0x57; 32];
const NAME_MARKET_IDENTITY_DOMAIN: &[u8] = b"hns-node/denuo-name-market-identity/v1";
const DENUO_OUTBOX_ENVELOPE_ID_DOMAIN: &[u8] = b"hns-wallet-denuo-outbox-envelope-v1\0";

/// Endpoint signing authority for exact local wallet handoff receipts.
///
/// The private key is zeroized, omitted from `Debug`, and never exposed by an
/// accessor. Equality exists only so complete node configurations retain their
/// established deterministic comparison semantics.
#[derive(Clone)]
pub struct DenuoRelayAcceptanceSigner {
    policy: DenuoPublicationAcceptancePolicy,
    endpoint_private_key: Arc<Zeroizing<[u8; 32]>>,
}

impl DenuoRelayAcceptanceSigner {
    pub fn new(
        policy: DenuoPublicationAcceptancePolicy,
        endpoint_private_key: [u8; 32],
    ) -> Result<Self, DenuoRelayAcceptanceSignerError> {
        let endpoint_private_key = Zeroizing::new(endpoint_private_key);
        let signing_key = SigningKey::from_bytes((&*endpoint_private_key).into())
            .map_err(|_| DenuoRelayAcceptanceSignerError::InvalidPrivateKey)?;
        if signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            != policy.hnsa().endpoint_public_key
        {
            return Err(DenuoRelayAcceptanceSignerError::KeyMismatch);
        }
        Ok(Self {
            policy,
            endpoint_private_key: Arc::new(endpoint_private_key),
        })
    }

    pub const fn policy(&self) -> &DenuoPublicationAcceptancePolicy {
        &self.policy
    }

    fn sign(
        &self,
        expectation: DenuoPublicationAcceptanceExpectation,
        accepted_at_unix: u64,
    ) -> Result<Vec<u8>, DenuoRelayHandleError> {
        let maximum_expiry = accepted_at_unix
            .checked_add(u64::from(self.policy.maximum_receipt_lifetime_seconds()))
            .ok_or(DenuoRelayHandleError::NameMarket(
                "Denuo acceptance receipt time overflowed",
            ))?;
        let expires_at_unix = maximum_expiry.min(self.policy.hnsa().effective_expires_at_unix);
        if expires_at_unix <= accepted_at_unix {
            return Err(DenuoRelayHandleError::NameMarket(
                "Denuo acceptance endpoint is outside its effective window",
            ));
        }
        sign_denuo_publication_acceptance(
            &self.policy,
            expectation,
            accepted_at_unix,
            expires_at_unix,
            &self.endpoint_private_key,
        )
        .map_err(|_| DenuoRelayHandleError::NameMarket("failed to sign Denuo acceptance receipt"))
    }
}

impl std::fmt::Debug for DenuoRelayAcceptanceSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DenuoRelayAcceptanceSigner")
            .field("policy", &self.policy)
            .field("endpoint_private_key", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for DenuoRelayAcceptanceSigner {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy
            && self.endpoint_private_key.as_ref().as_ref()
                == other.endpoint_private_key.as_ref().as_ref()
    }
}

impl Eq for DenuoRelayAcceptanceSigner {}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DenuoRelayAcceptanceSignerError {
    #[error("Denuo relay acceptance private key is invalid")]
    InvalidPrivateKey,
    #[error("Denuo relay acceptance private key does not match the HNSA endpoint")]
    KeyMismatch,
}

/// Public event kind projected to the authenticated local wallet transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoNameMarketEventKind {
    Offer,
    Cancellation,
}

impl DenuoNameMarketEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Cancellation => "cancellation",
        }
    }
}

/// One exact canonical singular envelope admitted by the typed adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoNameMarketEvent {
    pub revision: u64,
    pub received_at_unix: u64,
    pub kind: DenuoNameMarketEventKind,
    pub content_hash: [u8; 32],
    pub envelope_bytes: Vec<u8>,
}

/// One bounded local event page. A consumer behind `oldest_revision` must
/// rebuild from a fresh active inventory rather than silently skipping rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoNameMarketEventPage {
    pub instance_nonce: [u8; 32],
    pub cursor_reset: bool,
    pub oldest_revision: u64,
    pub head_revision: u64,
    pub events: Vec<DenuoNameMarketEvent>,
}

/// One latest seller/name state in a coherent process-local snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoNameMarketSnapshotRecord {
    pub kind: DenuoNameMarketEventKind,
    pub content_hash: [u8; 32],
    pub envelope_bytes: Vec<u8>,
}

/// A coherent bounded page over the adapter's latest seller/name states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoNameMarketSnapshotPage {
    pub instance_nonce: [u8; 32],
    pub snapshot_revision: u64,
    pub next_offset: Option<usize>,
    pub records: Vec<DenuoNameMarketSnapshotRecord>,
}

/// Result of one local or peer publication admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoNameMarketAdmission {
    pub revision: u64,
    pub kind: DenuoNameMarketEventKind,
    pub content_hash: [u8; 32],
    pub inserted: bool,
    pub(crate) rebroadcast: Option<NameMarketMessage>,
}

/// One exact response/request that the native peer event loop must send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoNameMarketSend {
    pub peer: PeerId,
    pub request_id: u64,
    pub message: NameMarketMessage,
}

/// Complete bounded result of consuming one typed peer message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DenuoNameMarketDispatch {
    pub sends: Vec<DenuoNameMarketSend>,
    pub admissions: Vec<DenuoNameMarketAdmission>,
}

#[derive(Clone, Debug)]
enum NameMarketRecordState {
    Active { listing: FixedPriceListing },
    Cancelled { cancellation: ListingCancellation },
}

#[derive(Clone, Debug)]
struct NameMarketRecord {
    listing_hash: [u8; 32],
    sequence: u64,
    state: NameMarketRecordState,
    envelope_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct PendingNameMarketRequest {
    hashes: Vec<[u8; 32]>,
    expires_at_unix: u64,
}

#[derive(Debug)]
struct DenuoNameMarketState {
    network_magic: u32,
    network_genesis: [u8; 32],
    records: BTreeMap<[u8; 32], NameMarketRecord>,
    listing_index: BTreeMap<[u8; 32], [u8; 32]>,
    events: VecDeque<DenuoNameMarketEvent>,
    revision: u64,
    next_request_id: u64,
    pending: HashMap<(PeerId, u64), PendingNameMarketRequest>,
    hello_peers: BTreeSet<PeerId>,
}

impl DenuoNameMarketState {
    fn new(network_magic: u32, network_genesis: [u8; 32]) -> Self {
        Self {
            network_magic,
            network_genesis,
            records: BTreeMap::new(),
            listing_index: BTreeMap::new(),
            events: VecDeque::new(),
            revision: 0,
            next_request_id: 1,
            pending: HashMap::new(),
            hello_peers: BTreeSet::new(),
        }
    }

    fn next_request_id(&mut self) -> u64 {
        let request_id = self.next_request_id.max(1);
        self.next_request_id = request_id.checked_add(1).unwrap_or(1);
        request_id
    }

    fn expire_pending(&mut self, now: u64) {
        self.pending
            .retain(|_, request| request.expires_at_unix > now);
    }
}

#[derive(Debug)]
struct DenuoRelayService {
    relay: RelayStore,
    name_market: DenuoNameMarketState,
    acceptance_signer: Option<DenuoRelayAcceptanceSigner>,
}

/// Shared bounded Denuo relay service for native runtime extensions.
///
/// The handle exposes only verified canonical object storage and abuse policy;
/// it has no signing, matching, pricing, or funds interface.
#[derive(Clone)]
pub struct DenuoRelayHandle {
    inner: Arc<Mutex<DenuoRelayService>>,
}

impl std::fmt::Debug for DenuoRelayHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DenuoRelayHandle")
            .finish_non_exhaustive()
    }
}

/// Node relay-handle failure.
#[derive(Debug, Error)]
pub enum DenuoRelayHandleError {
    /// Relay policy rejected the operation.
    #[error(transparent)]
    Relay(#[from] RelayError),
    /// A caller panic poisoned the process-local relay lock.
    #[error("Denuo relay lock poisoned")]
    LockPoisoned,
    /// Typed name-market semantics or correlation rejected the message.
    #[error("Denuo name-market message rejected: {0}")]
    NameMarket(&'static str),
}

impl DenuoRelayHandle {
    pub(crate) fn new(
        roles: RelayRoles,
        limits: RelayLimits,
        network_magic: u32,
        network_genesis: [u8; 32],
        acceptance_signer: Option<DenuoRelayAcceptanceSigner>,
    ) -> Result<Self, RelayError> {
        if acceptance_signer.as_ref().is_some_and(|signer| {
            let network = signer.policy().network();
            network.magic != network_magic || network.genesis.as_bytes() != &network_genesis
        }) {
            return Err(RelayError::InvalidLimits);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(DenuoRelayService {
                relay: RelayStore::new(roles, limits)?,
                name_market: DenuoNameMarketState::new(network_magic, network_genesis),
                acceptance_signer,
            })),
        })
    }

    /// Admit one hash-first announcement.
    pub fn announce(
        &self,
        peer: PeerIdentity,
        announcement: Announcement,
        now: u64,
    ) -> Result<AnnouncementAdmission, DenuoRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .relay
            .announce(peer, announcement, now)
            .map_err(Into::into)
    }

    /// Admit one exact already-protocol-verified requested payload.
    pub fn put(
        &self,
        peer: PeerIdentity,
        object: RelayObject,
        now: u64,
    ) -> Result<ObjectAdmission, DenuoRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .relay
            .put(peer, object, now)
            .map_err(Into::into)
    }

    /// Fetch one exact object by hash. Board enumeration is intentionally absent.
    pub fn get(
        &self,
        kind: RelayKind,
        hash: ObjectHash,
        now: u64,
    ) -> Result<Option<RelayObject>, DenuoRelayHandleError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .relay
            .get(kind, hash, now)
            .cloned())
    }

    /// Set local per-signer relay policy.
    pub fn set_signer_policy(
        &self,
        signer: SignerIdentity,
        policy: SignerPolicy,
    ) -> Result<(), DenuoRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .relay
            .set_signer_policy(signer, policy)
            .map_err(Into::into)
    }

    /// Apply a malformed-message penalty and progressive ban.
    pub fn penalize_malformed(
        &self,
        peer: PeerIdentity,
        now: u64,
    ) -> Result<(), DenuoRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .relay
            .penalize_malformed(peer, now)
            .map_err(Into::into)
    }

    /// Read bounded name-free role/cache/abuse status.
    pub fn status(&self, now: u64) -> Result<RelayStatus, DenuoRelayHandleError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .relay
            .status(now))
    }

    /// Admit an exact canonical singular offer/cancellation envelope from the
    /// authenticated local wallet boundary. The returned message is suitable
    /// for peer propagation only after this call commits the process-local
    /// relay and event state.
    pub fn submit_name_market_envelope(
        &self,
        envelope_bytes: &[u8],
        now: u64,
    ) -> Result<DenuoNameMarketAdmission, DenuoRelayHandleError> {
        let (registry, request_id, message) = NameMarketMessage::decode_envelope(envelope_bytes)
            .map_err(|_| DenuoRelayHandleError::NameMarket("invalid canonical envelope"))?;
        if registry != DenuoRegistryVersion::V2 || request_id == 0 {
            return Err(DenuoRelayHandleError::NameMarket(
                "local publication requires Denuo V2 and a nonzero request ID",
            ));
        }
        let encoded = message
            .encode_envelope(registry, request_id)
            .map_err(|_| DenuoRelayHandleError::NameMarket("invalid canonical envelope"))?;
        if encoded != envelope_bytes {
            return Err(DenuoRelayHandleError::NameMarket(
                "local publication envelope is not canonical",
            ));
        }
        let mut service = self
            .inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?;
        match message {
            NameMarketMessage::Offer(listing) => admit_listing(
                &mut service,
                LOCAL_WALLET_RELAY_PEER,
                listing,
                request_id,
                now,
            ),
            NameMarketMessage::Cancel(cancellation) => admit_cancellation(
                &mut service,
                LOCAL_WALLET_RELAY_PEER,
                cancellation,
                request_id,
                now,
            ),
            _ => Err(DenuoRelayHandleError::NameMarket(
                "local publication accepts only singular offers and cancellations",
            )),
        }
    }

    /// Admit one exact durable wallet handoff and return an endpoint-signed
    /// receipt covering the exact attempt and canonical envelope.
    pub fn submit_name_market_handoff(
        &self,
        envelope_bytes: &[u8],
        expectation: DenuoPublicationAcceptanceExpectation,
        now: u64,
    ) -> Result<(DenuoNameMarketAdmission, Vec<u8>), DenuoRelayHandleError> {
        let (registry, request_id, message) = NameMarketMessage::decode_envelope(envelope_bytes)
            .map_err(|_| DenuoRelayHandleError::NameMarket("invalid canonical envelope"))?;
        if registry != DenuoRegistryVersion::V2 || request_id == 0 {
            return Err(DenuoRelayHandleError::NameMarket(
                "local publication requires Denuo V2 and a nonzero request ID",
            ));
        }
        let encoded = message
            .encode_envelope(registry, request_id)
            .map_err(|_| DenuoRelayHandleError::NameMarket("invalid canonical envelope"))?;
        if encoded != envelope_bytes {
            return Err(DenuoRelayHandleError::NameMarket(
                "local publication envelope is not canonical",
            ));
        }
        validate_handoff_expectation(envelope_bytes, request_id, &message, expectation, now)?;

        let mut service = self
            .inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?;
        let signer = service
            .acceptance_signer
            .clone()
            .ok_or(DenuoRelayHandleError::NameMarket(
                "Denuo publication acceptance signer is not configured",
            ))?;
        let admission = match message {
            NameMarketMessage::Offer(listing) => admit_listing(
                &mut service,
                LOCAL_WALLET_RELAY_PEER,
                listing,
                request_id,
                now,
            )?,
            NameMarketMessage::Cancel(cancellation) => admit_cancellation(
                &mut service,
                LOCAL_WALLET_RELAY_PEER,
                cancellation,
                request_id,
                now,
            )?,
            _ => {
                return Err(DenuoRelayHandleError::NameMarket(
                    "local publication accepts only singular offers and cancellations",
                ));
            }
        };
        let receipt = signer.sign(expectation, now)?;
        Ok((admission, receipt))
    }

    /// Consume one typed peer message and return only bounded, exactly
    /// correlated sends plus newly committed publications.
    pub fn receive_name_market(
        &self,
        peer_identity: PeerIdentity,
        peer: PeerId,
        request_id: u64,
        message: NameMarketMessage,
        now: u64,
    ) -> Result<DenuoNameMarketDispatch, DenuoRelayHandleError> {
        let mut service = self
            .inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?;
        service.name_market.expire_pending(now);
        let mut dispatch = DenuoNameMarketDispatch::default();
        match message {
            NameMarketMessage::Hello(hello) => {
                validate_market_hello(&service.name_market, hello)?;
                if service.name_market.hello_peers.insert(peer) {
                    dispatch.sends.push(DenuoNameMarketSend {
                        peer,
                        request_id: request_id.max(1),
                        message: NameMarketMessage::Hello(local_market_hello(&service.name_market)),
                    });
                    let inventory_request = service.name_market.next_request_id();
                    dispatch.sends.push(DenuoNameMarketSend {
                        peer,
                        request_id: inventory_request,
                        message: NameMarketMessage::GetOfferInventory,
                    });
                }
            }
            NameMarketMessage::GetOfferInventory => {
                dispatch.sends.push(DenuoNameMarketSend {
                    peer,
                    request_id,
                    message: NameMarketMessage::OfferInventory(active_inventory(
                        &service.name_market,
                        now,
                    )),
                });
            }
            NameMarketMessage::OfferInventory(hashes) => {
                let missing = hashes
                    .into_iter()
                    .filter(|hash| !active_listing_known(&service.name_market, *hash, now))
                    .collect::<Vec<_>>();
                for chunk in missing.chunks(MAX_NAME_OFFERS_PER_MESSAGE) {
                    if service.name_market.pending.len() >= MAX_DENUO_NAME_MARKET_PENDING_REQUESTS {
                        return Err(DenuoRelayHandleError::NameMarket(
                            "name-market peer request capacity reached",
                        ));
                    }
                    let request_id = service.name_market.next_request_id();
                    let hashes = chunk.to_vec();
                    service.name_market.pending.insert(
                        (peer, request_id),
                        PendingNameMarketRequest {
                            hashes: hashes.clone(),
                            expires_at_unix: now
                                .saturating_add(DENUO_NAME_MARKET_REQUEST_LIFETIME_SECONDS),
                        },
                    );
                    dispatch.sends.push(DenuoNameMarketSend {
                        peer,
                        request_id,
                        message: NameMarketMessage::GetOffers(hashes),
                    });
                }
            }
            NameMarketMessage::GetOffers(hashes) => {
                let listings = hashes
                    .into_iter()
                    .filter_map(|hash| active_listing(&service.name_market, hash, now))
                    .collect::<Vec<_>>();
                if !listings.is_empty() {
                    dispatch.sends.push(DenuoNameMarketSend {
                        peer,
                        request_id,
                        message: NameMarketMessage::Offers(listings),
                    });
                }
            }
            NameMarketMessage::Offers(listings) => {
                let expected = service
                    .name_market
                    .pending
                    .remove(&(peer, request_id))
                    .ok_or(DenuoRelayHandleError::NameMarket(
                        "uncorrelated name-market offer batch",
                    ))?;
                let returned = listings
                    .iter()
                    .map(|listing| {
                        listing.listing_hash().map_err(|_| {
                            DenuoRelayHandleError::NameMarket("invalid listing signature")
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if returned
                    .iter()
                    .any(|hash| expected.hashes.binary_search(hash).is_err())
                {
                    return Err(DenuoRelayHandleError::NameMarket(
                        "offer batch does not match its request",
                    ));
                }
                for listing in listings {
                    let admission =
                        admit_listing(&mut service, peer_identity, listing, request_id, now)?;
                    dispatch.admissions.push(admission);
                }
            }
            NameMarketMessage::GetOffer(hash) => {
                if let Some(listing) = active_listing(&service.name_market, hash, now) {
                    dispatch.sends.push(DenuoNameMarketSend {
                        peer,
                        request_id,
                        message: NameMarketMessage::Offer(listing),
                    });
                }
            }
            NameMarketMessage::Offer(listing) => {
                let expected = service
                    .name_market
                    .pending
                    .remove(&(peer, request_id))
                    .ok_or(DenuoRelayHandleError::NameMarket(
                        "uncorrelated singular name-market offer",
                    ))?;
                let hash = listing
                    .listing_hash()
                    .map_err(|_| DenuoRelayHandleError::NameMarket("invalid listing signature"))?;
                if expected.hashes.as_slice() != [hash] {
                    return Err(DenuoRelayHandleError::NameMarket(
                        "singular offer does not match its request",
                    ));
                }
                dispatch.admissions.push(admit_listing(
                    &mut service,
                    peer_identity,
                    listing,
                    request_id,
                    now,
                )?);
            }
            NameMarketMessage::Cancel(cancellation) => {
                let event_request_id = if request_id == 0 {
                    service.name_market.next_request_id()
                } else {
                    request_id
                };
                dispatch.admissions.push(admit_cancellation(
                    &mut service,
                    peer_identity,
                    cancellation,
                    event_request_id,
                    now,
                )?);
            }
        }
        Ok(dispatch)
    }

    /// Read one bounded, monotonic process-local event page for an
    /// authenticated wallet consumer.
    pub fn name_market_events(
        &self,
        instance_nonce: [u8; 32],
        after_revision: u64,
        limit: usize,
    ) -> Result<DenuoNameMarketEventPage, DenuoRelayHandleError> {
        if instance_nonce == [0; 32] || limit == 0 || limit > MAX_DENUO_NAME_MARKET_EVENT_PAGE {
            return Err(DenuoRelayHandleError::NameMarket(
                "invalid name-market event page limit",
            ));
        }
        let service = self
            .inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?;
        let oldest_revision = service
            .name_market
            .events
            .front()
            .map_or(service.name_market.revision.saturating_add(1), |event| {
                event.revision
            });
        if after_revision > service.name_market.revision {
            return Err(DenuoRelayHandleError::NameMarket(
                "name-market event cursor is outside the retained window",
            ));
        }
        let events = service
            .name_market
            .events
            .iter()
            .filter(|event| event.revision > after_revision)
            .take(limit)
            .cloned()
            .collect();
        Ok(DenuoNameMarketEventPage {
            instance_nonce,
            cursor_reset: false,
            oldest_revision,
            head_revision: service.name_market.revision,
            events,
        })
    }

    /// Page the latest seller/name states under one exact adapter revision.
    /// A changed revision invalidates the whole traversal rather than mixing
    /// states from different snapshots.
    pub fn name_market_snapshot(
        &self,
        instance_nonce: [u8; 32],
        expected_revision: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> Result<DenuoNameMarketSnapshotPage, DenuoRelayHandleError> {
        if instance_nonce == [0; 32] || limit == 0 || limit > MAX_DENUO_NAME_MARKET_SNAPSHOT_PAGE {
            return Err(DenuoRelayHandleError::NameMarket(
                "invalid name-market snapshot page limit",
            ));
        }
        let service = self
            .inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?;
        let revision = service.name_market.revision;
        if expected_revision.is_some_and(|expected| expected != revision)
            || offset > service.name_market.records.len()
        {
            return Err(DenuoRelayHandleError::NameMarket(
                "name-market snapshot changed during traversal",
            ));
        }
        let records = service
            .name_market
            .records
            .values()
            .skip(offset)
            .take(limit)
            .map(|record| -> Result<_, DenuoRelayHandleError> {
                let (kind, content_hash) = match &record.state {
                    NameMarketRecordState::Active { .. } => {
                        (DenuoNameMarketEventKind::Offer, record.listing_hash)
                    }
                    NameMarketRecordState::Cancelled { cancellation } => {
                        let cancellation_hash = cancellation.cancellation_hash().map_err(|_| {
                            DenuoRelayHandleError::NameMarket(
                                "retained name-market cancellation identity is invalid",
                            )
                        })?;
                        (DenuoNameMarketEventKind::Cancellation, cancellation_hash)
                    }
                };
                Ok(DenuoNameMarketSnapshotRecord {
                    kind,
                    content_hash,
                    envelope_bytes: record.envelope_bytes.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let consumed =
            offset
                .checked_add(records.len())
                .ok_or(DenuoRelayHandleError::NameMarket(
                    "name-market snapshot cursor overflowed",
                ))?;
        let next_offset = (consumed < service.name_market.records.len()).then_some(consumed);
        Ok(DenuoNameMarketSnapshotPage {
            instance_nonce,
            snapshot_revision: revision,
            next_offset,
            records,
        })
    }
}

fn validate_handoff_expectation(
    envelope_bytes: &[u8],
    request_id: u64,
    message: &NameMarketMessage,
    expectation: DenuoPublicationAcceptanceExpectation,
    now: u64,
) -> Result<(), DenuoRelayHandleError> {
    let (network, content_id, message_kind) = match message {
        NameMarketMessage::Offer(listing) => (
            listing.network(),
            listing
                .listing_hash()
                .map_err(|_| DenuoRelayHandleError::NameMarket("invalid listing identity"))?,
            DenuoPublicationMessageKind::Offer,
        ),
        NameMarketMessage::Cancel(cancellation) => (
            cancellation.network,
            cancellation
                .cancellation_hash()
                .map_err(|_| DenuoRelayHandleError::NameMarket("invalid cancellation identity"))?,
            DenuoPublicationMessageKind::Cancellation,
        ),
        _ => {
            return Err(DenuoRelayHandleError::NameMarket(
                "local publication accepts only singular offers and cancellations",
            ));
        }
    };
    let mut envelope_id = Sha256::new();
    envelope_id.update(DENUO_OUTBOX_ENVELOPE_ID_DOMAIN);
    envelope_id.update(envelope_bytes);
    let envelope_id: [u8; 32] = envelope_id.finalize().into();
    let envelope_digest: [u8; 32] = Sha256::digest(envelope_bytes).into();
    if expectation.network_magic != network.magic
        || expectation.network_genesis != *network.genesis.as_bytes()
        || expectation.request_id != request_id
        || expectation.content_id != content_id
        || expectation.message_kind != message_kind
        || expectation.envelope_id != envelope_id
        || expectation.envelope_digest != envelope_digest
        || expectation.prepared_at_unix > now
    {
        return Err(DenuoRelayHandleError::NameMarket(
            "Denuo handoff does not match its canonical envelope",
        ));
    }
    Ok(())
}

fn validate_market_hello(
    state: &DenuoNameMarketState,
    hello: NameMarketHello,
) -> Result<(), DenuoRelayHandleError> {
    if hello.hns_magic != state.network_magic
        || hello.hns_genesis.as_bytes() != &state.network_genesis
        || hello.maximum_payload == 0
        || usize::try_from(hello.maximum_payload)
            .ok()
            .is_none_or(|maximum| maximum > MAX_DENUO_MARKET_PAYLOAD)
    {
        return Err(DenuoRelayHandleError::NameMarket(
            "name-market hello has the wrong network or bounds",
        ));
    }
    Ok(())
}

fn local_market_hello(state: &DenuoNameMarketState) -> NameMarketHello {
    NameMarketHello {
        hns_magic: state.network_magic,
        hns_genesis: state.network_genesis.into(),
        maximum_payload: u32::try_from(MAX_DENUO_MARKET_PAYLOAD)
            .expect("canonical Denuo market bound fits u32"),
        feature_flags: 0,
    }
}

fn active_inventory(state: &DenuoNameMarketState, now: u64) -> Vec<[u8; 32]> {
    state
        .records
        .values()
        .filter_map(|record| match &record.state {
            NameMarketRecordState::Active { listing, .. }
                if listing.created_at <= now && now < listing.expires_at =>
            {
                Some(record.listing_hash)
            }
            _ => None,
        })
        .collect()
}

fn active_listing_known(state: &DenuoNameMarketState, hash: [u8; 32], now: u64) -> bool {
    active_listing(state, hash, now).is_some()
}

fn active_listing(
    state: &DenuoNameMarketState,
    hash: [u8; 32],
    now: u64,
) -> Option<FixedPriceListing> {
    let identity = state.listing_index.get(&hash)?;
    let record = state.records.get(identity)?;
    match &record.state {
        NameMarketRecordState::Active { listing, .. }
            if record.listing_hash == hash
                && listing.created_at <= now
                && now < listing.expires_at =>
        {
            Some(listing.clone())
        }
        _ => None,
    }
}

fn admit_listing(
    service: &mut DenuoRelayService,
    peer: PeerIdentity,
    listing: FixedPriceListing,
    request_id: u64,
    now: u64,
) -> Result<DenuoNameMarketAdmission, DenuoRelayHandleError> {
    listing
        .verify()
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid listing signature"))?;
    if listing.network().magic != service.name_market.network_magic
        || listing.network().genesis.as_bytes() != &service.name_market.network_genesis
        || listing.created_at > now
        || listing.expires_at <= now
    {
        return Err(DenuoRelayHandleError::NameMarket(
            "listing has the wrong network or active window",
        ));
    }
    let listing_hash = listing
        .listing_hash()
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid listing identity"))?;
    let identity = listing_identity(&listing)?;
    if let Some(existing) = service.name_market.records.get(&identity) {
        if existing.listing_hash == listing_hash
            && matches!(existing.state, NameMarketRecordState::Active { .. })
        {
            return Ok(DenuoNameMarketAdmission {
                revision: service.name_market.revision,
                kind: DenuoNameMarketEventKind::Offer,
                content_hash: listing_hash,
                inserted: false,
                rebroadcast: None,
            });
        }
        if listing.sequence <= existing.sequence {
            return Err(DenuoRelayHandleError::NameMarket(
                "listing sequence does not advance seller/name state",
            ));
        }
    } else if service.name_market.records.len() >= MAX_DENUO_NAME_MARKET_RECORDS {
        return Err(DenuoRelayHandleError::NameMarket(
            "name-market record capacity reached",
        ));
    }
    let payload = listing
        .encode()
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid listing encoding"))?;
    admit_relay_object(
        &mut service.relay,
        peer,
        identity,
        listing.sequence,
        listing.created_at,
        listing.expires_at,
        payload,
        now,
    )?;
    let envelope_bytes = NameMarketMessage::Offer(listing.clone())
        .encode_envelope(DenuoRegistryVersion::V2, request_id)
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid listing envelope"))?;
    if let Some(previous) = service.name_market.records.get(&identity) {
        service
            .name_market
            .listing_index
            .remove(&previous.listing_hash);
    }
    service
        .name_market
        .listing_index
        .insert(listing_hash, identity);
    service.name_market.records.insert(
        identity,
        NameMarketRecord {
            listing_hash,
            sequence: listing.sequence,
            state: NameMarketRecordState::Active {
                listing: listing.clone(),
            },
            envelope_bytes: envelope_bytes.clone(),
        },
    );
    append_event(
        &mut service.name_market,
        now,
        DenuoNameMarketEventKind::Offer,
        listing_hash,
        envelope_bytes,
    )?;
    Ok(DenuoNameMarketAdmission {
        revision: service.name_market.revision,
        kind: DenuoNameMarketEventKind::Offer,
        content_hash: listing_hash,
        inserted: true,
        rebroadcast: Some(NameMarketMessage::OfferInventory(vec![listing_hash])),
    })
}

fn admit_cancellation(
    service: &mut DenuoRelayService,
    peer: PeerIdentity,
    cancellation: ListingCancellation,
    request_id: u64,
    now: u64,
) -> Result<DenuoNameMarketAdmission, DenuoRelayHandleError> {
    cancellation
        .verify()
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid cancellation signature"))?;
    if cancellation.network.magic != service.name_market.network_magic
        || cancellation.network.genesis.as_bytes() != &service.name_market.network_genesis
        || cancellation.created_at > now
        || cancellation.expires_at <= now
    {
        return Err(DenuoRelayHandleError::NameMarket(
            "cancellation has the wrong network or active window",
        ));
    }
    let cancellation_hash = cancellation
        .cancellation_hash()
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid cancellation identity"))?;
    let identity = *service
        .name_market
        .listing_index
        .get(&cancellation.listing_hash)
        .ok_or(DenuoRelayHandleError::NameMarket(
            "cancellation target listing is unavailable",
        ))?;
    let existing =
        service
            .name_market
            .records
            .get(&identity)
            .ok_or(DenuoRelayHandleError::NameMarket(
                "cancellation target state is unavailable",
            ))?;
    let listing = match &existing.state {
        NameMarketRecordState::Active { listing, .. } => listing.clone(),
        NameMarketRecordState::Cancelled {
            cancellation: durable,
        } => {
            let durable_hash = durable
                .cancellation_hash()
                .map_err(|_| DenuoRelayHandleError::NameMarket("invalid retained cancellation"))?;
            if durable_hash == cancellation_hash {
                return Ok(DenuoNameMarketAdmission {
                    revision: service.name_market.revision,
                    kind: DenuoNameMarketEventKind::Cancellation,
                    content_hash: cancellation_hash,
                    inserted: false,
                    rebroadcast: None,
                });
            }
            return Err(DenuoRelayHandleError::NameMarket(
                "cancellation does not advance seller/name state",
            ));
        }
    };
    cancellation
        .verify_for_listing(&listing, cancellation.network, now)
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid listing cancellation"))?;
    if cancellation.sequence <= existing.sequence {
        return Err(DenuoRelayHandleError::NameMarket(
            "cancellation sequence does not advance seller/name state",
        ));
    }
    let payload = cancellation
        .encode()
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid cancellation encoding"))?;
    admit_relay_object(
        &mut service.relay,
        peer,
        identity,
        cancellation.sequence,
        cancellation.created_at,
        cancellation.expires_at,
        payload,
        now,
    )?;
    let envelope_bytes = NameMarketMessage::Cancel(cancellation.clone())
        .encode_envelope(DenuoRegistryVersion::V2, request_id)
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid cancellation envelope"))?;
    service.name_market.records.insert(
        identity,
        NameMarketRecord {
            listing_hash: cancellation.listing_hash,
            sequence: cancellation.sequence,
            state: NameMarketRecordState::Cancelled {
                cancellation: cancellation.clone(),
            },
            envelope_bytes: envelope_bytes.clone(),
        },
    );
    append_event(
        &mut service.name_market,
        now,
        DenuoNameMarketEventKind::Cancellation,
        cancellation_hash,
        envelope_bytes,
    )?;
    Ok(DenuoNameMarketAdmission {
        revision: service.name_market.revision,
        kind: DenuoNameMarketEventKind::Cancellation,
        content_hash: cancellation_hash,
        inserted: true,
        rebroadcast: Some(NameMarketMessage::Cancel(cancellation)),
    })
}

#[allow(clippy::too_many_arguments)]
fn admit_relay_object(
    relay: &mut RelayStore,
    peer: PeerIdentity,
    signer: SignerIdentity,
    sequence: u64,
    created_at: u64,
    expires_at: u64,
    payload: Vec<u8>,
    now: u64,
) -> Result<(), DenuoRelayHandleError> {
    let object = RelayObject::new(
        RelayKind::NameMarket,
        signer,
        sequence,
        created_at,
        expires_at,
        payload,
    )?;
    match relay.announce(peer, object.announcement.clone(), now)? {
        AnnouncementAdmission::FetchRequired { .. } => {
            let _ = relay.put(peer, object, now)?;
            Ok(())
        }
        AnnouncementAdmission::AlreadyStored => Ok(()),
        AnnouncementAdmission::AlreadyPending => Err(DenuoRelayHandleError::NameMarket(
            "relay object fetch is already pending from another delivery",
        )),
    }
}

fn listing_identity(listing: &FixedPriceListing) -> Result<[u8; 32], DenuoRelayHandleError> {
    let name_hash = listing
        .name_hash()
        .map_err(|_| DenuoRelayHandleError::NameMarket("invalid listing name"))?;
    let mut identity = Vec::with_capacity(
        NAME_MARKET_IDENTITY_DOMAIN.len() + listing.seller_public_key().len() + 32,
    );
    identity.extend_from_slice(NAME_MARKET_IDENTITY_DOMAIN);
    identity.extend_from_slice(listing.seller_public_key());
    identity.extend_from_slice(name_hash.as_bytes());
    Ok(blake2b_256(&identity))
}

fn append_event(
    state: &mut DenuoNameMarketState,
    received_at_unix: u64,
    kind: DenuoNameMarketEventKind,
    content_hash: [u8; 32],
    envelope_bytes: Vec<u8>,
) -> Result<(), DenuoRelayHandleError> {
    if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_DENUO_MARKET_PAYLOAD {
        return Err(DenuoRelayHandleError::NameMarket(
            "name-market event envelope exceeds bounds",
        ));
    }
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or(DenuoRelayHandleError::NameMarket(
            "name-market revision exhausted",
        ))?;
    if state.events.len() == MAX_DENUO_NAME_MARKET_EVENTS {
        state.events.pop_front();
    }
    state.events.push_back(DenuoNameMarketEvent {
        revision: state.revision,
        received_at_unix,
        kind,
        content_hash,
        envelope_bytes,
    });
    Ok(())
}
