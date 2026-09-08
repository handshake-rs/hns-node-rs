//! Node-owned handle and typed name-market adapter for the bounded Shakescape relay.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use hns_marketplace_protocol::{
    sign_shakescape_publication_acceptance, CrossChainMessage, DirectOffer, DirectOfferTake,
    NameMarketHello, NameMarketMessage, ShakescapePublicationAcceptanceExpectation,
    ShakescapePublicationAcceptancePolicy, ShakescapePublicationMessageKind,
    ShakescapeRegistryVersion, SwapSessionHello, MAX_NAME_OFFERS_PER_MESSAGE,
    MAX_SHAKESCAPE_MARKET_PAYLOAD,
};
use hns_p2p::PeerId;
use hns_primitives::blake2b_256;
use hns_shakescape_market_relay::{
    Announcement, AnnouncementAdmission, ObjectAdmission, ObjectHash, PeerIdentity, RelayError,
    RelayKind, RelayLimits, RelayObject, RelayRoles, RelayStatus, RelayStore, SignerIdentity,
    SignerPolicy,
};
use hns_swap::{FixedPriceListing, ListingCancellation};
use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum live seller/name rows in the process-local typed adapter.
pub const MAX_SHAKESCAPE_NAME_MARKET_RECORDS: usize = 4_096;
/// Maximum durable-consumer events retained by the process-local adapter.
pub const MAX_SHAKESCAPE_NAME_MARKET_EVENTS: usize = 8_192;
/// Maximum events exposed by one authenticated local wallet RPC call.
pub const MAX_SHAKESCAPE_NAME_MARKET_EVENT_PAGE: usize = 256;
/// Maximum latest-state records exposed by one authenticated snapshot page.
pub const MAX_SHAKESCAPE_NAME_MARKET_SNAPSHOT_PAGE: usize = 256;
/// Maximum correlated peer requests retained at once.
const MAX_SHAKESCAPE_NAME_MARKET_PENDING_REQUESTS: usize = 1_024;
const SHAKESCAPE_NAME_MARKET_REQUEST_LIFETIME_SECONDS: u64 = 15;
const MAX_SHAKESCAPE_CROSS_CHAIN_OFFERS: usize = 4_096;
const MAX_SHAKESCAPE_CROSS_CHAIN_SESSIONS: usize = 1_024;
const MAX_SHAKESCAPE_CROSS_CHAIN_PENDING_REQUESTS: usize = 4_096;
const SHAKESCAPE_CROSS_CHAIN_REQUEST_LIFETIME_SECONDS: u64 = 15;
const LOCAL_WALLET_RELAY_PEER: [u8; 32] = [0x57; 32];
const NAME_MARKET_IDENTITY_DOMAIN: &[u8] = b"hns-node/shakescape-name-market-identity/v1";
const SHAKESCAPE_OUTBOX_ENVELOPE_ID_DOMAIN: &[u8] = b"hns-wallet-shakescape-outbox-envelope-v1\0";

/// Endpoint signing authority for exact local wallet handoff receipts.
///
/// The private key is zeroized, omitted from `Debug`, and never exposed by an
/// accessor. Equality exists only so complete node configurations retain their
/// established deterministic comparison semantics.
#[derive(Clone)]
pub struct ShakescapeRelayAcceptanceSigner {
    policy: ShakescapePublicationAcceptancePolicy,
    endpoint_private_key: Arc<Zeroizing<[u8; 32]>>,
}

impl ShakescapeRelayAcceptanceSigner {
    pub fn new(
        policy: ShakescapePublicationAcceptancePolicy,
        endpoint_private_key: [u8; 32],
    ) -> Result<Self, ShakescapeRelayAcceptanceSignerError> {
        let endpoint_private_key = Zeroizing::new(endpoint_private_key);
        let signing_key = SigningKey::from_bytes((&*endpoint_private_key).into())
            .map_err(|_| ShakescapeRelayAcceptanceSignerError::InvalidPrivateKey)?;
        if signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            != policy.hnsa().endpoint_public_key
        {
            return Err(ShakescapeRelayAcceptanceSignerError::KeyMismatch);
        }
        Ok(Self {
            policy,
            endpoint_private_key: Arc::new(endpoint_private_key),
        })
    }

    pub const fn policy(&self) -> &ShakescapePublicationAcceptancePolicy {
        &self.policy
    }

    fn sign(
        &self,
        expectation: ShakescapePublicationAcceptanceExpectation,
        accepted_at_unix: u64,
    ) -> Result<Vec<u8>, ShakescapeRelayHandleError> {
        let maximum_expiry = accepted_at_unix
            .checked_add(u64::from(self.policy.maximum_receipt_lifetime_seconds()))
            .ok_or(ShakescapeRelayHandleError::NameMarket(
                "Shakescape acceptance receipt time overflowed",
            ))?;
        let expires_at_unix = maximum_expiry.min(self.policy.hnsa().effective_expires_at_unix);
        if expires_at_unix <= accepted_at_unix {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "Shakescape acceptance endpoint is outside its effective window",
            ));
        }
        sign_shakescape_publication_acceptance(
            &self.policy,
            expectation,
            accepted_at_unix,
            expires_at_unix,
            &self.endpoint_private_key,
        )
        .map_err(|_| {
            ShakescapeRelayHandleError::NameMarket("failed to sign Shakescape acceptance receipt")
        })
    }
}

impl std::fmt::Debug for ShakescapeRelayAcceptanceSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShakescapeRelayAcceptanceSigner")
            .field("policy", &self.policy)
            .field("endpoint_private_key", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for ShakescapeRelayAcceptanceSigner {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy
            && self.endpoint_private_key.as_ref().as_ref()
                == other.endpoint_private_key.as_ref().as_ref()
    }
}

impl Eq for ShakescapeRelayAcceptanceSigner {}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ShakescapeRelayAcceptanceSignerError {
    #[error("Shakescape relay acceptance private key is invalid")]
    InvalidPrivateKey,
    #[error("Shakescape relay acceptance private key does not match the HNSA endpoint")]
    KeyMismatch,
}

/// Public event kind projected to the authenticated local wallet transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShakescapeNameMarketEventKind {
    Offer,
    Cancellation,
}

impl ShakescapeNameMarketEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Cancellation => "cancellation",
        }
    }
}

/// One exact canonical singular envelope admitted by the typed adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeNameMarketEvent {
    pub revision: u64,
    pub received_at_unix: u64,
    pub kind: ShakescapeNameMarketEventKind,
    pub content_hash: [u8; 32],
    pub envelope_bytes: Vec<u8>,
}

/// One bounded local event page. A consumer behind `oldest_revision` must
/// rebuild from a fresh active inventory rather than silently skipping rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeNameMarketEventPage {
    pub instance_nonce: [u8; 32],
    pub cursor_reset: bool,
    pub oldest_revision: u64,
    pub head_revision: u64,
    pub events: Vec<ShakescapeNameMarketEvent>,
}

/// One latest seller/name state in a coherent process-local snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeNameMarketSnapshotRecord {
    pub kind: ShakescapeNameMarketEventKind,
    pub content_hash: [u8; 32],
    pub envelope_bytes: Vec<u8>,
}

/// A coherent bounded page over the adapter's latest seller/name states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeNameMarketSnapshotPage {
    pub instance_nonce: [u8; 32],
    pub snapshot_revision: u64,
    pub next_offset: Option<usize>,
    pub records: Vec<ShakescapeNameMarketSnapshotRecord>,
}

/// Result of one local or peer publication admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeNameMarketAdmission {
    pub revision: u64,
    pub kind: ShakescapeNameMarketEventKind,
    pub content_hash: [u8; 32],
    pub inserted: bool,
    pub(crate) rebroadcast: Option<NameMarketMessage>,
}

/// One exact response/request that the native peer event loop must send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeNameMarketSend {
    pub peer: PeerId,
    pub request_id: u64,
    pub message: NameMarketMessage,
}

/// Complete bounded result of consuming one typed peer message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShakescapeNameMarketDispatch {
    pub sends: Vec<ShakescapeNameMarketSend>,
    pub admissions: Vec<ShakescapeNameMarketAdmission>,
}

/// One exactly targeted cross-chain send. Bilateral session material is never
/// broadcast to unrelated board peers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakescapeCrossChainSend {
    pub peer: PeerId,
    pub request_id: u64,
    pub message: CrossChainMessage,
}

/// Bounded transport effects from one cross-chain board/session message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShakescapeCrossChainDispatch {
    pub sends: Vec<ShakescapeCrossChainSend>,
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
struct ShakescapeNameMarketState {
    network_magic: u32,
    network_genesis: [u8; 32],
    records: BTreeMap<[u8; 32], NameMarketRecord>,
    listing_index: BTreeMap<[u8; 32], [u8; 32]>,
    events: VecDeque<ShakescapeNameMarketEvent>,
    revision: u64,
    next_request_id: u64,
    pending: HashMap<(PeerId, u64), PendingNameMarketRequest>,
    hello_peers: BTreeSet<PeerId>,
}

impl ShakescapeNameMarketState {
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

#[derive(Clone, Debug)]
struct CrossChainOfferRecord {
    offer: DirectOffer,
    owner: Option<PeerId>,
}

#[derive(Clone, Debug)]
struct CrossChainSessionRoute {
    offer_id: [u8; 32],
    maker: PeerId,
    taker: PeerId,
    take: DirectOfferTake,
    hello: Option<SwapSessionHello>,
}

#[derive(Debug)]
struct ShakescapeCrossChainState {
    network_magic: u32,
    network_genesis: [u8; 32],
    offers: BTreeMap<[u8; 32], CrossChainOfferRecord>,
    sessions: BTreeMap<[u8; 32], CrossChainSessionRoute>,
    peers: BTreeSet<PeerId>,
    pending: HashMap<(PeerId, u64), ([u8; 32], u64)>,
    next_request_id: u64,
}

impl ShakescapeCrossChainState {
    fn new(network_magic: u32, network_genesis: [u8; 32]) -> Self {
        Self {
            network_magic,
            network_genesis,
            offers: BTreeMap::new(),
            sessions: BTreeMap::new(),
            peers: BTreeSet::new(),
            pending: HashMap::new(),
            next_request_id: 1,
        }
    }

    fn next_request_id(&mut self) -> u64 {
        let request_id = self.next_request_id.max(1);
        self.next_request_id = request_id.checked_add(1).unwrap_or(1);
        request_id
    }

    fn expire(&mut self, now: u64) {
        self.pending.retain(|_, (_, expires_at)| *expires_at > now);
        self.offers
            .retain(|_, record| record.offer.header.expires_at > now);
        self.sessions.retain(|_, route| {
            self.offers.contains_key(&route.offer_id) && route.take.header.expires_at > now
        });
    }
}

#[derive(Debug)]
struct ShakescapeRelayService {
    relay: RelayStore,
    name_market: ShakescapeNameMarketState,
    cross_chain: ShakescapeCrossChainState,
    acceptance_signer: Option<ShakescapeRelayAcceptanceSigner>,
}

/// Shared bounded Shakescape relay service for native runtime extensions.
///
/// The handle exposes only verified canonical object storage and abuse policy;
/// it has no signing, matching, pricing, or funds interface.
#[derive(Clone)]
pub struct ShakescapeRelayHandle {
    inner: Arc<Mutex<ShakescapeRelayService>>,
}

impl std::fmt::Debug for ShakescapeRelayHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShakescapeRelayHandle")
            .finish_non_exhaustive()
    }
}

/// Node relay-handle failure.
#[derive(Debug, Error)]
pub enum ShakescapeRelayHandleError {
    /// Relay policy rejected the operation.
    #[error(transparent)]
    Relay(#[from] RelayError),
    /// A caller panic poisoned the process-local relay lock.
    #[error("Shakescape relay lock poisoned")]
    LockPoisoned,
    /// Typed name-market semantics or correlation rejected the message.
    #[error("Shakescape name-market message rejected: {0}")]
    NameMarket(&'static str),
    /// Typed HNS/BTC board routing or bilateral correlation rejected a message.
    #[error("Shakescape cross-chain message rejected: {0}")]
    CrossChain(&'static str),
    /// The message is valid for a relay role this node did not enable. This is
    /// local policy, not peer misbehavior, and must never affect peer score.
    #[error("Shakescape relay role is disabled: {0:?}")]
    RoleDisabled(RelayKind),
}

impl ShakescapeRelayHandle {
    pub(crate) fn new(
        roles: RelayRoles,
        limits: RelayLimits,
        network_magic: u32,
        network_genesis: [u8; 32],
        acceptance_signer: Option<ShakescapeRelayAcceptanceSigner>,
    ) -> Result<Self, RelayError> {
        if acceptance_signer.as_ref().is_some_and(|signer| {
            let network = signer.policy().network();
            network.magic != network_magic || network.genesis.as_bytes() != &network_genesis
        }) {
            return Err(RelayError::InvalidLimits);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(ShakescapeRelayService {
                relay: RelayStore::new(roles, limits)?,
                name_market: ShakescapeNameMarketState::new(network_magic, network_genesis),
                cross_chain: ShakescapeCrossChainState::new(network_magic, network_genesis),
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
    ) -> Result<AnnouncementAdmission, ShakescapeRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?
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
    ) -> Result<ObjectAdmission, ShakescapeRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?
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
    ) -> Result<Option<RelayObject>, ShakescapeRelayHandleError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?
            .relay
            .get(kind, hash, now)
            .cloned())
    }

    /// Set local per-signer relay policy.
    pub fn set_signer_policy(
        &self,
        signer: SignerIdentity,
        policy: SignerPolicy,
    ) -> Result<(), ShakescapeRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?
            .relay
            .set_signer_policy(signer, policy)
            .map_err(Into::into)
    }

    /// Apply a malformed-message penalty and progressive ban.
    pub fn penalize_malformed(
        &self,
        peer: PeerIdentity,
        now: u64,
    ) -> Result<(), ShakescapeRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?
            .relay
            .penalize_malformed(peer, now)
            .map_err(Into::into)
    }

    /// Read bounded name-free role/cache/abuse status.
    pub fn status(&self, now: u64) -> Result<RelayStatus, ShakescapeRelayHandleError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?
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
    ) -> Result<ShakescapeNameMarketAdmission, ShakescapeRelayHandleError> {
        let (registry, request_id, message) = NameMarketMessage::decode_envelope(envelope_bytes)
            .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid canonical envelope"))?;
        if registry != ShakescapeRegistryVersion::V1 || request_id == 0 {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "local publication requires Shakescape V1 and a nonzero request ID",
            ));
        }
        let encoded = message
            .encode_envelope(registry, request_id)
            .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid canonical envelope"))?;
        if encoded != envelope_bytes {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "local publication envelope is not canonical",
            ));
        }
        let mut service = self
            .inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?;
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
            _ => Err(ShakescapeRelayHandleError::NameMarket(
                "local publication accepts only singular offers and cancellations",
            )),
        }
    }

    /// Admit one exact durable wallet handoff and return an endpoint-signed
    /// receipt covering the exact attempt and canonical envelope.
    pub fn submit_name_market_handoff(
        &self,
        envelope_bytes: &[u8],
        expectation: ShakescapePublicationAcceptanceExpectation,
        now: u64,
    ) -> Result<(ShakescapeNameMarketAdmission, Vec<u8>), ShakescapeRelayHandleError> {
        let (registry, request_id, message) = NameMarketMessage::decode_envelope(envelope_bytes)
            .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid canonical envelope"))?;
        if registry != ShakescapeRegistryVersion::V1 || request_id == 0 {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "local publication requires Shakescape V1 and a nonzero request ID",
            ));
        }
        let encoded = message
            .encode_envelope(registry, request_id)
            .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid canonical envelope"))?;
        if encoded != envelope_bytes {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "local publication envelope is not canonical",
            ));
        }
        validate_handoff_expectation(envelope_bytes, request_id, &message, expectation, now)?;

        let mut service = self
            .inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?;
        let signer =
            service
                .acceptance_signer
                .clone()
                .ok_or(ShakescapeRelayHandleError::NameMarket(
                    "Shakescape publication acceptance signer is not configured",
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
                return Err(ShakescapeRelayHandleError::NameMarket(
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
    ) -> Result<ShakescapeNameMarketDispatch, ShakescapeRelayHandleError> {
        let mut service = self
            .inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?;
        service.name_market.expire_pending(now);
        let mut dispatch = ShakescapeNameMarketDispatch::default();
        match message {
            NameMarketMessage::Hello(hello) => {
                validate_market_hello(&service.name_market, hello)?;
                if service.name_market.hello_peers.insert(peer) {
                    dispatch.sends.push(ShakescapeNameMarketSend {
                        peer,
                        request_id: request_id.max(1),
                        message: NameMarketMessage::Hello(local_market_hello(&service.name_market)),
                    });
                    let inventory_request = service.name_market.next_request_id();
                    dispatch.sends.push(ShakescapeNameMarketSend {
                        peer,
                        request_id: inventory_request,
                        message: NameMarketMessage::GetOfferInventory,
                    });
                }
            }
            NameMarketMessage::GetOfferInventory => {
                dispatch.sends.push(ShakescapeNameMarketSend {
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
                    if service.name_market.pending.len()
                        >= MAX_SHAKESCAPE_NAME_MARKET_PENDING_REQUESTS
                    {
                        return Err(ShakescapeRelayHandleError::NameMarket(
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
                                .saturating_add(SHAKESCAPE_NAME_MARKET_REQUEST_LIFETIME_SECONDS),
                        },
                    );
                    dispatch.sends.push(ShakescapeNameMarketSend {
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
                    dispatch.sends.push(ShakescapeNameMarketSend {
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
                    .ok_or(ShakescapeRelayHandleError::NameMarket(
                        "uncorrelated name-market offer batch",
                    ))?;
                let returned = listings
                    .iter()
                    .map(|listing| {
                        listing.listing_hash().map_err(|_| {
                            ShakescapeRelayHandleError::NameMarket("invalid listing signature")
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if returned
                    .iter()
                    .any(|hash| expected.hashes.binary_search(hash).is_err())
                {
                    return Err(ShakescapeRelayHandleError::NameMarket(
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
                    dispatch.sends.push(ShakescapeNameMarketSend {
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
                    .ok_or(ShakescapeRelayHandleError::NameMarket(
                        "uncorrelated singular name-market offer",
                    ))?;
                let hash = listing.listing_hash().map_err(|_| {
                    ShakescapeRelayHandleError::NameMarket("invalid listing signature")
                })?;
                if expected.hashes.as_slice() != [hash] {
                    return Err(ShakescapeRelayHandleError::NameMarket(
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

    /// Consume one canonical direct HNS/BTC message. Board inventory is shared
    /// among admitted peers, while take/proposal/hello/status traffic is routed
    /// only across the maker/taker pair established by the signed offer take.
    pub fn receive_cross_chain(
        &self,
        peer: PeerId,
        request_id: u64,
        message: CrossChainMessage,
        now: u64,
    ) -> Result<ShakescapeCrossChainDispatch, ShakescapeRelayHandleError> {
        let mut service = self
            .inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?;
        let required_role = match &message {
            CrossChainMessage::DirectOfferInventory(_)
            | CrossChainMessage::GetDirectOffer(_)
            | CrossChainMessage::DirectOffer(_)
            | CrossChainMessage::CancelDirectOffer(_) => RelayKind::CrossChainMarket,
            CrossChainMessage::TakeDirectOffer(_)
            | CrossChainMessage::SwapSessionProposal(_)
            | CrossChainMessage::SwapSessionHello(_) => RelayKind::Rendezvous,
            CrossChainMessage::SwapFundingStatus(_)
            | CrossChainMessage::SwapRedeemStatus(_)
            | CrossChainMessage::SwapRefundStatus(_)
            | CrossChainMessage::SwapWatchReady(_) => RelayKind::SwapStatus,
        };
        if !service.relay.status(now).roles.contains(required_role) {
            return Err(ShakescapeRelayHandleError::RoleDisabled(required_role));
        }
        let state = &mut service.cross_chain;
        state.expire(now);
        state.peers.insert(peer);
        let mut dispatch = ShakescapeCrossChainDispatch::default();
        match message {
            CrossChainMessage::DirectOfferInventory(offer_ids) => {
                let active = cross_chain_inventory(state, now);
                dispatch.sends.push(ShakescapeCrossChainSend {
                    peer,
                    request_id,
                    message: CrossChainMessage::DirectOfferInventory(active),
                });
                for offer_id in offer_ids {
                    let needs_owner = state
                        .offers
                        .get(&offer_id)
                        .is_none_or(|record| record.owner.is_none());
                    if !needs_owner {
                        continue;
                    }
                    if state.pending.len() >= MAX_SHAKESCAPE_CROSS_CHAIN_PENDING_REQUESTS {
                        return Err(ShakescapeRelayHandleError::CrossChain(
                            "cross-chain offer request capacity reached",
                        ));
                    }
                    let request_id = state.next_request_id();
                    state.pending.insert(
                        (peer, request_id),
                        (
                            offer_id,
                            now.saturating_add(SHAKESCAPE_CROSS_CHAIN_REQUEST_LIFETIME_SECONDS),
                        ),
                    );
                    dispatch.sends.push(ShakescapeCrossChainSend {
                        peer,
                        request_id,
                        message: CrossChainMessage::GetDirectOffer(offer_id),
                    });
                }
            }
            CrossChainMessage::GetDirectOffer(offer_id) => {
                if let Some(record) = state
                    .offers
                    .get(&offer_id)
                    .filter(|record| record.offer.header.expires_at > now)
                {
                    dispatch.sends.push(ShakescapeCrossChainSend {
                        peer,
                        request_id,
                        message: CrossChainMessage::DirectOffer(record.offer.clone()),
                    });
                }
            }
            CrossChainMessage::DirectOffer(offer) => {
                let expected = state.pending.remove(&(peer, request_id)).ok_or(
                    ShakescapeRelayHandleError::CrossChain("uncorrelated direct offer"),
                )?;
                if expected.0 != offer.offer_id {
                    return Err(ShakescapeRelayHandleError::CrossChain(
                        "direct offer does not match its request",
                    ));
                }
                validate_cross_chain_offer(state, &offer, now)?;
                if !state.offers.contains_key(&offer.offer_id)
                    && state.offers.len() >= MAX_SHAKESCAPE_CROSS_CHAIN_OFFERS
                {
                    return Err(ShakescapeRelayHandleError::CrossChain(
                        "cross-chain offer capacity reached",
                    ));
                }
                let offer_id = offer.offer_id;
                state.offers.insert(
                    offer_id,
                    CrossChainOfferRecord {
                        offer,
                        owner: Some(peer),
                    },
                );
                for target in state.peers.iter().copied().filter(|target| *target != peer) {
                    dispatch.sends.push(ShakescapeCrossChainSend {
                        peer: target,
                        request_id,
                        message: CrossChainMessage::DirectOfferInventory(vec![offer_id]),
                    });
                }
            }
            CrossChainMessage::CancelDirectOffer(cancellation) => {
                let record = state.offers.get(&cancellation.offer_id).ok_or(
                    ShakescapeRelayHandleError::CrossChain("unknown direct offer cancellation"),
                )?;
                if record.owner != Some(peer) {
                    return Err(ShakescapeRelayHandleError::CrossChain(
                        "direct offer cancellation came from a non-owner peer",
                    ));
                }
                cancellation
                    .verify_for_offer(&record.offer, record.offer.header.network, now)
                    .map_err(|_| {
                        ShakescapeRelayHandleError::CrossChain("invalid direct offer cancellation")
                    })?;
                state.offers.remove(&cancellation.offer_id);
                state
                    .sessions
                    .retain(|_, route| route.offer_id != cancellation.offer_id);
                for target in state.peers.iter().copied().filter(|target| *target != peer) {
                    dispatch.sends.push(ShakescapeCrossChainSend {
                        peer: target,
                        request_id,
                        message: CrossChainMessage::CancelDirectOffer(cancellation.clone()),
                    });
                }
            }
            CrossChainMessage::TakeDirectOffer(take) => {
                let record = state.offers.get(&take.offer_id).ok_or(
                    ShakescapeRelayHandleError::CrossChain("take targets an unknown direct offer"),
                )?;
                let maker = record.owner.ok_or(ShakescapeRelayHandleError::CrossChain(
                    "direct offer owner is currently unavailable",
                ))?;
                if maker == peer {
                    return Err(ShakescapeRelayHandleError::CrossChain(
                        "direct offer owner cannot take its own offer",
                    ));
                }
                take.verify_for_offer(&record.offer, record.offer.header.network, now)
                    .map_err(|_| {
                        ShakescapeRelayHandleError::CrossChain("invalid direct offer take")
                    })?;
                if let Some(route) = state.sessions.get(&take.swap_session_id) {
                    if route.maker != maker || route.taker != peer || route.take != take {
                        return Err(ShakescapeRelayHandleError::CrossChain(
                            "swap session route conflicts with an existing take",
                        ));
                    }
                } else {
                    if state.sessions.len() >= MAX_SHAKESCAPE_CROSS_CHAIN_SESSIONS {
                        return Err(ShakescapeRelayHandleError::CrossChain(
                            "cross-chain session capacity reached",
                        ));
                    }
                    state.sessions.insert(
                        take.swap_session_id,
                        CrossChainSessionRoute {
                            offer_id: take.offer_id,
                            maker,
                            taker: peer,
                            take: take.clone(),
                            hello: None,
                        },
                    );
                }
                dispatch.sends.push(ShakescapeCrossChainSend {
                    peer: maker,
                    request_id,
                    message: CrossChainMessage::TakeDirectOffer(take),
                });
            }
            CrossChainMessage::SwapSessionProposal(proposal) => {
                let session_id = proposal.terms().swap_session_id;
                let route = state.sessions.get(&session_id).cloned().ok_or(
                    ShakescapeRelayHandleError::CrossChain("unknown swap proposal session"),
                )?;
                if peer != route.maker {
                    return Err(ShakescapeRelayHandleError::CrossChain(
                        "swap proposal came from the non-maker peer",
                    ));
                }
                let offer = &state
                    .offers
                    .get(&route.offer_id)
                    .ok_or(ShakescapeRelayHandleError::CrossChain(
                        "swap proposal offer is unavailable",
                    ))?
                    .offer;
                proposal
                    .verify_for_direct_offer(offer, &route.take, offer.header.network, now)
                    .map_err(|_| ShakescapeRelayHandleError::CrossChain("invalid swap proposal"))?;
                dispatch.sends.push(ShakescapeCrossChainSend {
                    peer: route.taker,
                    request_id,
                    message: CrossChainMessage::SwapSessionProposal(proposal),
                });
            }
            CrossChainMessage::SwapSessionHello(hello) => {
                let route = state.sessions.get(&hello.swap_session_id).cloned().ok_or(
                    ShakescapeRelayHandleError::CrossChain("unknown swap hello session"),
                )?;
                if peer != route.taker {
                    return Err(ShakescapeRelayHandleError::CrossChain(
                        "swap hello came from the non-taker peer",
                    ));
                }
                let offer = &state
                    .offers
                    .get(&route.offer_id)
                    .ok_or(ShakescapeRelayHandleError::CrossChain(
                        "swap hello offer is unavailable",
                    ))?
                    .offer;
                hello
                    .verify_for_direct_offer(offer, &route.take, offer.header.network, now)
                    .map_err(|_| ShakescapeRelayHandleError::CrossChain("invalid swap hello"))?;
                state
                    .sessions
                    .get_mut(&hello.swap_session_id)
                    .expect("validated session route remains present")
                    .hello = Some(hello.clone());
                dispatch.sends.push(ShakescapeCrossChainSend {
                    peer: route.maker,
                    request_id,
                    message: CrossChainMessage::SwapSessionHello(hello),
                });
            }
            CrossChainMessage::SwapFundingStatus(status) => {
                let target = validate_cross_chain_status_route(
                    state,
                    peer,
                    status.swap_session_id,
                    |hello| status.verify_for_session(hello, hello.header.network, now),
                )?;
                dispatch.sends.push(ShakescapeCrossChainSend {
                    peer: target,
                    request_id,
                    message: CrossChainMessage::SwapFundingStatus(status),
                });
            }
            CrossChainMessage::SwapRedeemStatus(status) => {
                let target = validate_cross_chain_status_route(
                    state,
                    peer,
                    status.swap_session_id,
                    |hello| status.verify_for_session(hello, hello.header.network, now),
                )?;
                dispatch.sends.push(ShakescapeCrossChainSend {
                    peer: target,
                    request_id,
                    message: CrossChainMessage::SwapRedeemStatus(status),
                });
            }
            CrossChainMessage::SwapRefundStatus(status) => {
                let target = validate_cross_chain_status_route(
                    state,
                    peer,
                    status.swap_session_id,
                    |hello| status.verify_for_session(hello, hello.header.network, now),
                )?;
                dispatch.sends.push(ShakescapeCrossChainSend {
                    peer: target,
                    request_id,
                    message: CrossChainMessage::SwapRefundStatus(status),
                });
            }
            CrossChainMessage::SwapWatchReady(status) => {
                let target = validate_cross_chain_status_route(
                    state,
                    peer,
                    status.swap_session_id,
                    |hello| status.verify_for_session(hello, hello.header.network, now),
                )?;
                dispatch.sends.push(ShakescapeCrossChainSend {
                    peer: target,
                    request_id,
                    message: CrossChainMessage::SwapWatchReady(status),
                });
            }
        }
        Ok(dispatch)
    }

    /// Retire volatile routes for a closed transport. Signed offers remain
    /// cached until expiry, but must be re-proven by a full offer response
    /// before a replacement connection can receive a take.
    pub fn cross_chain_peer_disconnected(
        &self,
        peer: PeerId,
    ) -> Result<(), ShakescapeRelayHandleError> {
        let mut service = self
            .inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?;
        let state = &mut service.cross_chain;
        state.peers.remove(&peer);
        state
            .pending
            .retain(|(pending_peer, _), _| *pending_peer != peer);
        for record in state.offers.values_mut() {
            if record.owner == Some(peer) {
                record.owner = None;
            }
        }
        state
            .sessions
            .retain(|_, route| route.maker != peer && route.taker != peer);
        Ok(())
    }

    /// Read one bounded, monotonic process-local event page for an
    /// authenticated wallet consumer.
    pub fn name_market_events(
        &self,
        instance_nonce: [u8; 32],
        after_revision: u64,
        limit: usize,
    ) -> Result<ShakescapeNameMarketEventPage, ShakescapeRelayHandleError> {
        if instance_nonce == [0; 32] || limit == 0 || limit > MAX_SHAKESCAPE_NAME_MARKET_EVENT_PAGE
        {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "invalid name-market event page limit",
            ));
        }
        let service = self
            .inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?;
        let oldest_revision = service
            .name_market
            .events
            .front()
            .map_or(service.name_market.revision.saturating_add(1), |event| {
                event.revision
            });
        if after_revision > service.name_market.revision {
            return Err(ShakescapeRelayHandleError::NameMarket(
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
        Ok(ShakescapeNameMarketEventPage {
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
    ) -> Result<ShakescapeNameMarketSnapshotPage, ShakescapeRelayHandleError> {
        if instance_nonce == [0; 32]
            || limit == 0
            || limit > MAX_SHAKESCAPE_NAME_MARKET_SNAPSHOT_PAGE
        {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "invalid name-market snapshot page limit",
            ));
        }
        let service = self
            .inner
            .lock()
            .map_err(|_| ShakescapeRelayHandleError::LockPoisoned)?;
        let revision = service.name_market.revision;
        if expected_revision.is_some_and(|expected| expected != revision)
            || offset > service.name_market.records.len()
        {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "name-market snapshot changed during traversal",
            ));
        }
        let records = service
            .name_market
            .records
            .values()
            .skip(offset)
            .take(limit)
            .map(|record| -> Result<_, ShakescapeRelayHandleError> {
                let (kind, content_hash) = match &record.state {
                    NameMarketRecordState::Active { .. } => {
                        (ShakescapeNameMarketEventKind::Offer, record.listing_hash)
                    }
                    NameMarketRecordState::Cancelled { cancellation } => {
                        let cancellation_hash = cancellation.cancellation_hash().map_err(|_| {
                            ShakescapeRelayHandleError::NameMarket(
                                "retained name-market cancellation identity is invalid",
                            )
                        })?;
                        (
                            ShakescapeNameMarketEventKind::Cancellation,
                            cancellation_hash,
                        )
                    }
                };
                Ok(ShakescapeNameMarketSnapshotRecord {
                    kind,
                    content_hash,
                    envelope_bytes: record.envelope_bytes.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let consumed =
            offset
                .checked_add(records.len())
                .ok_or(ShakescapeRelayHandleError::NameMarket(
                    "name-market snapshot cursor overflowed",
                ))?;
        let next_offset = (consumed < service.name_market.records.len()).then_some(consumed);
        Ok(ShakescapeNameMarketSnapshotPage {
            instance_nonce,
            snapshot_revision: revision,
            next_offset,
            records,
        })
    }
}

fn cross_chain_inventory(state: &ShakescapeCrossChainState, now: u64) -> Vec<[u8; 32]> {
    state
        .offers
        .iter()
        .filter(|(_, record)| {
            record.offer.header.expires_at > now
                && record
                    .owner
                    .is_some_and(|owner| state.peers.contains(&owner))
        })
        .map(|(offer_id, _)| *offer_id)
        .collect()
}

fn validate_cross_chain_offer(
    state: &ShakescapeCrossChainState,
    offer: &DirectOffer,
    now: u64,
) -> Result<(), ShakescapeRelayHandleError> {
    if offer.header.network.hns_magic != state.network_magic
        || offer.header.network.hns_genesis.as_bytes() != &state.network_genesis
    {
        return Err(ShakescapeRelayHandleError::CrossChain(
            "direct offer is bound to another Handshake network",
        ));
    }
    offer
        .verify_at(offer.header.network, now)
        .map_err(|_| ShakescapeRelayHandleError::CrossChain("invalid direct offer"))
}

fn validate_cross_chain_status_route<F>(
    state: &ShakescapeCrossChainState,
    peer: PeerId,
    session_id: [u8; 32],
    verify: F,
) -> Result<PeerId, ShakescapeRelayHandleError>
where
    F: FnOnce(&SwapSessionHello) -> hns_marketplace_protocol::Result<()>,
{
    let route = state
        .sessions
        .get(&session_id)
        .ok_or(ShakescapeRelayHandleError::CrossChain(
            "unknown cross-chain status session",
        ))?;
    let target = if peer == route.maker {
        route.taker
    } else if peer == route.taker {
        route.maker
    } else {
        return Err(ShakescapeRelayHandleError::CrossChain(
            "cross-chain status came from an unrelated peer",
        ));
    };
    let hello = route
        .hello
        .as_ref()
        .ok_or(ShakescapeRelayHandleError::CrossChain(
            "cross-chain status preceded the signed hello",
        ))?;
    verify(hello)
        .map_err(|_| ShakescapeRelayHandleError::CrossChain("invalid cross-chain status"))?;
    Ok(target)
}

fn validate_handoff_expectation(
    envelope_bytes: &[u8],
    request_id: u64,
    message: &NameMarketMessage,
    expectation: ShakescapePublicationAcceptanceExpectation,
    now: u64,
) -> Result<(), ShakescapeRelayHandleError> {
    let (network, content_id, message_kind) = match message {
        NameMarketMessage::Offer(listing) => (
            listing.network(),
            listing
                .listing_hash()
                .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid listing identity"))?,
            ShakescapePublicationMessageKind::Offer,
        ),
        NameMarketMessage::Cancel(cancellation) => (
            cancellation.network,
            cancellation.cancellation_hash().map_err(|_| {
                ShakescapeRelayHandleError::NameMarket("invalid cancellation identity")
            })?,
            ShakescapePublicationMessageKind::Cancellation,
        ),
        _ => {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "local publication accepts only singular offers and cancellations",
            ));
        }
    };
    let mut envelope_id = Sha256::new();
    envelope_id.update(SHAKESCAPE_OUTBOX_ENVELOPE_ID_DOMAIN);
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
        return Err(ShakescapeRelayHandleError::NameMarket(
            "Shakescape handoff does not match its canonical envelope",
        ));
    }
    Ok(())
}

fn validate_market_hello(
    state: &ShakescapeNameMarketState,
    hello: NameMarketHello,
) -> Result<(), ShakescapeRelayHandleError> {
    if hello.hns_magic != state.network_magic
        || hello.hns_genesis.as_bytes() != &state.network_genesis
        || hello.maximum_payload == 0
        || usize::try_from(hello.maximum_payload)
            .ok()
            .is_none_or(|maximum| maximum > MAX_SHAKESCAPE_MARKET_PAYLOAD)
    {
        return Err(ShakescapeRelayHandleError::NameMarket(
            "name-market hello has the wrong network or bounds",
        ));
    }
    Ok(())
}

fn local_market_hello(state: &ShakescapeNameMarketState) -> NameMarketHello {
    NameMarketHello {
        hns_magic: state.network_magic,
        hns_genesis: state.network_genesis.into(),
        maximum_payload: u32::try_from(MAX_SHAKESCAPE_MARKET_PAYLOAD)
            .expect("canonical Shakescape market bound fits u32"),
        feature_flags: 0,
    }
}

fn active_inventory(state: &ShakescapeNameMarketState, now: u64) -> Vec<[u8; 32]> {
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

fn active_listing_known(state: &ShakescapeNameMarketState, hash: [u8; 32], now: u64) -> bool {
    active_listing(state, hash, now).is_some()
}

fn active_listing(
    state: &ShakescapeNameMarketState,
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
    service: &mut ShakescapeRelayService,
    peer: PeerIdentity,
    listing: FixedPriceListing,
    request_id: u64,
    now: u64,
) -> Result<ShakescapeNameMarketAdmission, ShakescapeRelayHandleError> {
    listing
        .verify()
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid listing signature"))?;
    if listing.network().magic != service.name_market.network_magic
        || listing.network().genesis.as_bytes() != &service.name_market.network_genesis
        || listing.created_at > now
        || listing.expires_at <= now
    {
        return Err(ShakescapeRelayHandleError::NameMarket(
            "listing has the wrong network or active window",
        ));
    }
    let listing_hash = listing
        .listing_hash()
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid listing identity"))?;
    let identity = listing_identity(&listing)?;
    if let Some(existing) = service.name_market.records.get(&identity) {
        if existing.listing_hash == listing_hash
            && matches!(existing.state, NameMarketRecordState::Active { .. })
        {
            return Ok(ShakescapeNameMarketAdmission {
                revision: service.name_market.revision,
                kind: ShakescapeNameMarketEventKind::Offer,
                content_hash: listing_hash,
                inserted: false,
                rebroadcast: None,
            });
        }
        if listing.sequence <= existing.sequence {
            return Err(ShakescapeRelayHandleError::NameMarket(
                "listing sequence does not advance seller/name state",
            ));
        }
    } else if service.name_market.records.len() >= MAX_SHAKESCAPE_NAME_MARKET_RECORDS {
        return Err(ShakescapeRelayHandleError::NameMarket(
            "name-market record capacity reached",
        ));
    }
    let payload = listing
        .encode()
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid listing encoding"))?;
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
        .encode_envelope(ShakescapeRegistryVersion::V1, request_id)
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid listing envelope"))?;
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
        ShakescapeNameMarketEventKind::Offer,
        listing_hash,
        envelope_bytes,
    )?;
    Ok(ShakescapeNameMarketAdmission {
        revision: service.name_market.revision,
        kind: ShakescapeNameMarketEventKind::Offer,
        content_hash: listing_hash,
        inserted: true,
        rebroadcast: Some(NameMarketMessage::OfferInventory(vec![listing_hash])),
    })
}

fn admit_cancellation(
    service: &mut ShakescapeRelayService,
    peer: PeerIdentity,
    cancellation: ListingCancellation,
    request_id: u64,
    now: u64,
) -> Result<ShakescapeNameMarketAdmission, ShakescapeRelayHandleError> {
    cancellation
        .verify()
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid cancellation signature"))?;
    if cancellation.network.magic != service.name_market.network_magic
        || cancellation.network.genesis.as_bytes() != &service.name_market.network_genesis
        || cancellation.created_at > now
        || cancellation.expires_at <= now
    {
        return Err(ShakescapeRelayHandleError::NameMarket(
            "cancellation has the wrong network or active window",
        ));
    }
    let cancellation_hash = cancellation
        .cancellation_hash()
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid cancellation identity"))?;
    let identity = *service
        .name_market
        .listing_index
        .get(&cancellation.listing_hash)
        .ok_or(ShakescapeRelayHandleError::NameMarket(
            "cancellation target listing is unavailable",
        ))?;
    let existing = service.name_market.records.get(&identity).ok_or(
        ShakescapeRelayHandleError::NameMarket("cancellation target state is unavailable"),
    )?;
    let listing = match &existing.state {
        NameMarketRecordState::Active { listing, .. } => listing.clone(),
        NameMarketRecordState::Cancelled {
            cancellation: durable,
        } => {
            let durable_hash = durable.cancellation_hash().map_err(|_| {
                ShakescapeRelayHandleError::NameMarket("invalid retained cancellation")
            })?;
            if durable_hash == cancellation_hash {
                return Ok(ShakescapeNameMarketAdmission {
                    revision: service.name_market.revision,
                    kind: ShakescapeNameMarketEventKind::Cancellation,
                    content_hash: cancellation_hash,
                    inserted: false,
                    rebroadcast: None,
                });
            }
            return Err(ShakescapeRelayHandleError::NameMarket(
                "cancellation does not advance seller/name state",
            ));
        }
    };
    cancellation
        .verify_for_listing(&listing, cancellation.network, now)
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid listing cancellation"))?;
    if cancellation.sequence <= existing.sequence {
        return Err(ShakescapeRelayHandleError::NameMarket(
            "cancellation sequence does not advance seller/name state",
        ));
    }
    let payload = cancellation
        .encode()
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid cancellation encoding"))?;
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
        .encode_envelope(ShakescapeRegistryVersion::V1, request_id)
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid cancellation envelope"))?;
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
        ShakescapeNameMarketEventKind::Cancellation,
        cancellation_hash,
        envelope_bytes,
    )?;
    Ok(ShakescapeNameMarketAdmission {
        revision: service.name_market.revision,
        kind: ShakescapeNameMarketEventKind::Cancellation,
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
) -> Result<(), ShakescapeRelayHandleError> {
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
        AnnouncementAdmission::AlreadyPending => Err(ShakescapeRelayHandleError::NameMarket(
            "relay object fetch is already pending from another delivery",
        )),
    }
}

fn listing_identity(listing: &FixedPriceListing) -> Result<[u8; 32], ShakescapeRelayHandleError> {
    let name_hash = listing
        .name_hash()
        .map_err(|_| ShakescapeRelayHandleError::NameMarket("invalid listing name"))?;
    let mut identity = Vec::with_capacity(
        NAME_MARKET_IDENTITY_DOMAIN.len() + listing.seller_public_key().len() + 32,
    );
    identity.extend_from_slice(NAME_MARKET_IDENTITY_DOMAIN);
    identity.extend_from_slice(listing.seller_public_key());
    identity.extend_from_slice(name_hash.as_bytes());
    Ok(blake2b_256(&identity))
}

fn append_event(
    state: &mut ShakescapeNameMarketState,
    received_at_unix: u64,
    kind: ShakescapeNameMarketEventKind,
    content_hash: [u8; 32],
    envelope_bytes: Vec<u8>,
) -> Result<(), ShakescapeRelayHandleError> {
    if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_SHAKESCAPE_MARKET_PAYLOAD {
        return Err(ShakescapeRelayHandleError::NameMarket(
            "name-market event envelope exceeds bounds",
        ));
    }
    state.revision =
        state
            .revision
            .checked_add(1)
            .ok_or(ShakescapeRelayHandleError::NameMarket(
                "name-market revision exhausted",
            ))?;
    if state.events.len() == MAX_SHAKESCAPE_NAME_MARKET_EVENTS {
        state.events.pop_front();
    }
    state.events.push_back(ShakescapeNameMarketEvent {
        revision: state.revision,
        received_at_unix,
        kind,
        content_hash,
        envelope_bytes,
    });
    Ok(())
}

#[cfg(test)]
mod cross_chain_tests {
    use hns_marketplace_protocol::{
        AssetAmount, AssetId, ChainId, DirectOffer, DirectOfferTake, MarketPair, NetworkBinding,
        SignedObjectHeader, MARKETPLACE_PROTOCOL_VERSION,
    };
    use hns_protocol_primitives::BlockHash;

    use super::*;

    const NOW: u64 = 1_000;
    const MAGIC: u32 = 0x5b6e_f2d3;
    const GENESIS: [u8; 32] = [1; 32];

    fn public_key(secret: [u8; 32]) -> [u8; 33] {
        SigningKey::from_bytes((&secret).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn network() -> NetworkBinding {
        NetworkBinding {
            hns_magic: MAGIC,
            hns_genesis: BlockHash::new(GENESIS),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 1,
            counterchain_genesis: [2; 32],
        }
    }

    fn header(sequence: u64, created_at: u64, expires_at: u64) -> SignedObjectHeader {
        SignedObjectHeader {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: network(),
            pair: MarketPair::HNS_BTC,
            signer_public_key: [0; 33],
            sequence,
            created_at,
            expires_at,
        }
    }

    fn offer() -> DirectOffer {
        let mut offer = DirectOffer {
            header: header(1, NOW - 10, NOW + 600),
            offer_id: [0; 32],
            swap_session_id: [3; 32],
            maker_settlement_public_key: public_key([9; 32]),
            offered_asset: AssetId::HNS,
            offered_amount: AssetAmount::new(10_000_000),
            received_asset: AssetId::BTC,
            received_amount: AssetAmount::new(2_000),
            signature: [0; 64],
        };
        offer.sign(&[7; 32]).unwrap();
        offer
    }

    fn take(offer: &DirectOffer) -> DirectOfferTake {
        let mut take = DirectOfferTake {
            header: header(2, NOW, NOW + 500),
            offer_id: offer.offer_id,
            swap_session_id: offer.swap_session_id,
            taker_settlement_public_key: public_key([11; 32]),
            signature: [0; 64],
        };
        take.sign(&[10; 32]).unwrap();
        take
    }

    #[test]
    fn rendezvous_routes_a_verified_take_only_to_the_offer_owner() {
        let relay = ShakescapeRelayHandle::new(
            RelayRoles::ALL,
            RelayLimits::default(),
            MAGIC,
            GENESIS,
            None,
        )
        .unwrap();
        let maker = PeerId(1);
        let taker = PeerId(2);
        let observer = PeerId(3);
        for peer in [taker, observer] {
            relay
                .receive_cross_chain(
                    peer,
                    1,
                    CrossChainMessage::DirectOfferInventory(Vec::new()),
                    NOW,
                )
                .unwrap();
        }

        let offer = offer();
        let requested = relay
            .receive_cross_chain(
                maker,
                2,
                CrossChainMessage::DirectOfferInventory(vec![offer.offer_id]),
                NOW,
            )
            .unwrap();
        let request_id = requested
            .sends
            .iter()
            .find_map(|send| match send.message {
                CrossChainMessage::GetDirectOffer(id) if id == offer.offer_id => {
                    Some(send.request_id)
                }
                _ => None,
            })
            .unwrap();
        let announced = relay
            .receive_cross_chain(
                maker,
                request_id,
                CrossChainMessage::DirectOffer(offer.clone()),
                NOW,
            )
            .unwrap();
        assert!(announced.sends.iter().any(|send| send.peer == taker));
        assert!(announced.sends.iter().any(|send| send.peer == observer));

        let routed = relay
            .receive_cross_chain(
                taker,
                9,
                CrossChainMessage::TakeDirectOffer(take(&offer)),
                NOW,
            )
            .unwrap();
        assert_eq!(routed.sends.len(), 1);
        assert_eq!(routed.sends[0].peer, maker);
        assert!(!routed.sends.iter().any(|send| send.peer == observer));
    }

    #[test]
    fn disconnected_maker_must_reprove_the_full_offer_before_receiving_takes() {
        let relay = ShakescapeRelayHandle::new(
            RelayRoles::ALL,
            RelayLimits::default(),
            MAGIC,
            GENESIS,
            None,
        )
        .unwrap();
        let maker = PeerId(1);
        let taker = PeerId(2);
        let offer = offer();
        let requested = relay
            .receive_cross_chain(
                maker,
                1,
                CrossChainMessage::DirectOfferInventory(vec![offer.offer_id]),
                NOW,
            )
            .unwrap();
        let request_id = requested
            .sends
            .iter()
            .find(|send| matches!(send.message, CrossChainMessage::GetDirectOffer(_)))
            .unwrap()
            .request_id;
        relay
            .receive_cross_chain(
                maker,
                request_id,
                CrossChainMessage::DirectOffer(offer.clone()),
                NOW,
            )
            .unwrap();
        relay.cross_chain_peer_disconnected(maker).unwrap();
        let error = relay
            .receive_cross_chain(
                taker,
                3,
                CrossChainMessage::TakeDirectOffer(take(&offer)),
                NOW,
            )
            .unwrap_err();
        assert!(matches!(error, ShakescapeRelayHandleError::CrossChain(_)));
    }
}
