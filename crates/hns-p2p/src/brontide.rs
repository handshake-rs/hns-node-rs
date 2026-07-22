//! HSD-compatible Brontide (Noise XK) handshake and record protection.
//!
//! The protocol is intentionally pinned to HSD's
//! `Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared` construction. It is not
//! a generic Noise framework: fixed sizes, transcript rules, ECDH hashing,
//! Elligator-Squared encoding, nonce layout, and key rotation are consensus for
//! transport compatibility.

use hns_primitives::sha256;
use std::{fmt, sync::Arc};

use hns_secp256k1::{Secp256k1Transport, SecpError};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    constants::MAX_FRAME_PAYLOAD_SIZE,
    wire::{decode_frame, encode_frame, Frame, NetworkMagic},
    P2pError,
};

const PROTOCOL_NAME: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared";
const PROLOGUE: &[u8] = b"hns";
const TAG_SIZE: usize = 16;
const ROTATION_INTERVAL: u32 = 1_000;

pub const BRONTIDE_HEADER_SIZE: usize = 4 + TAG_SIZE;
pub const BRONTIDE_ACT_ONE_SIZE: usize = 64 + TAG_SIZE;
pub const BRONTIDE_ACT_TWO_SIZE: usize = 64 + TAG_SIZE;
pub const BRONTIDE_ACT_THREE_SIZE: usize = 33 + TAG_SIZE + TAG_SIZE;
pub const MAX_BRONTIDE_MESSAGE_SIZE: usize = MAX_FRAME_PAYLOAD_SIZE + 9;

#[derive(Debug)]
struct Secret([u8; 32]);

impl Secret {
    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Long-lived Brontide static identity. Debug output is deliberately redacted;
/// callers persist the private bytes before construction rather than exporting
/// them back out of this object.
#[derive(Clone)]
pub struct BrontideIdentity {
    secret: Arc<Secret>,
    public: [u8; 33],
}

impl BrontideIdentity {
    pub fn from_private_key(private_key: [u8; 32]) -> Result<Self, P2pError> {
        let public = Secp256k1Transport::new()
            .map_err(secp_error)?
            .public_key(&private_key)
            .map_err(secp_error)?;
        Ok(Self {
            secret: Arc::new(Secret::new(private_key)),
            public,
        })
    }

    pub fn generate() -> Self {
        Self::from_private_key(generate_private_key())
            .expect("generated secp256k1 private key must be valid")
    }

    pub const fn public_key(&self) -> &[u8; 33] {
        &self.public
    }

    pub(crate) fn private_key(&self) -> &[u8; 32] {
        self.secret.as_array()
    }
}

impl fmt::Debug for BrontideIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrontideIdentity")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
struct CipherState {
    key: Secret,
    salt: [u8; 32],
    nonce: u32,
}

impl CipherState {
    fn zero() -> Self {
        Self {
            key: Secret::new([0; 32]),
            salt: [0; 32],
            nonce: 0,
        }
    }

    fn init_key(&mut self, key: [u8; 32]) {
        self.key = Secret::new(key);
        self.nonce = 0;
    }

    fn init_salt(&mut self, key: [u8; 32], salt: [u8; 32]) {
        self.salt = salt;
        self.init_key(key);
    }

    fn nonce_bytes(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&self.nonce.to_le_bytes());
        nonce
    }

    fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; TAG_SIZE]), P2pError> {
        let mut tag = [0u8; TAG_SIZE];
        let ciphertext = encrypt_aead(
            Cipher::chacha20_poly1305(),
            self.key.as_array(),
            Some(&self.nonce_bytes()),
            associated_data,
            plaintext,
            &mut tag,
        )
        .map_err(crypto_error)?;
        self.advance()?;
        Ok((ciphertext, tag))
    }

    fn decrypt(
        &mut self,
        ciphertext: &[u8],
        tag: &[u8; TAG_SIZE],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, P2pError> {
        let plaintext = decrypt_aead(
            Cipher::chacha20_poly1305(),
            self.key.as_array(),
            Some(&self.nonce_bytes()),
            associated_data,
            ciphertext,
            tag,
        )
        .map_err(|_| P2pError::Protocol("Brontide authentication tag mismatch".to_owned()))?;
        self.advance()?;
        Ok(plaintext)
    }

    fn advance(&mut self) -> Result<(), P2pError> {
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or_else(|| P2pError::State("Brontide nonce overflow".to_owned()))?;
        if self.nonce == ROTATION_INTERVAL {
            let (salt, next) = hkdf_expand_pair(self.key.as_array(), &self.salt);
            self.salt = salt;
            self.init_key(next);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SymmetricState {
    cipher: CipherState,
    chain: [u8; 32],
    digest: [u8; 32],
}

impl SymmetricState {
    fn new() -> Self {
        let digest = sha256(PROTOCOL_NAME);
        let mut state = Self {
            cipher: CipherState::zero(),
            chain: digest,
            digest,
        };
        state.mix_hash(PROLOGUE, &[]);
        state
    }

    fn mix_hash(&mut self, data: &[u8], tag: &[u8]) {
        let mut input = Vec::with_capacity(self.digest.len() + data.len() + tag.len());
        input.extend_from_slice(&self.digest);
        input.extend_from_slice(data);
        input.extend_from_slice(tag);
        self.digest = sha256(&input);
    }

    fn mix_key(&mut self, input: &[u8]) {
        let (chain, temporary) = hkdf_expand_pair(input, &self.chain);
        self.chain = chain;
        self.cipher.init_key(temporary);
    }

    fn encrypt_hash(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; TAG_SIZE]), P2pError> {
        let (ciphertext, tag) = self.cipher.encrypt(plaintext, &self.digest)?;
        self.mix_hash(&ciphertext, &tag);
        Ok((ciphertext, tag))
    }

    fn decrypt_hash(
        &mut self,
        ciphertext: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<Vec<u8>, P2pError> {
        let mut transcript = Vec::with_capacity(self.digest.len() + ciphertext.len() + tag.len());
        transcript.extend_from_slice(&self.digest);
        transcript.extend_from_slice(ciphertext);
        transcript.extend_from_slice(tag);
        let next_digest = sha256(&transcript);
        let plaintext = self.cipher.decrypt(ciphertext, tag, &self.digest)?;
        self.digest = next_digest;
        Ok(plaintext)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Initiator,
    Responder,
}

/// Stateful three-act HSD Brontide handshake.
///
/// Callers provide ephemeral private keys and Elligator entropy explicitly to
/// keep the state machine deterministic under oracle tests. Production callers
/// should obtain both with [`generate_private_key`] and `rand::random()`.
#[derive(Debug)]
pub struct BrontideHandshake {
    role: Role,
    symmetric: SymmetricState,
    local_static: Secret,
    local_ephemeral: Option<Secret>,
    remote_static: [u8; 33],
    remote_ephemeral: [u8; 33],
    secp: Secp256k1Transport,
}

impl BrontideHandshake {
    pub fn initiator(local_static: [u8; 32], remote_static: [u8; 33]) -> Result<Self, P2pError> {
        let secp = Secp256k1Transport::new().map_err(secp_error)?;
        // Validate both keys before a socket is allowed to enter the protocol.
        secp.public_key(&local_static).map_err(secp_error)?;
        secp.derive_compressed(&remote_static, &local_static)
            .map_err(secp_error)?;
        let mut symmetric = SymmetricState::new();
        symmetric.mix_hash(&remote_static, &[]);
        Ok(Self {
            role: Role::Initiator,
            symmetric,
            local_static: Secret::new(local_static),
            local_ephemeral: None,
            remote_static,
            remote_ephemeral: [0; 33],
            secp,
        })
    }

    pub fn responder(local_static: [u8; 32]) -> Result<Self, P2pError> {
        let secp = Secp256k1Transport::new().map_err(secp_error)?;
        let local_public = secp.public_key(&local_static).map_err(secp_error)?;
        let mut symmetric = SymmetricState::new();
        symmetric.mix_hash(&local_public, &[]);
        Ok(Self {
            role: Role::Responder,
            symmetric,
            local_static: Secret::new(local_static),
            local_ephemeral: None,
            remote_static: [0; 33],
            remote_ephemeral: [0; 33],
            secp,
        })
    }

    pub fn generate_act_one(
        &mut self,
        ephemeral: [u8; 32],
        entropy: [u8; 32],
    ) -> Result<[u8; BRONTIDE_ACT_ONE_SIZE], P2pError> {
        self.require_role(Role::Initiator, "generate act one")?;
        let public = self.secp.public_key(&ephemeral).map_err(secp_error)?;
        let uniform = self
            .secp
            .public_key_to_hash(&public, &entropy)
            .map_err(secp_error)?;
        self.symmetric.mix_hash(&public, &[]);
        let shared = self.ecdh(&self.remote_static, &ephemeral)?;
        self.symmetric.mix_key(&shared);
        let (empty, tag) = self.symmetric.encrypt_hash(&[])?;
        debug_assert!(empty.is_empty());
        self.local_ephemeral = Some(Secret::new(ephemeral));
        let mut act = [0u8; BRONTIDE_ACT_ONE_SIZE];
        act[..64].copy_from_slice(&uniform);
        act[64..].copy_from_slice(&tag);
        Ok(act)
    }

    pub fn receive_act_one(&mut self, act: &[u8; BRONTIDE_ACT_ONE_SIZE]) -> Result<(), P2pError> {
        self.require_role(Role::Responder, "receive act one")?;
        let uniform: &[u8; 64] = act[..64]
            .try_into()
            .expect("act-one Elligator field has fixed length");
        let tag: &[u8; TAG_SIZE] = act[64..].try_into().expect("act-one tag has fixed length");
        let remote = self
            .secp
            .public_key_from_hash(uniform)
            .map_err(secp_error)?;
        self.remote_ephemeral = remote;
        self.symmetric.mix_hash(&remote, &[]);
        let shared = self.ecdh(&remote, self.local_static.as_array())?;
        self.symmetric.mix_key(&shared);
        let empty = self.symmetric.decrypt_hash(&[], tag)?;
        if !empty.is_empty() {
            return Err(P2pError::Protocol(
                "Brontide act one carried plaintext".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn generate_act_two(
        &mut self,
        ephemeral: [u8; 32],
        entropy: [u8; 32],
    ) -> Result<[u8; BRONTIDE_ACT_TWO_SIZE], P2pError> {
        self.require_role(Role::Responder, "generate act two")?;
        if self.remote_ephemeral == [0; 33] {
            return Err(P2pError::State(
                "Brontide act one has not been received".to_owned(),
            ));
        }
        let public = self.secp.public_key(&ephemeral).map_err(secp_error)?;
        let uniform = self
            .secp
            .public_key_to_hash(&public, &entropy)
            .map_err(secp_error)?;
        self.symmetric.mix_hash(&public, &[]);
        let shared = self.ecdh(&self.remote_ephemeral, &ephemeral)?;
        self.symmetric.mix_key(&shared);
        let (empty, tag) = self.symmetric.encrypt_hash(&[])?;
        debug_assert!(empty.is_empty());
        self.local_ephemeral = Some(Secret::new(ephemeral));
        let mut act = [0u8; BRONTIDE_ACT_TWO_SIZE];
        act[..64].copy_from_slice(&uniform);
        act[64..].copy_from_slice(&tag);
        Ok(act)
    }

    pub fn receive_act_two(&mut self, act: &[u8; BRONTIDE_ACT_TWO_SIZE]) -> Result<(), P2pError> {
        self.require_role(Role::Initiator, "receive act two")?;
        let local_ephemeral = self
            .local_ephemeral
            .as_ref()
            .ok_or_else(|| P2pError::State("Brontide act one has not been generated".to_owned()))?;
        let uniform: &[u8; 64] = act[..64]
            .try_into()
            .expect("act-two Elligator field has fixed length");
        let tag: &[u8; TAG_SIZE] = act[64..].try_into().expect("act-two tag has fixed length");
        let remote = self
            .secp
            .public_key_from_hash(uniform)
            .map_err(secp_error)?;
        self.remote_ephemeral = remote;
        self.symmetric.mix_hash(&remote, &[]);
        let shared = self.ecdh(&remote, local_ephemeral.as_array())?;
        self.symmetric.mix_key(&shared);
        let empty = self.symmetric.decrypt_hash(&[], tag)?;
        if !empty.is_empty() {
            return Err(P2pError::Protocol(
                "Brontide act two carried plaintext".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn generate_act_three(
        mut self,
    ) -> Result<([u8; BRONTIDE_ACT_THREE_SIZE], BrontideSession), P2pError> {
        self.require_role(Role::Initiator, "generate act three")?;
        if self.remote_ephemeral == [0; 33] {
            return Err(P2pError::State(
                "Brontide act two has not been received".to_owned(),
            ));
        }
        let local_public = self
            .secp
            .public_key(self.local_static.as_array())
            .map_err(secp_error)?;
        let (ciphertext, tag_one) = self.symmetric.encrypt_hash(&local_public)?;
        let shared = self.ecdh(&self.remote_ephemeral, self.local_static.as_array())?;
        self.symmetric.mix_key(&shared);
        let (empty, tag_two) = self.symmetric.encrypt_hash(&[])?;
        debug_assert!(empty.is_empty());
        let mut act = [0u8; BRONTIDE_ACT_THREE_SIZE];
        act[..33].copy_from_slice(&ciphertext);
        act[33..49].copy_from_slice(&tag_one);
        act[49..].copy_from_slice(&tag_two);
        let session = self.split()?;
        Ok((act, session))
    }

    pub fn receive_act_three(
        mut self,
        act: &[u8; BRONTIDE_ACT_THREE_SIZE],
    ) -> Result<BrontideSession, P2pError> {
        self.require_role(Role::Responder, "receive act three")?;
        let local_ephemeral = self
            .local_ephemeral
            .as_ref()
            .ok_or_else(|| P2pError::State("Brontide act two has not been generated".to_owned()))?;
        let tag_one: &[u8; TAG_SIZE] = act[33..49]
            .try_into()
            .expect("act-three first tag has fixed length");
        let remote = self.symmetric.decrypt_hash(&act[..33], tag_one)?;
        let remote_static: [u8; 33] = remote
            .try_into()
            .map_err(|_| P2pError::Protocol("Brontide act three key has wrong size".to_owned()))?;
        self.remote_static = remote_static;
        let shared = self.ecdh(&remote_static, local_ephemeral.as_array())?;
        self.symmetric.mix_key(&shared);
        let tag_two: &[u8; TAG_SIZE] = act[49..]
            .try_into()
            .expect("act-three second tag has fixed length");
        let empty = self.symmetric.decrypt_hash(&[], tag_two)?;
        if !empty.is_empty() {
            return Err(P2pError::Protocol(
                "Brontide act three carried trailing plaintext".to_owned(),
            ));
        }
        self.split()
    }

    fn require_role(&self, expected: Role, operation: &str) -> Result<(), P2pError> {
        if self.role != expected {
            return Err(P2pError::State(format!(
                "cannot {operation} as a {:?}",
                self.role
            )));
        }
        Ok(())
    }

    fn ecdh(&self, public_key: &[u8; 33], private_key: &[u8; 32]) -> Result<[u8; 32], P2pError> {
        let compressed = self
            .secp
            .derive_compressed(public_key, private_key)
            .map_err(secp_error)?;
        Ok(sha256(&compressed))
    }

    fn split(self) -> Result<BrontideSession, P2pError> {
        let (first, second) = hkdf_expand_pair(&[], &self.symmetric.chain);
        let (send_key, receive_key) = match self.role {
            Role::Initiator => (first, second),
            Role::Responder => (second, first),
        };
        let mut send_cipher = CipherState::zero();
        send_cipher.init_salt(send_key, self.symmetric.chain);
        let mut receive_cipher = CipherState::zero();
        receive_cipher.init_salt(receive_key, self.symmetric.chain);
        Ok(BrontideSession {
            send_cipher,
            receive_cipher,
            remote_static: self.remote_static,
        })
    }
}

/// Established bidirectional Brontide record keys.
#[derive(Debug)]
pub struct BrontideSession {
    send_cipher: CipherState,
    receive_cipher: CipherState,
    remote_static: [u8; 33],
}

impl BrontideSession {
    pub fn remote_static_key(&self) -> &[u8; 33] {
        &self.remote_static
    }

    /// Encrypt one complete HSD stream message using its four-byte little-endian
    /// length record followed by the separately authenticated payload.
    pub fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>, P2pError> {
        if message.len() > MAX_BRONTIDE_MESSAGE_SIZE {
            return Err(P2pError::LimitExceeded {
                context: "Brontide message",
                limit: MAX_BRONTIDE_MESSAGE_SIZE,
                actual: message.len(),
            });
        }
        let length = u32::try_from(message.len())
            .map_err(|_| P2pError::Protocol("Brontide message length exceeds u32".to_owned()))?
            .to_le_bytes();
        let (encrypted_length, length_tag) = self.send_cipher.encrypt(&length, &[])?;
        let (encrypted_message, message_tag) = self.send_cipher.encrypt(message, &[])?;
        let mut output = Vec::with_capacity(BRONTIDE_HEADER_SIZE + message.len() + TAG_SIZE);
        output.extend_from_slice(&encrypted_length);
        output.extend_from_slice(&length_tag);
        output.extend_from_slice(&encrypted_message);
        output.extend_from_slice(&message_tag);
        Ok(output)
    }

    /// Authenticate and decode an HSD stream length record.
    pub fn decrypt_header(
        &mut self,
        header: &[u8; BRONTIDE_HEADER_SIZE],
    ) -> Result<usize, P2pError> {
        let tag: &[u8; TAG_SIZE] = header[4..]
            .try_into()
            .expect("Brontide header tag has fixed length");
        let plaintext = self.receive_cipher.decrypt(&header[..4], tag, &[])?;
        let size = u32::from_le_bytes(
            plaintext
                .as_slice()
                .try_into()
                .map_err(|_| P2pError::Protocol("Brontide header has wrong size".to_owned()))?,
        ) as usize;
        if size > MAX_BRONTIDE_MESSAGE_SIZE {
            return Err(P2pError::LimitExceeded {
                context: "Brontide message",
                limit: MAX_BRONTIDE_MESSAGE_SIZE,
                actual: size,
            });
        }
        Ok(size)
    }

    /// Authenticate and decrypt the payload record after [`Self::decrypt_header`].
    pub fn decrypt_payload(&mut self, record: &[u8]) -> Result<Vec<u8>, P2pError> {
        if record.len() < TAG_SIZE {
            return Err(P2pError::Protocol(
                "Brontide payload record is truncated".to_owned(),
            ));
        }
        let split = record.len() - TAG_SIZE;
        let tag: &[u8; TAG_SIZE] = record[split..]
            .try_into()
            .expect("Brontide payload tag has fixed length");
        self.receive_cipher.decrypt(&record[..split], tag, &[])
    }

    pub(crate) fn into_ciphers(self) -> (BrontideSendCipher, BrontideReceiveCipher) {
        (
            BrontideSendCipher(self.send_cipher),
            BrontideReceiveCipher(self.receive_cipher),
        )
    }
}

#[derive(Debug)]
pub(crate) struct BrontideSendCipher(CipherState);

impl BrontideSendCipher {
    pub(crate) fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>, P2pError> {
        let mut session = BrontideSession {
            send_cipher: std::mem::replace(&mut self.0, CipherState::zero()),
            receive_cipher: CipherState::zero(),
            remote_static: [0; 33],
        };
        let result = session.encrypt_message(message);
        self.0 = session.send_cipher;
        result
    }
}

#[derive(Debug)]
pub(crate) struct BrontideReceiveCipher(CipherState);

impl BrontideReceiveCipher {
    pub(crate) fn decrypt_header(
        &mut self,
        header: &[u8; BRONTIDE_HEADER_SIZE],
    ) -> Result<usize, P2pError> {
        let tag: &[u8; TAG_SIZE] = header[4..]
            .try_into()
            .expect("Brontide header tag has fixed length");
        let plaintext = self.0.decrypt(&header[..4], tag, &[])?;
        let size = u32::from_le_bytes(
            plaintext
                .as_slice()
                .try_into()
                .map_err(|_| P2pError::Protocol("Brontide header has wrong size".to_owned()))?,
        ) as usize;
        if size > MAX_BRONTIDE_MESSAGE_SIZE {
            return Err(P2pError::LimitExceeded {
                context: "Brontide message",
                limit: MAX_BRONTIDE_MESSAGE_SIZE,
                actual: size,
            });
        }
        Ok(size)
    }

    pub(crate) fn decrypt_payload(&mut self, record: &[u8]) -> Result<Vec<u8>, P2pError> {
        if record.len() < TAG_SIZE {
            return Err(P2pError::Protocol(
                "Brontide payload record is truncated".to_owned(),
            ));
        }
        let split = record.len() - TAG_SIZE;
        let tag: &[u8; TAG_SIZE] = record[split..]
            .try_into()
            .expect("Brontide payload tag has fixed length");
        self.0.decrypt(&record[..split], tag, &[])
    }
}

/// Reader half for established HSD Brontide stream records.
pub(crate) struct AsyncBrontideFrameReader<R> {
    io: R,
    cipher: BrontideReceiveCipher,
    magic: NetworkMagic,
}

impl<R> AsyncBrontideFrameReader<R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) fn new(io: R, cipher: BrontideReceiveCipher, magic: NetworkMagic) -> Self {
        Self { io, cipher, magic }
    }

    pub(crate) async fn read_frame(&mut self) -> Result<Frame, P2pError> {
        let mut header = [0u8; BRONTIDE_HEADER_SIZE];
        self.io.read_exact(&mut header).await?;
        let size = self.cipher.decrypt_header(&header)?;
        let mut payload = vec![0u8; size + TAG_SIZE];
        self.io.read_exact(&mut payload).await?;
        let plaintext = self.cipher.decrypt_payload(&payload)?;
        decode_frame(self.magic, &plaintext)
    }
}

/// Writer half for established HSD Brontide stream records.
pub(crate) struct AsyncBrontideFrameWriter<W> {
    io: W,
    cipher: BrontideSendCipher,
    magic: NetworkMagic,
}

impl<W> AsyncBrontideFrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub(crate) fn new(io: W, cipher: BrontideSendCipher, magic: NetworkMagic) -> Self {
        Self { io, cipher, magic }
    }

    pub(crate) async fn write_frame(&mut self, frame: &Frame) -> Result<usize, P2pError> {
        let plaintext = encode_frame(self.magic, frame)?;
        let record = self.cipher.encrypt_message(&plaintext)?;
        let size = record.len();
        self.io.write_all(&record).await?;
        self.io.flush().await?;
        Ok(size)
    }
}

/// Complete an outbound Brontide handshake over a connected socket.
pub(crate) async fn outbound_handshake<T>(
    io: &mut T,
    identity: &BrontideIdentity,
    remote_static: [u8; 33],
) -> Result<BrontideSession, P2pError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut handshake = BrontideHandshake::initiator(*identity.private_key(), remote_static)?;
    let act_one = handshake.generate_act_one(generate_private_key(), rand::random())?;
    io.write_all(&act_one).await?;
    io.flush().await?;
    let mut act_two = [0u8; BRONTIDE_ACT_TWO_SIZE];
    io.read_exact(&mut act_two).await?;
    handshake.receive_act_two(&act_two)?;
    let (act_three, session) = handshake.generate_act_three()?;
    io.write_all(&act_three).await?;
    io.flush().await?;
    Ok(session)
}

/// Complete an inbound Brontide handshake over an accepted socket.
pub(crate) async fn inbound_handshake<T>(
    io: &mut T,
    identity: &BrontideIdentity,
) -> Result<BrontideSession, P2pError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut handshake = BrontideHandshake::responder(*identity.private_key())?;
    let mut act_one = [0u8; BRONTIDE_ACT_ONE_SIZE];
    io.read_exact(&mut act_one).await?;
    handshake.receive_act_one(&act_one)?;
    let act_two = handshake.generate_act_two(generate_private_key(), rand::random())?;
    io.write_all(&act_two).await?;
    io.flush().await?;
    let mut act_three = [0u8; BRONTIDE_ACT_THREE_SIZE];
    io.read_exact(&mut act_three).await?;
    handshake.receive_act_three(&act_three)
}

/// Generate a valid random secp256k1 private scalar.
pub fn generate_private_key() -> [u8; 32] {
    let secp = Secp256k1Transport::new().expect("pinned secp256k1 context must initialize");
    loop {
        let candidate = rand::random::<[u8; 32]>();
        if secp.public_key(&candidate).is_ok() {
            return candidate;
        }
    }
}

fn hkdf_expand_pair(secret: &[u8], salt: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let pseudorandom_key = hmac_sha256(salt, secret);
    let first = hmac_sha256(&pseudorandom_key, &[1]);
    let mut second_input = [0u8; 33];
    second_input[..32].copy_from_slice(&first);
    second_input[32] = 2;
    let second = hmac_sha256(&pseudorandom_key, &second_input);
    (first, second)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut normalized = [0u8; 64];
    if key.len() > normalized.len() {
        normalized[..32].copy_from_slice(&sha256(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend(normalized.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(64 + inner_hash.len());
    outer.extend(normalized.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

fn crypto_error(error: openssl::error::ErrorStack) -> P2pError {
    P2pError::State(format!("Brontide crypto failed: {error}"))
}

fn secp_error(error: SecpError) -> P2pError {
    P2pError::Protocol(format!("Brontide secp256k1 failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORACLE_FIXTURE: &str = include_str!("../../../fixtures/hsd/p2p/wire-v1.json");

    fn oracle_string(pointer: &str) -> String {
        serde_json::from_str::<serde_json::Value>(ORACLE_FIXTURE)
            .expect("pinned P2P oracle fixture")
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("missing oracle string {pointer}"))
            .to_owned()
    }

    fn exchange() -> (BrontideSession, BrontideSession) {
        let initiator_static = [0x11; 32];
        let responder_static = [0x21; 32];
        let responder_public = Secp256k1Transport::new()
            .expect("secp")
            .public_key(&responder_static)
            .expect("responder public");
        let mut initiator =
            BrontideHandshake::initiator(initiator_static, responder_public).expect("initiator");
        let mut responder = BrontideHandshake::responder(responder_static).expect("responder");
        let act_one = initiator
            .generate_act_one([0x12; 32], [0x31; 32])
            .expect("act one");
        responder.receive_act_one(&act_one).expect("receive one");
        let act_two = responder
            .generate_act_two([0x22; 32], [0x32; 32])
            .expect("act two");
        initiator.receive_act_two(&act_two).expect("receive two");
        let (act_three, initiator) = initiator.generate_act_three().expect("act three");
        let responder = responder
            .receive_act_three(&act_three)
            .expect("receive three");
        (initiator, responder)
    }

    #[test]
    fn cipher_matches_pinned_hsd_vectors() {
        let mut cipher = CipherState::zero();
        cipher.init_salt([0x21; 32], [0x11; 32]);
        let (ciphertext, tag) = cipher.encrypt(b"hello", &[]).expect("encrypt");
        assert_eq!(
            hex(&ciphertext),
            oracle_string("/brontide/cipher/firstCiphertext")
        );
        assert_eq!(hex(&tag), oracle_string("/brontide/cipher/firstTag"));
        let (ciphertext, tag) = cipher.encrypt(b"hello", &[]).expect("encrypt two");
        assert_eq!(
            hex(&ciphertext),
            oracle_string("/brontide/cipher/secondCiphertext")
        );
        assert_eq!(hex(&tag), oracle_string("/brontide/cipher/secondTag"));
    }

    #[test]
    fn handshake_keys_and_hsd_packet_match_pinned_vectors() {
        let (mut initiator, responder) = exchange();
        assert_eq!(
            hex(initiator.send_cipher.key.as_array()),
            oracle_string("/brontide/handshake/initiatorSendKey")
        );
        assert_eq!(
            hex(initiator.receive_cipher.key.as_array()),
            oracle_string("/brontide/handshake/initiatorReceiveKey")
        );
        assert_eq!(
            initiator.send_cipher.key.as_array(),
            responder.receive_cipher.key.as_array()
        );
        assert_eq!(
            initiator.receive_cipher.key.as_array(),
            responder.send_cipher.key.as_array()
        );

        // HSD's non-stream Brontide helper uses a two-byte BE length. This
        // byte-for-byte vector independently checks the split session ciphers.
        let (encrypted_length, length_tag) = initiator
            .send_cipher
            .encrypt(&(5u16.to_be_bytes()), &[])
            .expect("length");
        let (encrypted_message, message_tag) = initiator
            .send_cipher
            .encrypt(b"hello", &[])
            .expect("message");
        let mut packet = Vec::new();
        packet.extend_from_slice(&encrypted_length);
        packet.extend_from_slice(&length_tag);
        packet.extend_from_slice(&encrypted_message);
        packet.extend_from_slice(&message_tag);
        assert_eq!(
            hex(&packet),
            oracle_string("/brontide/handshake/firstPacket")
        );
    }

    #[test]
    fn stream_records_round_trip_and_fail_closed() {
        let (mut initiator, mut responder) = exchange();
        let record = initiator
            .encrypt_message(b"native mainnet")
            .expect("encrypt");
        let header: &[u8; BRONTIDE_HEADER_SIZE] =
            record[..BRONTIDE_HEADER_SIZE].try_into().expect("header");
        let size = responder.decrypt_header(header).expect("header auth");
        assert_eq!(size, 14);
        assert_eq!(
            responder
                .decrypt_payload(&record[BRONTIDE_HEADER_SIZE..])
                .expect("payload auth"),
            b"native mainnet"
        );

        let (mut initiator, mut responder) = exchange();
        let mut record = initiator.encrypt_message(b"tamper").expect("encrypt");
        record[BRONTIDE_HEADER_SIZE] ^= 1;
        let header: &[u8; BRONTIDE_HEADER_SIZE] =
            record[..BRONTIDE_HEADER_SIZE].try_into().expect("header");
        responder.decrypt_header(header).expect("header auth");
        assert!(responder
            .decrypt_payload(&record[BRONTIDE_HEADER_SIZE..])
            .is_err());
    }

    #[test]
    fn cipher_rotation_matches_hsd() {
        let mut cipher = CipherState::zero();
        cipher.init_salt([0x21; 32], [0x11; 32]);
        cipher.nonce = 999;
        cipher.encrypt(b"hello", &[]).expect("rotation encrypt");
        assert_eq!(cipher.nonce, 0);
        assert_eq!(
            hex(cipher.key.as_array()),
            oracle_string("/brontide/cipher/rotatedKey")
        );
        assert_eq!(
            hex(&cipher.salt),
            oracle_string("/brontide/cipher/rotatedSalt")
        );
    }

    fn hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(TABLE[(byte >> 4) as usize] as char);
            output.push(TABLE[(byte & 0x0f) as usize] as char);
        }
        output
    }
}
