//! Authenticated HSD fixed seeds for portable Brontide bootstrap.

use std::{net::IpAddr, net::SocketAddr};

use hns_consensus::Network;

use crate::{constants::SERVICE_NETWORK, wire::NetAddress, P2pError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HsdBrontideSeed {
    pub host: &'static str,
    pub public_key_hex: &'static str,
}

// Key-bearing fixed seeds from HSD's pinned `lib/net/seeds` tables. DNS seed
// answers do not carry Brontide static keys and are therefore not an
// authenticated bootstrap substitute.
pub const HSD_MAINNET_BRONTIDE_SEEDS: &[HsdBrontideSeed] = &[
    HsdBrontideSeed {
        host: "129.153.177.220",
        public_key_hex: "02a58318ea330487308b1a4bd90bd196a466e99be64a3cf2f1fe7b5352154a25c2",
    },
    HsdBrontideSeed {
        host: "159.69.46.23",
        public_key_hex: "03e7c897432e08b0a2a6f6e9cfdb0aa8d3392f8abe4a3c2d40013b2ee06b1adb6a",
    },
    HsdBrontideSeed {
        host: "173.255.209.126",
        public_key_hex: "024798bdd795240b711787273406f7950fd2a943a0bb096701720682eb3aea37ed",
    },
    HsdBrontideSeed {
        host: "74.207.247.120",
        public_key_hex: "0290c11c1d0895f96f9c1b0c4f2b6034ee3d4ee8f5f90c9b6c76bd27d4bd0a5cbd",
    },
    HsdBrontideSeed {
        host: "172.104.214.189",
        public_key_hex: "039078400609f39f5ae6e6d132161561860e52d35637ed3f5a5050c160dd28dfde",
    },
    HsdBrontideSeed {
        host: "45.79.134.225",
        public_key_hex: "03fb5a5801cdb19f01472480d00c1c928e498f49955eab5217cd00e755bd267973",
    },
    HsdBrontideSeed {
        host: "35.154.209.88",
        public_key_hex: "022d850f3bfb951c6de1d2f239183721bfaa2b1ac89576200fcca6f84181d1da62",
    },
    HsdBrontideSeed {
        host: "194.50.5.26",
        public_key_hex: "023e3322d4221160923ea1dc481523a26ef3fa8483da062f7e92040534cc6b3606",
    },
    HsdBrontideSeed {
        host: "194.50.5.27",
        public_key_hex: "03949fede42b27117d0a75e08cf1b139a37241ad4bebcb5c8a9928fdec7469107d",
    },
    HsdBrontideSeed {
        host: "194.50.5.28",
        public_key_hex: "0247eb646fdf05bd470c5ad380d42e936ffe8278e46cc9bd5791ea58c28587ab45",
    },
];

pub const HSD_TESTNET_BRONTIDE_SEEDS: &[HsdBrontideSeed] = &[
    HsdBrontideSeed {
        host: "172.104.214.189",
        public_key_hex: "039078400609f39f5ae6e6d132161561860e52d35637ed3f5a5050c160dd28dfde",
    },
    HsdBrontideSeed {
        host: "173.255.209.126",
        public_key_hex: "024798bdd795240b711787273406f7950fd2a943a0bb096701720682eb3aea37ed",
    },
    HsdBrontideSeed {
        host: "172.104.177.177",
        public_key_hex: "0255dfda9369ca3cd616844c00eed63f2d7740cd56780a856def1e64f536214539",
    },
    HsdBrontideSeed {
        host: "139.162.183.168",
        public_key_hex: "0334b93039cdda203e704bb5a4831b66665b2f7b0dcea7fd022dfea623b1aa4081",
    },
];

pub const fn hsd_brontide_seed_table(network: Network) -> &'static [HsdBrontideSeed] {
    match network {
        Network::Mainnet => HSD_MAINNET_BRONTIDE_SEEDS,
        Network::Testnet => HSD_TESTNET_BRONTIDE_SEEDS,
        Network::Regtest | Network::Simnet => &[],
    }
}

pub fn decode_compressed_public_key(encoded: &str) -> Result<[u8; 33], P2pError> {
    if encoded.len() != 66 {
        return Err(P2pError::Configuration(format!(
            "compressed public key has {} hex characters; expected 66",
            encoded.len()
        )));
    }
    let mut key = [0u8; 33];
    for (index, output) in key.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&encoded[offset..offset + 2], 16).map_err(|error| {
            P2pError::Configuration(format!("invalid compressed public key hex: {error}"))
        })?;
    }
    if !matches!(key[0], 0x02 | 0x03) {
        return Err(P2pError::Configuration(
            "compressed public key has an invalid prefix".to_owned(),
        ));
    }
    Ok(key)
}

pub fn hsd_brontide_seed_addresses(network: Network) -> Result<Vec<NetAddress>, P2pError> {
    hsd_brontide_seed_table(network)
        .iter()
        .map(|seed| {
            let ip = seed.host.parse::<IpAddr>().map_err(|error| {
                P2pError::Configuration(format!(
                    "invalid pinned HSD seed IP {}: {error}",
                    seed.host
                ))
            })?;
            let mut address = NetAddress::from_socket_addr(
                SocketAddr::new(ip, network.params().brontide_port),
                0,
                SERVICE_NETWORK,
            );
            address.key = decode_compressed_public_key(seed.public_key_hex)?;
            Ok(address)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_seed_tables_are_key_bearing_and_network_scoped() {
        assert_eq!(hsd_brontide_seed_table(Network::Mainnet).len(), 10);
        assert_eq!(hsd_brontide_seed_table(Network::Testnet).len(), 4);
        assert!(hsd_brontide_seed_table(Network::Regtest).is_empty());
        let seeds = hsd_brontide_seed_addresses(Network::Mainnet).expect("mainnet seeds");
        assert!(seeds.iter().all(|seed| matches!(seed.key[0], 0x02 | 0x03)));
    }
}
