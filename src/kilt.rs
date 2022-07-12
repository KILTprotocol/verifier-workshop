use subxt::{ClientBuilder, Config, DefaultConfig, PolkadotExtrinsicParams};

// Generate the KILT runtime API
#[subxt::subxt(runtime_metadata_path = "metadata.scale")]
pub mod kilt {}

// Re-export all the auto generated code
pub use kilt::*;

// This is the runtime config for KILT.
// It only differs in the Index type from the default
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KiltConfig;
impl Config for KiltConfig {
    type Index = u64;
    type BlockNumber = <DefaultConfig as Config>::BlockNumber;
    type Hash = <DefaultConfig as Config>::Hash;
    type Hashing = <DefaultConfig as Config>::Hashing;
    type AccountId = <DefaultConfig as Config>::AccountId;
    type Address = <DefaultConfig as Config>::Address;
    type Header = <DefaultConfig as Config>::Header;
    type Signature = <DefaultConfig as Config>::Signature;
    type Extrinsic = <DefaultConfig as Config>::Extrinsic;
}

pub type KiltRuntimeApi = kilt::RuntimeApi<KiltConfig, PolkadotExtrinsicParams<KiltConfig>>;

/// Connect to a websocket endpoint using the KiltConfig
pub async fn connect<U: Into<String>>(url: U) -> Result<KiltRuntimeApi, subxt::BasicError> {
    Ok(ClientBuilder::new()
        .set_url(url)
        .build()
        .await?
        .to_runtime_api::<KiltRuntimeApi>())
}

#[cfg(test)]
mod tests {
    use subxt::sp_core::crypto::{Ss58AddressFormat, Ss58Codec};

    use super::*;
    use kilt::runtime_types::frame_support::storage::bounded_vec::BoundedVec;
    use kilt::runtime_types::pallet_web3_names::web3_name::AsciiWeb3Name;

    fn w3n<S: AsRef<str>>(s: S) -> AsciiWeb3Name {
        AsciiWeb3Name(BoundedVec(String::from(s.as_ref()).as_bytes().to_vec()))
    }

    #[tokio::test]
    async fn lookup_w3n() {
        let api = connect("wss://spiritnet.kilt.io:443").await.unwrap();

        let resp = api
            .storage()
            .web3_names()
            .owner(&w3n("johndoe"), None)
            .await
            // no network error
            .expect("Should connect with runtime API")
            // unwrap the owner option -> proof that it exists
            .expect("Should match owner with johndoe");

        let owner = format!(
            "did:kilt:{}",
            resp.owner
                .to_ss58check_with_version(Ss58AddressFormat::custom(38))
        );
        let expected_did = "did:kilt:4q8mf6k3k8aqiMaSVGy4WK7oqeu4kqVsNwchXb93UjVsEwHi";
        assert_eq!(expected_did, owner);
    }

    #[tokio::test]
    async fn serialize_stuff() {
        let call = kilt::web3_names::calls::Claim {
            name: BoundedVec(String::from("johndoe").as_bytes().to_vec()),
        };
        println!("Call: {:#?}", call);
    }
}
