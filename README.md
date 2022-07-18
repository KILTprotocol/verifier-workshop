## Usage

Expects the credential to be read via stdin.
Either create your own presentation or use one of the two prepared ones:

```
cargo run < presentation-1.json
# cargo run < presentation-2.json
```

## Credential structure

A credential is an json object that look like this:
```json
{
    "claim": {
        "cTypeHash": "0x3291bb126e33b4862d421bfaa1d2f272e6cdfc4f96658988fbcffea8914bd9ac",
        "contents": {
            "Email": "tino@kilt.io"
        },
        "owner": "did:kilt:4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH"
    },
    "claimHashes": [
        "0x2192b61d3f3109920e8991952a3fad9b7158e4fcac96dcfb873d5e975ba057e4",
        "0x2ef47f014e20bb908595f71ff022a53d7d84b5370dfed18479d4eee0575483c9"
    ],
    "claimNonceMap": {
        "0x0e0d56f241309d5a06ddf94e01d97d946f9b004d4f847302f050e5accf429c83": "5f25a0d1-b68f-4e06-a003-26c391935540",
        "0x758777288cc6705af9fb1b65f00647da18f696458ccbc59c4de0d50873e2b19d": "c57e9c72-fa8a-4e4f-b60f-a20234317bda"
    },
    "rootHash": "0xf69ce26ca50b5d5f38cd32a99d031cd52fff42f17b9afb32895ffba260fb616a",
    "claimerSignature": {
        "keyId": "did:kilt:4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH#0x78579576fa15684e5d868c9e123d62d471f1a95d8f9fc8032179d3735069784d",
        "signature": "0x6243baecdfa9c752161f501597bafbb0242db1174bb8362c18d6e51bdbbdf041997fb736a07dcf56cb023687c4cc044ffba39e0dfcf01b7caa00f0f8b4fbbd81"
    }
}
```

It contains:

* `claim`: The claim that is being presented.
    * includes the `ctype` (registered json schema)
    * includes the owner of the credential
* `claimHashes` + `claimNonceMap`: The hashes and nonces of the claim
* `rootHash`: The root hash of the claim (hash of the claimHashes)
* `claimerSignature`: The signature of the claimer over the root hash

## 1) Verify the claim hashes

First we need to recalculate the root hash of the claim. This is to make sure that the claimer doesn't show claims that were not attested by the issuer.

Therefore we have to normalize the claim contents and calculate the blake2b hash of the normalized claim contents.

The normalization process is based on json-ld:
* take the owner of the claim and convert it to a json formatted string that looks like this
`{"@id":"did:kilt:4siDmerNEBREZJsFoLM95x6cxEho73bCWKEDAXrKdou4a3mH"}`
* iterate over all top level elements of the claim and also convert them to json formatted strings by prefixing the key with the ctype of the claim for example:
`{"kilt:ctype:0x3291...#Email":"tino@kilt.io"}`

Now we can hash all those json formatted strings by applying blake2b to it with 256 bit (32 byte) output. 
The hashes are converted to strings by hex encoding them and prefixing them with `0x`. 
Those are the unsalted claim hashes. 
For each of the unsalted claim hashes we should find the corresponding nonce by looking up the nonce in the claimNonceMap.
The final claim hashes are the blake2b hashes of the nonce concatenated with the hex encoded unsalted hash.
Those claim hashes must all appear in the `claimHashes`.

## 2) Calculate the root hash

The root hash is calculated by feeding the raw bytes of the claimHashes to the blake2b hash function with 256 bit output in the same order as given in the credential. 
The calculated root hash is converted to a string by hex encoding it and prefixing it with `0x`.
If the root hash is equal to the `rootHash` field in the credential we can be sure that the integrity of the credential is intact.

## 3) Verify the claimer signature

To know if the claimer is the true owner of the claim and is also ok with the claim contents we need to verify the claimer signature. 
It is a sr25519 signature over the raw bytes of the root hash of the credential.
To verify the signature we first need to retrieve the public key of the claimer.
Therefore we lookup the DID document of the claimer from the KILT blockchain and pick the authentication public key from there.
This public key can then be used to verify the provided signature.

## 4) Check the attestation of the credential on-chain

To prove that the claim was attested by a valid issuer we need to lookup the attestation of the claim on-chain.
This is done by looking up the attestation details of the claim in the KILT blockchain given the root hash.
If we find an attestation we have to verify that it was issued by an attester that we trust and that the attestation has not been revoked.