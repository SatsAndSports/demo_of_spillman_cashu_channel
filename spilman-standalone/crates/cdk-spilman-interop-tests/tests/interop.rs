#![allow(unexpected_cfgs)]
//! Upstream `cdk` interoperability coverage for `cdk-spilman`.

use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bip39::Mnemonic;
use cdk::dhke::{blind_message, construct_proofs};
use cdk::mint::{MintBuilder, MintMeltLimits};
use cdk::nuts::nut10::Secret as Nut10Secret;
use cdk::nuts::{
    BatchCheckMintQuoteRequest, BatchMintRequest, BlindedMessage, CheckStateRequest,
    CheckStateResponse, CurrencyUnit, Id, KeySet, KeysetResponse, Keys, MeltQuoteBolt11Response,
    MeltRequest, MintInfo, MintQuoteBolt11Request, MintQuoteBolt11Response, MintQuoteState,
    MintRequest, MintResponse, PaymentMethod, PreMintSecrets, Proof, RestoreRequest,
    RestoreResponse, SpendingConditions, SwapRequest, SwapResponse,
};
use cdk::secret::Secret;
use cdk::util::unix_time;
use cdk::wallet::{MintConnector, ReceiveOptions, SendOptions, WalletBuilder};
use cdk::{Amount, Mint};
use cdk_common::amount::SplitTarget;
use cdk_common::common::{FeeReserve, QuoteTTL};
use cdk_common::nut00::KnownMethod;
use cdk_common::{MeltQuoteRequest, MeltQuoteResponse, MintQuoteRequest};
use cdk_fake_wallet::FakeWallet;
use cdk_spilman::{
    complete_funding_swap, compute_channel_from_token, create_funding_swap, ChannelParameters,
    CommitmentOutputs,
    DeterministicOutputsForOneContext, KeysetInfo,
};
use cdk_sqlite::wallet::memory;
use rand::random;

const DEFAULT_TEST_FEE_PPK: u64 = 400;

struct TestMintHelper {
    mint: Mint,
    active_sat_keyset_id: Id,
    public_keys_of_the_active_sat_keyset: Keys,
    unit: CurrencyUnit,
    input_fee_ppk: u64,
    final_expiry: Option<u64>,
}

impl TestMintHelper {
    async fn new() -> anyhow::Result<Self> {
        let mint = create_test_mint().await?;

        let active_sat_keyset_id = mint
            .get_active_keysets()
            .get(&CurrencyUnit::Sat)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing active SAT keyset"))?;

        let keysets_response = mint.keysets();
        let keyset_info = keysets_response
            .keysets
            .iter()
            .find(|k| k.id == active_sat_keyset_id)
            .ok_or_else(|| anyhow::anyhow!("missing keyset info"))?;
        let input_fee_ppk = keyset_info.input_fee_ppk;
        let final_expiry = keyset_info.final_expiry;
        let unit = keyset_info.unit.clone();

        let lookup = mint.keyset_pubkeys(&active_sat_keyset_id)?;
        let active_sat_keyset = lookup
            .keysets
            .first()
            .ok_or_else(|| anyhow::anyhow!("missing active SAT keyset pubkeys"))?;
        let public_keys_of_the_active_sat_keyset = active_sat_keyset.keys.clone();

        Ok(Self {
            mint,
            active_sat_keyset_id,
            public_keys_of_the_active_sat_keyset,
            unit,
            input_fee_ppk,
            final_expiry,
        })
    }

    fn mint(&self) -> &Mint {
        &self.mint
    }

    async fn mint_proofs(&self, amount: Amount) -> anyhow::Result<Vec<Proof>> {
        mint_test_proofs(&self.mint, amount).await
    }

    fn split_amount(&self, amount: Amount) -> anyhow::Result<Vec<Amount>> {
        let mut available_amounts_sorted: Vec<u64> = self
            .public_keys_of_the_active_sat_keyset
            .iter()
            .map(|(amt, _)| amt.to_u64())
            .collect();
        available_amounts_sorted.sort_by(|a, b| b.cmp(a));

        let mut result = Vec::new();
        let mut remaining = amount.to_u64();

        for amt in available_amounts_sorted {
            if remaining >= amt {
                result.push(Amount::from(amt));
                remaining -= amt;
            }
        }

        if remaining != 0 {
            return Err(anyhow::anyhow!("failed to split amount exactly"));
        }

        Ok(result)
    }

    fn create_blinded_message(
        &self,
        amount: Amount,
        spending_conditions: &SpendingConditions,
    ) -> anyhow::Result<(BlindedMessage, cdk::nuts::SecretKey, Secret)> {
        let nut10_secret: Nut10Secret = spending_conditions.clone().into();
        let secret: Secret = nut10_secret.try_into()?;
        let (blinded_point, blinding_factor) = blind_message(&secret.to_bytes(), None)?;
        let blinded_msg = BlindedMessage::new(amount, self.active_sat_keyset_id, blinded_point);

        Ok((blinded_msg, blinding_factor, secret))
    }
}

async fn create_test_mint() -> anyhow::Result<Mint> {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await?);
    let mut mint_builder = MintBuilder::new(db.clone());

    let fee_reserve = FeeReserve {
        min_fee_reserve: 1.into(),
        percent_fee_reserve: 1.0,
    };

    let ln_fake_backend = FakeWallet::new(
        fee_reserve,
        HashMap::default(),
        HashSet::default(),
        2,
        CurrencyUnit::Sat,
    );

    mint_builder
        .add_payment_processor(
            CurrencyUnit::Sat,
            PaymentMethod::Known(KnownMethod::Bolt11),
            MintMeltLimits::new(1, 10_000),
            Arc::new(ln_fake_backend),
        )
        .await?;

    mint_builder.set_unit_fee(&CurrencyUnit::Sat, DEFAULT_TEST_FEE_PPK)?;

    let mnemonic = Mnemonic::generate(12)?;

    mint_builder = mint_builder
        .with_name("test mint".to_string())
        .with_description("test mint for upstream cdk interop".to_string())
        .with_urls(vec!["https://test-mint".to_string()]);

    let mint = mint_builder
        .build_with_seed(db.clone(), &mnemonic.to_seed_normalized(""))
        .await?;

    mint.set_quote_ttl(QuoteTTL::new(10_000, 10_000)).await?;
    mint.start().await?;

    Ok(mint)
}

async fn mint_test_proofs(mint: &Mint, amount: Amount) -> anyhow::Result<Vec<Proof>> {
    let mint_quote: MintQuoteBolt11Response<_> = mint
        .get_mint_quote(
            MintQuoteBolt11Request {
                amount,
                unit: CurrencyUnit::Sat,
                description: None,
                pubkey: None,
            }
            .into(),
        )
        .await?
        .into();

    loop {
        let check: MintQuoteBolt11Response<_> = mint
            .check_mint_quotes(&[cdk_common::QuoteId::from_str(&mint_quote.quote)?])
            .await?
            .first()
            .ok_or_else(|| anyhow::anyhow!("missing mint quote status"))?
            .clone()
            .into();

        if check.state == MintQuoteState::Paid {
            break;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let keyset_id = *mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .ok_or_else(|| anyhow::anyhow!("missing active SAT keyset"))?;

    let keys = mint
        .keyset_pubkeys(&keyset_id)?
        .keysets
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing keyset pubkeys"))?
        .keys
        .clone();

    let fees: (u64, Vec<u64>) = (0, keys.iter().map(|a| a.0.to_u64()).collect());
    let premint_secrets = PreMintSecrets::random(keyset_id, amount, &SplitTarget::None, &fees.into())?;

    let request = cdk::nuts::MintRequest {
        quote: mint_quote.quote,
        outputs: premint_secrets.blinded_messages(),
        signature: None,
    };

    let mint_res = mint
        .process_mint_request(cdk::mint::MintInput::Single(request.try_into()?))
        .await?;

    Ok(construct_proofs(
        mint_res.signatures,
        premint_secrets.rs(),
        premint_secrets.secrets(),
        &keys,
    )?)
}

async fn create_test_blinded_messages(
    mint: &Mint,
    amount: Amount,
) -> anyhow::Result<(Vec<BlindedMessage>, PreMintSecrets)> {
    let keyset_id = *mint
        .get_active_keysets()
        .get(&CurrencyUnit::Sat)
        .ok_or_else(|| anyhow::anyhow!("missing active SAT keyset"))?;
    let split_target = SplitTarget::default();
    let fee_and_amounts = (0, (0..32).map(|x| 2u64.pow(x)).collect::<Vec<_>>()).into();

    let pre_mint = PreMintSecrets::random(keyset_id, amount, &split_target, &fee_and_amounts)?;
    Ok((pre_mint.blinded_messages().to_vec(), pre_mint))
}

fn unzip3<A, B, C>(vec: Vec<(A, B, C)>) -> (Vec<A>, Vec<B>, Vec<C>) {
    let mut vec_a = Vec::new();
    let mut vec_b = Vec::new();
    let mut vec_c = Vec::new();

    for (a, b, c) in vec {
        vec_a.push(a);
        vec_b.push(b);
        vec_c.push(c);
    }

    (vec_a, vec_b, vec_c)
}

#[derive(Clone)]
struct DirectMintConnection {
    mint: Mint,
}

impl DirectMintConnection {
    fn new(mint: Mint) -> Self {
        Self { mint }
    }
}

impl Debug for DirectMintConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DirectMintConnection")
    }
}

#[async_trait]
impl MintConnector for DirectMintConnection {
    #[cfg(all(feature = "bip353", not(target_arch = "wasm32")))]
    async fn resolve_dns_txt(&self, _domain: &str) -> Result<Vec<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn fetch_lnurl_pay_request(
        &self,
        _url: &str,
    ) -> Result<cdk::wallet::LnurlPayResponse, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn fetch_lnurl_invoice(
        &self,
        _url: &str,
    ) -> Result<cdk::wallet::LnurlPayInvoiceResponse, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, cdk::Error> {
        Ok(self.mint.pubkeys().keysets)
    }

    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, cdk::Error> {
        self.mint.keyset(&keyset_id).ok_or(cdk::Error::UnknownKeySet)
    }

    async fn get_mint_keysets(&self) -> Result<KeysetResponse, cdk::Error> {
        Ok(self.mint.keysets())
    }

    async fn post_mint_quote(
        &self,
        _request: MintQuoteRequest,
    ) -> Result<cdk_common::MintQuoteResponse<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_batch_check_mint_quote_status(
        &self,
        _method: &PaymentMethod,
        _request: BatchCheckMintQuoteRequest<String>,
    ) -> Result<Vec<MintQuoteBolt11Response<String>>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_batch_mint(
        &self,
        _method: &PaymentMethod,
        _request: BatchMintRequest<String>,
    ) -> Result<MintResponse, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn get_mint_quote_status(
        &self,
        _method: PaymentMethod,
        _quote_id: &str,
    ) -> Result<cdk_common::MintQuoteResponse<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_mint(
        &self,
        _method: &PaymentMethod,
        _request: MintRequest<String>,
    ) -> Result<MintResponse, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_melt_quote(
        &self,
        _request: MeltQuoteRequest,
    ) -> Result<MeltQuoteResponse<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn get_melt_quote_status(
        &self,
        _method: PaymentMethod,
        _quote_id: &str,
    ) -> Result<MeltQuoteResponse<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_melt(
        &self,
        _method: &PaymentMethod,
        _request: MeltRequest<String>,
    ) -> Result<MeltQuoteBolt11Response<String>, cdk::Error> {
        Err(cdk::Error::UnsupportedPaymentMethod)
    }

    async fn post_swap(&self, request: SwapRequest) -> Result<SwapResponse, cdk::Error> {
        self.mint.process_swap_request(request).await
    }

    async fn get_mint_info(&self) -> Result<MintInfo, cdk::Error> {
        Ok(self.mint.mint_info().await?.clone().time(unix_time()))
    }

    async fn post_check_state(
        &self,
        request: CheckStateRequest,
    ) -> Result<CheckStateResponse, cdk::Error> {
        self.mint.check_state(&request).await
    }

    async fn post_restore(&self, request: RestoreRequest) -> Result<RestoreResponse, cdk::Error> {
        self.mint.restore(request).await
    }

    async fn get_auth_wallet(&self) -> Option<cdk::wallet::AuthWallet> {
        None
    }

    async fn set_auth_wallet(&self, _wallet: Option<cdk::wallet::AuthWallet>) {}
}

#[tokio::test]
async fn test_spilman_2of2_spending_with_blinded_keys() -> anyhow::Result<()> {
    let test_mint = TestMintHelper::new().await?;
    let mint = test_mint.mint();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();
    let input_fee_ppk = test_mint.input_fee_ppk;

    let keyset_info = KeysetInfo::new(
        keyset_id,
        test_mint.unit.clone(),
        keys.clone(),
        input_fee_ppk,
        test_mint.final_expiry,
    );

    let capacity = 10u64;
    let future_expiry = unix_time() + 3600;
    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(capacity, &keyset_info, 64)?;

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        future_expiry,
        unix_time(),
        keyset_info.clone(),
        64,
        &alice_secret,
    )?;

    let funding_amount = params.get_total_funding_token_amount()?;
    let _funding_outputs =
        DeterministicOutputsForOneContext::new("funding".to_string(), funding_amount, params.clone())?;
    let input_proofs = test_mint.mint_proofs(Amount::from(funding_amount)).await?;

    let num_input_proofs = input_proofs.len() as u64;
    let actual_fee = (input_fee_ppk * num_input_proofs).div_ceil(1000);
    let available_for_outputs = funding_amount - actual_fee;

    let adjusted_funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        available_for_outputs,
        params.clone(),
    )?;

    let adjusted_blinded_messages = adjusted_funding_outputs.get_blinded_messages(None)?;
    let swap_request = SwapRequest::new(input_proofs.clone(), adjusted_blinded_messages);
    let swap_response = mint.process_swap_request(swap_request).await?;

    let secrets_with_blinding = adjusted_funding_outputs.get_secrets_with_blinding()?;
    let blinding_factors = secrets_with_blinding
        .iter()
        .map(|s| s.blinding_factor.clone())
        .collect();
    let secrets = secrets_with_blinding.iter().map(|s| s.secret.clone()).collect();
    let p2pk_proofs = construct_proofs(swap_response.signatures, blinding_factors, secrets, &keys)?;

    let spend_fee = (input_fee_ppk * p2pk_proofs.len() as u64).div_ceil(1000);
    let final_output_amount = available_for_outputs - spend_fee;
    let (new_outputs, _) = create_test_blinded_messages(mint, Amount::from(final_output_amount)).await?;

    let mut swap_request_2of2 = SwapRequest::new(p2pk_proofs, new_outputs);
    let alice_blinded_secret = params.get_sender_blinded_secret_key_for_stage1(&alice_secret)?;
    let charlie_blinded_secret = params.get_receiver_blinded_secret_key_for_stage1(&charlie_secret)?;
    swap_request_2of2.sign_sig_all(alice_blinded_secret)?;
    swap_request_2of2.sign_sig_all(charlie_blinded_secret)?;

    mint.process_swap_request(swap_request_2of2).await?;
    Ok(())
}

#[tokio::test]
async fn test_swap_to_funding() -> anyhow::Result<()> {
    use cdk::nuts::nut00::token::Token;

    let test_mint = TestMintHelper::new().await?;
    let mint = test_mint.mint();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();
    let input_fee_ppk = test_mint.input_fee_ppk;

    let keyset_info_json = serde_json::json!({
        "keysetId": keyset_id.to_string(),
        "unit": "sat",
        "inputFeePpk": input_fee_ppk,
        "keys": keys.iter().map(|(amt, pk)| {
            (u64::from(*amt).to_string(), pk.to_hex())
        }).collect::<std::collections::HashMap<_, _>>()
    })
    .to_string();

    let input_amount = Amount::from(100u64);
    let input_proofs = test_mint.mint_proofs(input_amount).await?;
    let token = Token::new(
        "http://localhost:3338".parse().unwrap(),
        input_proofs.clone(),
        None,
        CurrencyUnit::Sat,
    );
    let token_string = token.to_string();

    let expiry_timestamp = unix_time() + 3600;
    let max_amount = 64u64;
    let channel_secret_hex = cdk_spilman::compute_channel_secret_from_hex(
        &alice_secret.to_secret_hex(),
        &receiver_pubkey.to_hex(),
    )
    .map_err(anyhow::Error::msg)?;

    let compute_result = compute_channel_from_token(
        &token_string,
        &receiver_pubkey.to_hex(),
        &alice_secret.public_key().to_hex(),
        &channel_secret_hex,
        expiry_timestamp,
        &keyset_info_json,
        max_amount,
    )
    .map_err(anyhow::Error::msg)?;
    let compute_json: serde_json::Value = serde_json::from_str(&compute_result)?;
    let params_json = compute_json["params_json"].as_str().unwrap();
    let proofs_json = compute_json["proofs_json"].as_str().unwrap();

    let swap_result = create_funding_swap(
        params_json,
        &channel_secret_hex,
        &keyset_info_json,
        proofs_json,
    )
    .map_err(anyhow::Error::msg)?;
    let swap_json: serde_json::Value = serde_json::from_str(&swap_result)?;
    let swap_request_json = swap_json["swap_request_json"].as_str().unwrap();
    let funding_secrets_json = swap_json["funding_secrets_json"].as_str().unwrap();
    let funding_count = swap_json["funding_count"].as_u64().unwrap() as usize;

    let swap_request: SwapRequest = serde_json::from_str(swap_request_json)?;
    let swap_response = mint.process_swap_request(swap_request).await?;
    let swap_response_json = serde_json::to_string(&swap_response)?;

    let complete_result = complete_funding_swap(
        &swap_response_json,
        funding_secrets_json,
        &keyset_info_json,
    )
    .map_err(anyhow::Error::msg)?;
    let complete_json: serde_json::Value = serde_json::from_str(&complete_result)?;
    let funding_proofs_json = complete_json["funding_proofs_json"].as_str().unwrap();
    let funding_proofs: Vec<Proof> = serde_json::from_str(funding_proofs_json)?;

    assert_eq!(funding_proofs.len(), funding_count);
    assert!(!funding_proofs.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_spilman_refund_spending_with_blinded_key() -> anyhow::Result<()> {
    let test_mint = TestMintHelper::new().await?;
    let mint = test_mint.mint();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();
    let input_fee_ppk = test_mint.input_fee_ppk;

    let keyset_info = KeysetInfo::new(
        keyset_id,
        test_mint.unit.clone(),
        keys.clone(),
        input_fee_ppk,
        test_mint.final_expiry,
    );

    let capacity = 10u64;
    let future_expiry = unix_time() + 3600;
    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(capacity, &keyset_info, 64)?;

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        future_expiry,
        unix_time(),
        keyset_info,
        64,
        &alice_secret,
    )?;

    let blinded_alice = params.get_sender_blinded_pubkey_for_stage1()?;
    let blinded_charlie = params.get_receiver_blinded_pubkey_for_stage1()?;
    let blinded_alice_refund = params.get_sender_blinded_pubkey_for_stage1_refund()?;

    assert_ne!(blinded_alice.to_hex(), blinded_alice_refund.to_hex());

    let past_expiry = unix_time() - 3600;
    let spending_conditions = SpendingConditions::new_p2pk(
        blinded_alice,
        Some(cdk_common::nuts::Conditions {
            locktime: Some(past_expiry),
            pubkeys: Some(vec![blinded_charlie]),
            refund_keys: Some(vec![blinded_alice_refund]),
            num_sigs: Some(2),
            sig_flag: cdk_common::nuts::SigFlag::SigAll,
            num_sigs_refund: Some(1),
        }),
    );

    let input_proofs = test_mint.mint_proofs(Amount::from(capacity)).await?;
    let num_input_proofs = input_proofs.len() as u64;
    let actual_fee = (input_fee_ppk * num_input_proofs).div_ceil(1000);
    let available_for_outputs = capacity - actual_fee;

    let output_amount = Amount::from(available_for_outputs);
    let split_amounts = test_mint.split_amount(output_amount)?;
    let created = split_amounts
        .iter()
        .map(|&amt| test_mint.create_blinded_message(amt, &spending_conditions))
        .collect::<Result<Vec<_>, _>>()?;
    let (p2pk_outputs, blinding_factors, secrets) = unzip3(created);

    let swap_request = SwapRequest::new(input_proofs, p2pk_outputs);
    let swap_response = mint.process_swap_request(swap_request).await?;
    let p2pk_proofs = construct_proofs(swap_response.signatures, blinding_factors, secrets, &keys)?;

    let refund_fee = (input_fee_ppk * p2pk_proofs.len() as u64).div_ceil(1000);
    let refund_output_amount = available_for_outputs - refund_fee;
    let (new_outputs, _) = create_test_blinded_messages(mint, Amount::from(refund_output_amount)).await?;

    let mut swap_request_refund = SwapRequest::new(p2pk_proofs, new_outputs);
    let alice_refund_blinded_secret =
        params.get_sender_blinded_secret_key_for_stage1_refund(&alice_secret)?;
    swap_request_refund.sign_sig_all(alice_refund_blinded_secret)?;

    mint.process_swap_request(swap_request_refund).await?;
    Ok(())
}

#[test]
fn test_stage2_blinded_pubkeys_differ_from_stage1_and_raw() -> anyhow::Result<()> {
    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let mut keys = std::collections::BTreeMap::new();
    keys.insert(
        cdk_common::Amount::from(1u64),
        cdk_common::nuts::PublicKey::from_hex(
            "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104",
        )?,
    );
    let keyset_keys = cdk_common::nuts::Keys::new(keys);
    let keyset_id = cdk_common::nuts::Id::v1_from_keys(&keyset_keys);
    let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keyset_keys, 0, None);

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        100,
        100,
        unix_time() + 3600,
        unix_time(),
        keyset_info,
        64,
        &alice_secret,
    )?;

    let alice_raw = sender_pubkey.to_hex();
    let charlie_raw = receiver_pubkey.to_hex();
    let alice_stage1 = params.get_sender_blinded_pubkey_for_stage1()?.to_hex();
    let charlie_stage1 = params.get_receiver_blinded_pubkey_for_stage1()?.to_hex();
    let alice_stage2_64_0 = params.get_sender_blinded_pubkey_for_stage2_output(64, 0)?.to_hex();
    let charlie_stage2_64_0 = params.get_receiver_blinded_pubkey_for_stage2_output(64, 0)?.to_hex();
    let alice_refund = params.get_sender_blinded_pubkey_for_stage1_refund()?.to_hex();

    assert_ne!(alice_stage2_64_0, alice_raw);
    assert_ne!(charlie_stage2_64_0, charlie_raw);
    assert_ne!(alice_stage2_64_0, alice_stage1);
    assert_ne!(charlie_stage2_64_0, charlie_stage1);
    assert_ne!(alice_stage2_64_0, charlie_stage2_64_0);
    assert_ne!(alice_stage2_64_0, alice_refund);

    let alice_stage2_64_1 = params.get_sender_blinded_pubkey_for_stage2_output(64, 1)?.to_hex();
    let alice_stage2_32_0 = params.get_sender_blinded_pubkey_for_stage2_output(32, 0)?.to_hex();

    assert_ne!(alice_stage2_64_0, alice_stage2_64_1);
    assert_ne!(alice_stage2_64_0, alice_stage2_32_0);
    Ok(())
}

#[test]
fn test_sender_can_derive_secret_keys_for_stage2_outputs() -> anyhow::Result<()> {
    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let mut keys = std::collections::BTreeMap::new();
    for amount in [1u64, 2, 4, 8, 16, 32, 64] {
        let mint_secret = cdk::nuts::SecretKey::generate();
        keys.insert(cdk_common::Amount::from(amount), mint_secret.public_key());
    }

    let keyset_keys = cdk_common::nuts::Keys::new(keys);
    let keyset_id = cdk_common::nuts::Id::v1_from_keys(&keyset_keys);
    let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keyset_keys, 0, None);

    let capacity = 100u64;
    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        capacity,
        unix_time() + 3600,
        unix_time(),
        keyset_info,
        64,
        &alice_secret,
    )?;

    let sender_outputs =
        DeterministicOutputsForOneContext::new("sender".to_string(), capacity, params.clone())?;
    let secrets_with_blinding = sender_outputs.get_secrets_with_blinding()?;

    let mut index_by_amount: HashMap<u64, usize> = HashMap::new();
    for output in &secrets_with_blinding {
        let amount = output.amount;
        let index = *index_by_amount.get(&amount).unwrap_or(&0);
        index_by_amount.insert(amount, index + 1);

        let blinded_secret =
            params.get_sender_blinded_secret_key_for_stage2_output(&alice_secret, amount, index)?;
        let derived_pubkey = blinded_secret.public_key();

        let secret_str = output.secret.to_string();
        let secret_json: serde_json::Value = serde_json::from_str(&secret_str)?;
        assert!(secret_json.is_array());
        assert_eq!(secret_json[0].as_str(), Some("P2PK"));

        let locked_pubkey_hex = secret_json[1]["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("secret missing locked pubkey"))?;
        assert_eq!(derived_pubkey.to_hex(), locked_pubkey_hex);
    }

    let key_64_0 = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, 64, 0)?
        .public_key()
        .to_hex();
    let key_32_0 = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, 32, 0)?
        .public_key()
        .to_hex();
    let key_64_1 = params
        .get_sender_blinded_secret_key_for_stage2_output(&alice_secret, 64, 1)?
        .public_key()
        .to_hex();

    assert_ne!(key_64_0, key_32_0);
    assert_ne!(key_64_0, key_64_1);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage2ReceiverProofMode {
    P2pkEOnly,
    SignatureOnly,
    SignatureAndP2pkE,
}

async fn create_stage2_receiver_proof_fixture(
    proof_mode: Stage2ReceiverProofMode,
) -> anyhow::Result<(Mint, cdk::nuts::SecretKey, Vec<Proof>)> {
    let test_mint = TestMintHelper::new().await?;
    let mint = test_mint.mint().clone();

    let alice_secret = cdk::nuts::SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = cdk::nuts::SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_id = test_mint.active_sat_keyset_id;
    let keys = test_mint.public_keys_of_the_active_sat_keyset.clone();
    let input_fee_ppk = test_mint.input_fee_ppk;
    let keyset_info = KeysetInfo::new(
        keyset_id,
        test_mint.unit.clone(),
        keys.clone(),
        input_fee_ppk,
        test_mint.final_expiry,
    );

    let mint_amount = 100u64;
    let input_proofs = test_mint.mint_proofs(Amount::from(mint_amount)).await?;
    let num_input_proofs = input_proofs.len() as u64;
    let actual_fee = (input_fee_ppk * num_input_proofs).div_ceil(1000);
    let actual_funding = mint_amount - actual_fee;

    let capacity = 10u64;
    let balance = 5u64;
    let future_expiry = unix_time() + 3600;

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "http://localhost:3338".to_string(),
        CurrencyUnit::Sat,
        capacity,
        actual_funding,
        future_expiry,
        unix_time(),
        keyset_info.clone(),
        64,
        &alice_secret,
    )?;

    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        actual_funding,
        params.clone(),
    )?;
    let funding_blinded_messages = funding_outputs.get_blinded_messages(None)?;
    let swap_request = SwapRequest::new(input_proofs, funding_blinded_messages);
    let swap_response = mint.process_swap_request(swap_request).await?;

    let secrets_with_blinding = funding_outputs.get_secrets_with_blinding()?;
    let blinding_factors = secrets_with_blinding.iter().map(|s| s.blinding_factor.clone()).collect();
    let secrets = secrets_with_blinding.iter().map(|s| s.secret.clone()).collect();
    let funding_proofs = construct_proofs(swap_response.signatures, blinding_factors, secrets, &keys)?;

    let commitment_outputs = CommitmentOutputs::for_balance(balance, &params)?;
    let mut close_swap = commitment_outputs.create_swap_request(funding_proofs, None)?;

    let alice_blinded_secret = params.get_sender_blinded_secret_key_for_stage1(&alice_secret)?;
    let charlie_blinded_secret = params.get_receiver_blinded_secret_key_for_stage1(&charlie_secret)?;
    close_swap.sign_sig_all(alice_blinded_secret)?;
    close_swap.sign_sig_all(charlie_blinded_secret)?;

    let close_response = mint.process_swap_request(close_swap).await?;
    let proofs_with_meta = commitment_outputs.unblind_all(close_response.signatures, &keys)?;

    let receiver_proofs = proofs_with_meta
        .into_iter()
        .filter(|p| p.is_receiver)
        .map(|proof_meta| {
            let mut proof = proof_meta.proof;
            match proof_mode {
                Stage2ReceiverProofMode::P2pkEOnly => {}
                Stage2ReceiverProofMode::SignatureOnly => {
                    let signing_key = params
                        .get_receiver_blinded_secret_key_for_stage2_output(
                            &charlie_secret,
                            proof_meta.amount,
                            proof_meta.index,
                        )
                        .expect("stage2 signing key");
                    proof.p2pk_e = None;
                    proof.sign_p2pk(signing_key).expect("sign stage2 proof");
                }
                Stage2ReceiverProofMode::SignatureAndP2pkE => {
                    let signing_key = params
                        .get_receiver_blinded_secret_key_for_stage2_output(
                            &charlie_secret,
                            proof_meta.amount,
                            proof_meta.index,
                        )
                        .expect("stage2 signing key");
                    proof.sign_p2pk(signing_key).expect("sign stage2 proof");
                }
            }
            proof
        })
        .collect();

    Ok((mint, charlie_secret, receiver_proofs))
}

async fn assert_wallet_can_receive_and_spend_stage2_receiver_proofs(
    mint: Mint,
    receiver_proofs: Vec<Proof>,
    receive_options: ReceiveOptions,
) -> anyhow::Result<()> {
    let connector = DirectMintConnection::new(mint.clone());
    let store = Arc::new(memory::empty().await?);
    let seed = random::<[u8; 64]>();
    let wallet = WalletBuilder::new()
        .mint_url("http://localhost:3338".parse().unwrap())
        .unit(CurrencyUnit::Sat)
        .localstore(store)
        .seed(seed)
        .client(connector)
        .build()?;

    let received_amount = wallet
        .receive_proofs(receiver_proofs, receive_options, None, None)
        .await?;
    let prepared = wallet
        .prepare_send(Amount::from(1u64), SendOptions::default())
        .await?;
    let _token = prepared.confirm(None).await?;
    assert!(received_amount > Amount::ZERO);
    Ok(())
}

#[tokio::test]
async fn test_stage2_receiver_can_sign_and_spend_with_wallet() -> anyhow::Result<()> {
    let (mint, charlie_secret, receiver_proofs) =
        create_stage2_receiver_proof_fixture(Stage2ReceiverProofMode::P2pkEOnly).await?;
    assert_wallet_can_receive_and_spend_stage2_receiver_proofs(
        mint,
        receiver_proofs,
        ReceiveOptions {
            p2pk_signing_keys: vec![charlie_secret],
            ..Default::default()
        },
    )
    .await
}

#[tokio::test]
async fn test_stage2_receiver_signature_only_can_spend_with_wallet() -> anyhow::Result<()> {
    let (mint, _charlie_secret, receiver_proofs) =
        create_stage2_receiver_proof_fixture(Stage2ReceiverProofMode::SignatureOnly).await?;
    assert_wallet_can_receive_and_spend_stage2_receiver_proofs(
        mint,
        receiver_proofs,
        ReceiveOptions::default(),
    )
    .await
}

#[tokio::test]
async fn test_stage2_receiver_signature_and_p2pk_e_can_spend_with_wallet() -> anyhow::Result<()> {
    let (mint, _charlie_secret, receiver_proofs) =
        create_stage2_receiver_proof_fixture(Stage2ReceiverProofMode::SignatureAndP2pkE).await?;
    assert_wallet_can_receive_and_spend_stage2_receiver_proofs(
        mint,
        receiver_proofs,
        ReceiveOptions::default(),
    )
    .await
}
