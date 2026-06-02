module Swt3Ai
  # A witness payload ready for transmission to the witness endpoint.
  WitnessPayload = Struct.new(
    :procedure_id, :factor_a, :factor_b, :factor_c,
    :clearing_level, :anchor_fingerprint, :anchor_epoch,
    :fingerprint_timestamp_ms, :ai_model_id, :ai_prompt_hash,
    :ai_response_hash, :ai_latency_ms, :ai_input_tokens,
    :ai_output_tokens, :agent_id, :cycle_id,
    :payload_signature, :signing_algorithm, :signing_key_id, :signing_key_version,
    :policy_version_hash, :jurisdiction, :legal_basis,
    :purpose_class, :authorization_id,
    :revocation_target, :revocation_reason,
    keyword_init: true
  )

  # A receipt returned by the witness endpoint after successful anchoring.
  WitnessReceipt = Struct.new(
    :procedure_id, :verdict, :swt3_anchor, :clearing_level,
    :witnessed_at, :verification_url, :ok, :error,
    keyword_init: true
  )

  # Configuration for a Witness client.
  WitnessConfig = Struct.new(
    :endpoint, :api_key, :tenant_id, :clearing_level,
    :buffer_size, :flush_interval, :timeout, :max_retries,
    :agent_id, :signing_key, :signing_algorithm, :signing_key_id, :signing_key_version,
    :cycle_id, :policy_version,
    :jurisdiction, :legal_basis, :purpose_class,
    keyword_init: true
  )

  # Valid signing algorithms.
  SIGNING_ALGORITHMS = %w[hmac-sha256 ml-dsa-65].freeze

  # Revocation reason codes for AI-REV.1 anchors.
  REVOCATION_REASONS = {
    "unspecified" => 0,
    "model_recall" => 1,
    "policy_violation" => 2,
    "data_contamination" => 3,
    "consent_withdrawal" => 4,
    "regulatory_order" => 5,
    "error_correction" => 6,
  }.freeze
end
