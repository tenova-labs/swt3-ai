require "openssl"

module Swt3Ai
  module Signing
    # Sign a payload with HMAC-SHA256 for non-repudiation.
    #
    # If agent_id is provided, the message is "{fingerprint}:{agent_id}".
    # Otherwise, the message is just the fingerprint.
    # Returns a 64-character lowercase hex string.
    def self.sign_payload(signing_key, anchor_fingerprint, agent_id = nil)
      message = agent_id ? "#{anchor_fingerprint}:#{agent_id}" : anchor_fingerprint
      OpenSSL::HMAC.hexdigest("SHA256", signing_key, message)
    end
  end
end
