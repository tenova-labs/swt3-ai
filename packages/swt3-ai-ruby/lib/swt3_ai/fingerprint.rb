require "openssl"

module Swt3Ai
  module Fingerprint
    # Mint an SWT3 fingerprint from the canonical formula.
    #
    # Returns the first 12 hex characters of:
    #   SHA-256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}")
    #
    # This formula is locked and must produce identical output across
    # all SWT3 SDK implementations (Python, TypeScript, Rust, C#, Ruby).
    def self.mint_fingerprint(tenant_id, procedure_id, factor_a, factor_b, factor_c, timestamp_ms)
      input = "WITNESS:#{tenant_id}:#{procedure_id}:#{num_str(factor_a)}:#{num_str(factor_b)}:#{num_str(factor_c)}:#{timestamp_ms}"
      sha256_hex(input, 12)
    end

    # Compute a truncated SHA-256 hash. Default length is 16 hex characters.
    def self.sha256_truncated(data, length = 16)
      sha256_hex(data, length)
    end

    # Compute SHA-256 and return the first N hex characters.
    def self.sha256_hex(data, length = 64)
      digest = OpenSSL::Digest::SHA256.hexdigest(data.to_s)
      digest[0, [length, 64].min]
    end

    # Get the current timestamp in milliseconds and epoch seconds.
    def self.timestamp_ms
      ms = (Time.now.to_f * 1000).to_i
      epoch = ms / 1000
      [ms, epoch]
    end

    # Format a numeric factor as a string matching the canonical formula.
    # Integer-valued floats are formatted without decimals: 1.0 -> "1"
    def self.num_str(v)
      v == v.to_i ? v.to_i.to_s : v.to_s
    end

    private_class_method :num_str
  end
end
