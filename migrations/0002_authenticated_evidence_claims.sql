-- Derived PCR diagnostics for retained attempts.
--
-- The frozen evidence JSON remains unchanged. These claims are stored only
-- after the verifier authenticates the AWS chain, COSE signature and nonce.

ALTER TABLE attempts ADD COLUMN evidence_claims_json TEXT;
