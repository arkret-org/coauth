CREATE TABLE IF NOT EXISTS risk_action_proposals (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    proposer_did TEXT NOT NULL,
    reason TEXT NOT NULL,
    ticket TEXT,
    state TEXT NOT NULL DEFAULT 'draft',
    approval_proofs JSONB NOT NULL DEFAULT '[]'::JSONB,
    required_approvals INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    CONSTRAINT risk_action_proposals_action_non_empty
        CHECK (btrim(action) <> ''),
    CONSTRAINT risk_action_proposals_proposer_did_non_empty
        CHECK (btrim(proposer_did) <> ''),
    CONSTRAINT risk_action_proposals_reason_non_empty
        CHECK (btrim(reason) <> ''),
    CONSTRAINT risk_action_proposals_state_valid
        CHECK (state IN ('draft', 'approved', 'executed', 'cancelled', 'rejected')),
    CONSTRAINT risk_action_proposals_required_approvals_positive
        CHECK (required_approvals >= 1)
);

CREATE INDEX IF NOT EXISTS risk_action_proposals_account_idx
    ON risk_action_proposals(account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS risk_action_proposals_state_idx
    ON risk_action_proposals(state);
