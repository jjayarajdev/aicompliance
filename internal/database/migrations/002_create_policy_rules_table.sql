-- Create policy rules table for managing security and compliance policies
CREATE TABLE policy_rules (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 100, -- Lower number = higher priority
    
    -- Rule conditions
    conditions JSONB NOT NULL, -- JSON object defining when rule applies
    
    -- Rule types
    rule_type VARCHAR(50) NOT NULL, -- 'pii_detection', 'content_filter', 'rate_limit', 'access_control'
    
    -- Target specification
    target_providers TEXT[], -- ['openai', 'anthropic'] or ['*'] for all
    target_endpoints TEXT[], -- Endpoint patterns to match
    target_users TEXT[], -- User IDs or patterns
    target_roles TEXT[], -- Role names
    
    -- PII detection configuration
    pii_types TEXT[], -- ['ssn', 'email', 'phone', 'credit_card', 'custom']
    pii_patterns TEXT[], -- Custom regex patterns for PII detection
    pii_threshold DECIMAL(3,2) DEFAULT 0.8, -- Confidence threshold 0.00-1.00
    
    -- Content filtering
    content_categories TEXT[], -- ['harmful', 'explicit', 'political', 'medical']
    content_keywords TEXT[], -- Keywords to flag
    content_regexes TEXT[], -- Regular expressions for content matching
    
    -- Actions to take
    action VARCHAR(20) NOT NULL DEFAULT 'allow', -- 'allow', 'block', 'sanitize', 'redact', 'warn'
    redaction_strategy VARCHAR(20) DEFAULT 'mask', -- 'mask', 'remove', 'replace'
    replacement_text VARCHAR(255) DEFAULT '[REDACTED]',
    
    -- Rate limiting (if rule_type = 'rate_limit')
    rate_limit_requests INTEGER, -- Max requests per window
    rate_limit_window_seconds INTEGER, -- Time window in seconds
    rate_limit_scope VARCHAR(20) DEFAULT 'user', -- 'user', 'ip', 'global'
    
    -- Notification settings
    notify_on_violation BOOLEAN DEFAULT FALSE,
    notification_channels TEXT[], -- ['email', 'slack', 'webhook']
    notification_recipients TEXT[],
    
    -- Metadata
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    version INTEGER NOT NULL DEFAULT 1,
    tags TEXT[],
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for efficient policy matching
CREATE INDEX idx_policy_rules_enabled ON policy_rules(enabled);
CREATE INDEX idx_policy_rules_priority ON policy_rules(priority) WHERE enabled = true;
CREATE INDEX idx_policy_rules_rule_type ON policy_rules(rule_type) WHERE enabled = true;
CREATE INDEX idx_policy_rules_target_providers ON policy_rules USING GIN(target_providers);
CREATE INDEX idx_policy_rules_target_endpoints ON policy_rules USING GIN(target_endpoints);
CREATE INDEX idx_policy_rules_target_users ON policy_rules USING GIN(target_users);
CREATE INDEX idx_policy_rules_target_roles ON policy_rules USING GIN(target_roles);
CREATE INDEX idx_policy_rules_created_at ON policy_rules(created_at);
CREATE INDEX idx_policy_rules_updated_at ON policy_rules(updated_at);

-- Create composite index for efficient rule matching
CREATE INDEX idx_policy_rules_matching ON policy_rules(enabled, priority, rule_type) 
WHERE enabled = true;

-- Create GIN indexes for JSON conditions
CREATE INDEX idx_policy_rules_conditions ON policy_rules USING GIN(conditions);

-- Create policy rule versions table for audit trail
CREATE TABLE policy_rule_versions (
    id BIGSERIAL PRIMARY KEY,
    rule_id BIGINT NOT NULL REFERENCES policy_rules(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    rule_data JSONB NOT NULL, -- Complete rule data at this version
    change_type VARCHAR(20) NOT NULL, -- 'created', 'updated', 'deleted', 'enabled', 'disabled'
    change_description TEXT,
    changed_by VARCHAR(255),
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    UNIQUE(rule_id, version)
);

CREATE INDEX idx_policy_rule_versions_rule_id ON policy_rule_versions(rule_id);
CREATE INDEX idx_policy_rule_versions_changed_at ON policy_rule_versions(changed_at);

-- Create trigger to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_policy_rules_updated_at 
    BEFORE UPDATE ON policy_rules 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default policy rules
INSERT INTO policy_rules (
    name, 
    description, 
    rule_type, 
    conditions, 
    target_providers, 
    pii_types, 
    action
) VALUES 
(
    'Default PII Detection',
    'Detect and redact common PII types in all requests',
    'pii_detection',
    '{"match_any": true}',
    ARRAY['*'],
    ARRAY['ssn', 'email', 'phone', 'credit_card'],
    'redact'
),
(
    'Block High Risk Content',
    'Block requests with high risk content classification',
    'content_filter',
    '{"risk_score": {"min": 0.8}}',
    ARRAY['*'],
    ARRAY['harmful', 'explicit'],
    'block'
),
(
    'Rate Limit Per User',
    'Limit users to 100 requests per hour',
    'rate_limit',
    '{"applies_to": "authenticated_users"}',
    ARRAY['*'],
    NULL,
    'block'
);

-- Set rate limiting parameters for the rate limit rule
UPDATE policy_rules 
SET 
    rate_limit_requests = 100,
    rate_limit_window_seconds = 3600,
    rate_limit_scope = 'user'
WHERE name = 'Rate Limit Per User';

-- Add comments for documentation
COMMENT ON TABLE policy_rules IS 'Configuration table for AI Gateway security and compliance policies';
COMMENT ON COLUMN policy_rules.conditions IS 'JSON object defining when this rule should be applied';
COMMENT ON COLUMN policy_rules.priority IS 'Rule priority - lower numbers are evaluated first';
COMMENT ON COLUMN policy_rules.target_providers IS 'Array of AI providers this rule applies to, or ["*"] for all';
COMMENT ON COLUMN policy_rules.action IS 'Action to take when rule conditions are met';
COMMENT ON TABLE policy_rule_versions IS 'Audit trail of all changes to policy rules'; 