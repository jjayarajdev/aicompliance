-- Create audit logs table for tracking API requests and policy decisions
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    request_id UUID NOT NULL,
    user_id VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    host VARCHAR(255) NOT NULL,
    
    -- Request details
    request_headers JSONB,
    request_body_size INTEGER DEFAULT 0,
    request_body_hash VARCHAR(64),
    
    -- Response details
    response_status INTEGER,
    response_headers JSONB,
    response_body_size INTEGER DEFAULT 0,
    response_time_ms INTEGER,
    
    -- AI Provider information
    provider VARCHAR(50), -- 'openai', 'anthropic', etc.
    provider_model VARCHAR(100),
    provider_endpoint TEXT,
    
    -- Content analysis results
    content_analysis JSONB,
    pii_detected BOOLEAN DEFAULT FALSE,
    pii_types TEXT[],
    content_classification VARCHAR(20), -- 'public', 'internal', 'confidential', 'restricted'
    risk_score DECIMAL(3,2), -- 0.00 to 1.00
    
    -- Policy decisions
    policy_decisions JSONB,
    action_taken VARCHAR(20), -- 'allow', 'block', 'sanitize', 'redact'
    policy_violations TEXT[],
    
    -- Performance metrics
    cache_hit BOOLEAN DEFAULT FALSE,
    cache_key VARCHAR(255),
    processing_time_ms INTEGER,
    
    -- Metadata
    client_ip INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    tags TEXT[],
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for efficient querying
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_provider ON audit_logs(provider);
CREATE INDEX idx_audit_logs_action_taken ON audit_logs(action_taken);
CREATE INDEX idx_audit_logs_pii_detected ON audit_logs(pii_detected);
CREATE INDEX idx_audit_logs_content_classification ON audit_logs(content_classification);
CREATE INDEX idx_audit_logs_response_status ON audit_logs(response_status);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- Create partial indexes for specific queries
CREATE INDEX idx_audit_logs_policy_violations ON audit_logs(timestamp) 
WHERE array_length(policy_violations, 1) > 0;

CREATE INDEX idx_audit_logs_high_risk ON audit_logs(timestamp) 
WHERE risk_score > 0.7;

-- Add comments for documentation
COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail for all API requests through the AI Gateway';
COMMENT ON COLUMN audit_logs.request_id IS 'Unique identifier for the request, used for tracing';
COMMENT ON COLUMN audit_logs.content_analysis IS 'JSON object containing detailed content analysis results';
COMMENT ON COLUMN audit_logs.policy_decisions IS 'JSON object containing all policy evaluation results';
COMMENT ON COLUMN audit_logs.risk_score IS 'Calculated risk score from 0.00 (no risk) to 1.00 (high risk)';
COMMENT ON COLUMN audit_logs.action_taken IS 'Final action taken by the gateway based on policy evaluation'; 