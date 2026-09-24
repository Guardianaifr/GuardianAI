"""initial baseline migration

Revision ID: 0001_initial_baseline
Revises:
Create Date: 2026-09-23

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0001_initial_baseline'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'security_events',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('guardian_id', sa.Text(), nullable=True),
        sa.Column('tenant_id', sa.Text(), server_default='default', nullable=True),
        sa.Column('event_type', sa.Text(), nullable=True),
        sa.Column('severity', sa.Text(), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.Float(), nullable=True),
    )

    op.create_table(
        'analytics',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('tenant_id', sa.Text(), server_default='default', nullable=True),
        sa.Column('path', sa.Text(), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.Column('timestamp', sa.Float(), nullable=True),
    )

    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('guardian_id', sa.Text(), nullable=True),
        sa.Column('action', sa.Text(), nullable=True),
        sa.Column('user', sa.Text(), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.Float(), nullable=True),
        sa.Column('signature', sa.Text(), nullable=True),
        sa.Column('prev_hash', sa.Text(), nullable=True),
        sa.Column('entry_hash', sa.Text(), nullable=True),
    )

    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('key_name', sa.Text(), unique=True, nullable=True),
        sa.Column('key_prefix', sa.Text(), nullable=True),
        sa.Column('key_hash', sa.Text(), unique=True, nullable=True),
        sa.Column('is_active', sa.Integer(), server_default='1', nullable=True),
        sa.Column('created_by', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Float(), nullable=True),
        sa.Column('last_used_at', sa.Float(), nullable=True),
    )

    op.create_table(
        'revoked_tokens',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('jti', sa.Text(), unique=True, nullable=True),
        sa.Column('revoked_by', sa.Text(), nullable=True),
        sa.Column('revoked_at', sa.Float(), nullable=True),
        sa.Column('expires_at', sa.Float(), nullable=True),
    )

    op.create_table(
        'issued_tokens',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('jti', sa.Text(), unique=True, nullable=True),
        sa.Column('subject', sa.Text(), nullable=True),
        sa.Column('role', sa.Text(), nullable=True),
        sa.Column('issued_at', sa.Float(), nullable=True),
        sa.Column('expires_at', sa.Float(), nullable=True),
        sa.Column('revoked_at', sa.Float(), nullable=True),
        sa.Column('revoked_by', sa.Text(), nullable=True),
        sa.Column('revoke_reason', sa.Text(), nullable=True),
    )

    op.create_table(
        'audit_delivery_failures',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('sink_type', sa.Text(), nullable=True),
        sa.Column('payload', sa.Text(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('created_at', sa.Float(), nullable=True),
        sa.Column('last_attempt_at', sa.Float(), nullable=True),
    )

    op.create_table(
        'customers',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('email', sa.Text(), unique=True, nullable=True),
        sa.Column('tenant_name', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Float(), nullable=True),
    )

    op.create_table(
        'orders',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('order_id', sa.Text(), unique=True, nullable=True),
        sa.Column('customer_email', sa.Text(), nullable=True),
        sa.Column('tenant_name', sa.Text(), nullable=True),
        sa.Column('plan', sa.Text(), nullable=True),
        sa.Column('payment_method', sa.Text(), nullable=True),
        sa.Column('provider', sa.Text(), nullable=True),
        sa.Column('status', sa.Text(), nullable=True),
        sa.Column('checkout_url', sa.Text(), nullable=True),
        sa.Column('provider_transaction_id', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Float(), nullable=True),
        sa.Column('updated_at', sa.Float(), nullable=True),
    )

    op.create_table(
        'licenses',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('order_id', sa.Text(), unique=True, nullable=True),
        sa.Column('machine_id', sa.Text(), nullable=True),
        sa.Column('license_key', sa.Text(), nullable=True),
        sa.Column('status', sa.Text(), nullable=True),
        sa.Column('issued_at', sa.Float(), nullable=True),
    )

    op.create_table(
        'lockout_state',
        sa.Column('identity', sa.Text(), primary_key=True),
        sa.Column('failed_count', sa.Integer(), nullable=True),
        sa.Column('locked_until', sa.Float(), nullable=True),
    )

    op.create_table(
        'agentic_agent_keys',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('agent_id', sa.Text(), nullable=False),
        sa.Column('key_id', sa.Text(), nullable=False),
        sa.Column('key_secret_hash', sa.Text(), nullable=False),
        sa.Column('key_secret_ciphertext', sa.Text(), nullable=False),
        sa.Column('cert_fingerprints_json', sa.Text(), nullable=True),
        sa.Column('status', sa.Text(), server_default='active', nullable=True),
        sa.Column('created_by', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Float(), nullable=True),
        sa.Column('rotated_at', sa.Float(), nullable=True),
        sa.Column('revoked_at', sa.Float(), nullable=True),
        sa.Column('revoked_by', sa.Text(), nullable=True),
        sa.Column('revoke_reason', sa.Text(), nullable=True),
        sa.UniqueConstraint('agent_id', 'key_id', name='uq_agentic_agent_key'),
    )

    op.create_table(
        'agentic_revocations',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('revocation_type', sa.Text(), nullable=False),
        sa.Column('agent_id', sa.Text(), nullable=True),
        sa.Column('key_id', sa.Text(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('revoked_by', sa.Text(), nullable=True),
        sa.Column('revoked_at', sa.Float(), nullable=True),
    )

    op.create_table(
        'agentic_execution_grants',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('execution_id', sa.Text(), unique=True, nullable=False),
        sa.Column('agent_id', sa.Text(), nullable=True),
        sa.Column('parent_agent', sa.Text(), nullable=True),
        sa.Column('scopes_json', sa.Text(), nullable=True),
        sa.Column('tools_json', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.Float(), nullable=True),
        sa.Column('created_by', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Float(), nullable=True),
        sa.Column('revoked_at', sa.Float(), nullable=True),
        sa.Column('revoked_by', sa.Text(), nullable=True),
        sa.Column('revoke_reason', sa.Text(), nullable=True),
    )

    op.create_table(
        'agentic_policy_edges',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('parent_agent', sa.Text(), nullable=False),
        sa.Column('child_agent', sa.Text(), nullable=False),
        sa.Column('scopes_json', sa.Text(), nullable=True),
        sa.Column('tools_json', sa.Text(), nullable=True),
        sa.Column('max_hops', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Float(), nullable=True),
        sa.UniqueConstraint('parent_agent', 'child_agent', name='uq_agentic_policy_edge'),
    )

    op.create_table(
        'agentic_trace_hashes',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('trace_hash', sa.Text(), unique=True, nullable=False),
        sa.Column('agent_id', sa.Text(), nullable=True),
        sa.Column('execution_id', sa.Text(), nullable=True),
        sa.Column('first_seen_at', sa.Float(), nullable=True),
    )
    op.create_table(
        'erc8004_registrations',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('agent_id', sa.Text(), nullable=False),
        sa.Column('passport_id', sa.Text(), nullable=False),
        sa.Column('chain', sa.Text(), nullable=False),
        sa.Column('status', sa.Text(), nullable=False),
        sa.Column('token_id', sa.Integer(), nullable=True),
        sa.Column('tx_hash', sa.Text(), nullable=True),
        sa.Column('retries', sa.Integer(), server_default='0', nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.Float(), nullable=True),
        sa.Column('owner_address', sa.Text(), nullable=True),
        sa.UniqueConstraint('agent_id', 'chain', name='uq_erc8004_agent_chain'),
    )

    op.create_table(
        'agent_passports',
        sa.Column('passport_id', sa.Text(), primary_key=True),
        sa.Column('agent_id', sa.Text(), unique=True, nullable=False),
        sa.Column('owner_pubkey', sa.Text(), nullable=False),
        sa.Column('chain_id', sa.Text(), server_default='base', nullable=True),
        sa.Column('trust_score', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('tier', sa.Text(), server_default='UNVERIFIED', nullable=True),
        sa.Column('credentials', sa.Text(), server_default='[]', nullable=True),
        sa.Column('metadata', sa.Text(), server_default='{}', nullable=True),
        sa.Column('issued_at', sa.Float(), nullable=True),
        sa.Column('updated_at', sa.Float(), nullable=True),
        sa.Column('is_active', sa.Integer(), server_default='1', nullable=True),
        sa.Column('cortex_events_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('last_anchor_tx', sa.Text(), server_default='', nullable=True),
        sa.Column('tenant_id', sa.Text(), server_default='default', nullable=True),
    )
    op.create_index('idx_passports_owner_pubkey', 'agent_passports', ['owner_pubkey'])
    op.create_index('idx_active_owner_pubkey_unique', 'agent_passports', ['owner_pubkey'], unique=True, sqlite_where=sa.text("is_active = 1"))

    op.create_table(
        'passport_credentials',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('passport_id', sa.Text(), sa.ForeignKey('agent_passports.passport_id'), nullable=False),
        sa.Column('credential_type', sa.Text(), nullable=False),
        sa.Column('credential_data', sa.Text(), nullable=False),
        sa.Column('issued_at', sa.Float(), nullable=True),
        sa.Column('expires_at', sa.Float(), nullable=True),
        sa.Column('is_valid', sa.Integer(), server_default='1', nullable=True),
    )

    op.create_table(
        'passport_score_history',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('agent_id', sa.Text(), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('tier', sa.Text(), nullable=False),
        sa.Column('breakdown', sa.Text(), server_default='{}', nullable=True),
        sa.Column('recorded_at', sa.Float(), nullable=True),
    )

    op.create_table(
        'cortex_events',
        sa.Column('event_id', sa.Text(), primary_key=True),
        sa.Column('agent_id', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.Float(), nullable=False),
        sa.Column('event_type', sa.Text(), nullable=False),
        sa.Column('category', sa.Text(), server_default='', nullable=True),
        sa.Column('action', sa.Text(), server_default='', nullable=True),
        sa.Column('context_hash', sa.Text(), server_default='', nullable=True),
        sa.Column('input_hash', sa.Text(), server_default='', nullable=True),
        sa.Column('output_hash', sa.Text(), server_default='', nullable=True),
        sa.Column('reasoning_hash', sa.Text(), server_default='', nullable=True),
        sa.Column('reasoning_text', sa.Text(), server_default='', nullable=True),
        sa.Column('confidence', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('parent_event_id', sa.Text(), server_default='', nullable=True),
        sa.Column('merkle_leaf', sa.Text(), server_default='', nullable=True),
        sa.Column('metadata', sa.Text(), server_default='{}', nullable=True),
        sa.Column('anchored', sa.Integer(), server_default='0', nullable=True),
        sa.Column('anchor_tx', sa.Text(), server_default='', nullable=True),
    )
    op.create_index('idx_cortex_agent_ts', 'cortex_events', ['agent_id', 'timestamp'])
    op.create_index('idx_cortex_agent_type', 'cortex_events', ['agent_id', 'event_type'])

    op.create_table(
        'cortex_trials',
        sa.Column('agent_id', sa.Text(), primary_key=True),
        sa.Column('started_at', sa.Float(), nullable=False),
        sa.Column('expires_at', sa.Float(), nullable=False),
        sa.Column('is_active', sa.Integer(), server_default='1', nullable=True),
    )

    op.create_table(
        'cortex_anchors',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('agent_id', sa.Text(), nullable=False),
        sa.Column('merkle_root', sa.Text(), nullable=False),
        sa.Column('event_count', sa.Integer(), nullable=False),
        sa.Column('period_start', sa.Float(), nullable=False),
        sa.Column('period_end', sa.Float(), nullable=False),
        sa.Column('chain_id', sa.Text(), server_default='monad', nullable=True),
        sa.Column('tx_hash', sa.Text(), server_default='', nullable=True),
        sa.Column('anchored_at', sa.Float(), nullable=False),
        sa.Column('verified', sa.Integer(), server_default='0', nullable=True),
    )

    op.create_table(
        'cortex_insurance_certificates',
        sa.Column('certificate_id', sa.Text(), primary_key=True),
        sa.Column('agent_id', sa.Text(), nullable=False),
        sa.Column('period_start', sa.Float(), nullable=False),
        sa.Column('period_end', sa.Float(), nullable=False),
        sa.Column('generated_at', sa.Float(), nullable=False),
        sa.Column('total_decisions', sa.Integer(), nullable=False),
        sa.Column('total_events', sa.Integer(), nullable=False),
        sa.Column('merkle_anchors', sa.Integer(), nullable=False),
        sa.Column('cross_agent_interlocks', sa.Integer(), nullable=False),
        sa.Column('risk_level', sa.Text(), nullable=False),
        sa.Column('data_hash', sa.Text(), nullable=False),
        sa.Column('certificate_signature', sa.Text(), nullable=False),
        sa.Column('onchain_tx', sa.Text(), server_default='', nullable=True),
        sa.Column('onchain_chain', sa.Text(), server_default='', nullable=True),
        sa.Column('onchain_simulated', sa.Integer(), server_default='0', nullable=True),
    )

    op.create_table(
        'cortex_interlocks',
        sa.Column('interlock_id', sa.Text(), primary_key=True),
        sa.Column('agent_a_id', sa.Text(), nullable=False),
        sa.Column('agent_b_id', sa.Text(), nullable=False),
        sa.Column('nonce', sa.Text(), nullable=False),
        sa.Column('interaction_hash', sa.Text(), nullable=False),
        sa.Column('agent_a_event_id', sa.Text(), server_default='', nullable=True),
        sa.Column('agent_b_event_id', sa.Text(), server_default='', nullable=True),
        sa.Column('timestamp', sa.Float(), nullable=False),
        sa.Column('proof_hash', sa.Text(), server_default='', nullable=True),
        sa.Column('metadata', sa.Text(), server_default='{}', nullable=True),
    )
    op.create_index('idx_interlock_agents', 'cortex_interlocks', ['agent_a_id', 'agent_b_id'])

    op.create_table(
        'agent_encrypted_memories',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('agent_id', sa.Text(), nullable=False),
        sa.Column('session_id', sa.Text(), nullable=False),
        sa.Column('seq_no', sa.Integer(), nullable=False),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=False),
        sa.Column('iv', sa.LargeBinary(), nullable=False),
        sa.Column('aad', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.Float(), nullable=False),
        sa.Column('created_at', sa.Float(), nullable=False),
        sa.UniqueConstraint('agent_id', 'session_id', 'seq_no', name='uq_agent_memories'),
    )
    op.create_index('idx_encrypted_memories_agent', 'agent_encrypted_memories', ['agent_id'])

    op.create_table(
        'blocked_transactions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('tx_hash', sa.Text(), unique=True, nullable=True),
        sa.Column('from_address', sa.Text(), nullable=True),
        sa.Column('to_address', sa.Text(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.Float(), nullable=True),
    )
    op.create_table(
        'web3sec_rules',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('rule_type', sa.Text(), nullable=True),
        sa.Column('pattern', sa.Text(), nullable=True),
        sa.Column('action', sa.Text(), nullable=True),
    )
    op.create_table(
        'web3sec_whitelist',
        sa.Column('address', sa.Text(), primary_key=True),
        sa.Column('label', sa.Text(), nullable=True),
        sa.Column('added_at', sa.Float(), nullable=True),
    )


def downgrade() -> None:

    op.drop_table('web3sec_whitelist')
    op.drop_table('web3sec_rules')
    op.drop_table('blocked_transactions')
    op.drop_index('idx_encrypted_memories_agent', table_name='agent_encrypted_memories')
    op.drop_table('agent_encrypted_memories')
    op.drop_index('idx_interlock_agents', table_name='cortex_interlocks')
    op.drop_table('cortex_interlocks')
    op.drop_table('cortex_insurance_certificates')
    op.drop_table('cortex_anchors')
    op.drop_table('cortex_trials')
    op.drop_index('idx_cortex_agent_type', table_name='cortex_events')
    op.drop_index('idx_cortex_agent_ts', table_name='cortex_events')
    op.drop_table('cortex_events')
    op.drop_table('passport_score_history')
    op.drop_table('passport_credentials')
    op.drop_index('idx_active_owner_pubkey_unique', table_name='agent_passports')
    op.drop_index('idx_passports_owner_pubkey', table_name='agent_passports')
    op.drop_table('agent_passports')
    op.drop_table('erc8004_registrations')

    op.drop_table('agentic_trace_hashes')
    op.drop_table('agentic_policy_edges')
    op.drop_table('agentic_execution_grants')
    op.drop_table('agentic_revocations')
    op.drop_table('agentic_agent_keys')
    op.drop_table('lockout_state')
    op.drop_table('licenses')
    op.drop_table('orders')
    op.drop_table('customers')
    op.drop_table('audit_delivery_failures')
    op.drop_table('issued_tokens')
    op.drop_table('revoked_tokens')
    op.drop_table('api_keys')
    op.drop_table('audit_logs')
    op.drop_table('analytics')
    op.drop_table('security_events')
