"""Add agents, security_events, and blocked_ips tables

Revision ID: f2acb25bab88
Revises: 
Create Date: 2025-11-27 23:22:50.079404

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'f2acb25bab88'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create agents table
    op.create_table('agents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('hostname', sa.String(), nullable=False),
        sa.Column('platform', sa.String(), nullable=False),
        sa.Column('platform_version', sa.String(), nullable=True),
        sa.Column('agent_version', sa.String(), nullable=False),
        sa.Column('capabilities', sa.JSON(), nullable=True),
        sa.Column('is_admin', sa.Boolean(), nullable=False, default=False),
        sa.Column('registered_at', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(), nullable=False, default='online'),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_agents_id', 'agents', ['id'], unique=False)
    op.create_index('ix_agents_hostname', 'agents', ['hostname'], unique=True)
    
    # Create security_events table
    op.create_table('security_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('agent_id', sa.Integer(), nullable=False),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False, default='LOW'),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('description', sa.String(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('source_ip', sa.String(), nullable=True),
        sa.Column('destination_ip', sa.String(), nullable=True),
        sa.Column('process_name', sa.String(), nullable=True),
        sa.Column('is_threat', sa.Boolean(), nullable=False, default=False),
        sa.Column('threat_id', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id']),
        sa.ForeignKeyConstraint(['threat_id'], ['threat_events.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_security_events_id', 'security_events', ['id'], unique=False)
    op.create_index('ix_security_events_agent_id', 'security_events', ['agent_id'], unique=False)
    op.create_index('ix_security_events_event_type', 'security_events', ['event_type'], unique=False)
    op.create_index('ix_security_events_timestamp', 'security_events', ['timestamp'], unique=False)
    
    # Create blocked_ips table
    op.create_table('blocked_ips',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(), nullable=False),
        sa.Column('reason', sa.String(), nullable=False),
        sa.Column('blocked_at', sa.DateTime(), nullable=False),
        sa.Column('blocked_by', sa.String(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('threat_id', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_blocked_ips_id', 'blocked_ips', ['id'], unique=False)
    op.create_index('ix_blocked_ips_ip_address', 'blocked_ips', ['ip_address'], unique=True)


def downgrade():
    op.drop_index('ix_blocked_ips_ip_address', table_name='blocked_ips')
    op.drop_index('ix_blocked_ips_id', table_name='blocked_ips')
    op.drop_table('blocked_ips')
    
    op.drop_index('ix_security_events_timestamp', table_name='security_events')
    op.drop_index('ix_security_events_event_type', table_name='security_events')
    op.drop_index('ix_security_events_agent_id', table_name='security_events')
    op.drop_index('ix_security_events_id', table_name='security_events')
    op.drop_table('security_events')
    
    op.drop_index('ix_agents_hostname', table_name='agents')
    op.drop_index('ix_agents_id', table_name='agents')
    op.drop_table('agents')
