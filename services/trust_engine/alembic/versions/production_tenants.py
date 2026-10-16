"""Scope persisted scans to deployment tenants."""
from alembic import op
import sqlalchemy as sa
revision='production_tenants'
down_revision='cp2_scan_lifecycle'
branch_labels=None
depends_on=None

def upgrade():
    op.add_column('scan_snapshots',sa.Column('tenant_id',sa.String(64),nullable=False,server_default='owner'))
    op.create_index('ix_scan_snapshots_tenant_id','scan_snapshots',['tenant_id'])

def downgrade():
    op.drop_index('ix_scan_snapshots_tenant_id',table_name='scan_snapshots')
    op.drop_column('scan_snapshots','tenant_id')
