"""Persist every scan and execution; preserve fractional scores."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB
revision = "cp2_scan_lifecycle"
down_revision = "eb6abc0f635b"
branch_labels = None
depends_on = None

def upgrade():
    op.alter_column("trust_scores", "overall_score", existing_type=sa.Integer(), type_=sa.Float(), postgresql_using="overall_score::double precision")
    op.create_table("scan_snapshots",
        sa.Column("request_id",sa.String(),primary_key=True),
        sa.Column("scan_id",UUID(as_uuid=False),sa.ForeignKey("scans.id"),nullable=False,unique=True),
        sa.Column("payload",JSONB(),nullable=False),
        sa.Column("updated_at",sa.DateTime(),nullable=False))
    op.create_table("agent_executions",
        sa.Column("id",UUID(as_uuid=False),primary_key=True),
        sa.Column("scan_id",UUID(as_uuid=False),sa.ForeignKey("scans.id"),nullable=False),
        sa.Column("agent_id",UUID(as_uuid=False),sa.ForeignKey("agents.id"),nullable=False),
        sa.Column("file",sa.Text()), sa.Column("status",sa.String(),nullable=False),
        sa.Column("payload",JSONB(),nullable=False))

def downgrade():
    op.drop_table("agent_executions")
    op.drop_table("scan_snapshots")
    op.alter_column("trust_scores","overall_score",existing_type=sa.Float(),type_=sa.Integer(),postgresql_using="round(overall_score)::integer")
