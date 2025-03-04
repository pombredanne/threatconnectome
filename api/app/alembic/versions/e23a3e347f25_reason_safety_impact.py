"""reason_safety_impact

Revision ID: e23a3e347f25
Revises: 77356863e454
Create Date: 2025-03-03 06:40:09.149136

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e23a3e347f25'
down_revision = '77356863e454'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('threat', sa.Column('reason_safety_impact', sa.Text(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('threat', 'reason_safety_impact')
    # ### end Alembic commands ###
