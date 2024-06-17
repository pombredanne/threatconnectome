"""change_ticket_status

Revision ID: ce8ccec8d851
Revises: 60ecd0090353
Create Date: 2024-06-07 07:44:45.997215

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ce8ccec8d851'
down_revision = '60ecd0090353'
branch_labels = None
depends_on = None


def _delete_ticketstatus() -> None:
    op.get_bind().exec_driver_sql(
        "DELETE FROM ticketstatus"
    )
def _delete_currentticketstatus() -> None:
    op.get_bind().exec_driver_sql(
        "DELETE FROM currentticketstatus"
    )

def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    _delete_currentticketstatus()
    _delete_ticketstatus()
    op.add_column('ticketstatus', sa.Column('user_id', sa.String(length=36), nullable=False))
    op.create_index(op.f('ix_ticketstatus_user_id'), 'ticketstatus', ['user_id'], unique=False)
    op.create_foreign_key('ix_ticketstatus_user_id', 'ticketstatus', 'account', ['user_id'], ['user_id'])
    # ### end Alembic commands ###

def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('ix_ticketstatus_user_id', 'ticketstatus', type_='foreignkey')
    op.drop_index(op.f('ix_ticketstatus_user_id'), table_name='ticketstatus')
    op.drop_column('ticketstatus', 'user_id')
    # ### end Alembic commands ###
