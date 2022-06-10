"""empty message

Revision ID: 177c13631573
Revises: e8abccf53846
Create Date: 2022-05-17 12:54:59.307636

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '177c13631573'
down_revision = 'e8abccf53846'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('cotizacion', sa.Column('valor_total', sa.Integer(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('cotizacion', 'valor_total')
    # ### end Alembic commands ###