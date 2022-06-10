"""empty message

Revision ID: d601ce9a9590
Revises: abde0b0c2840
Create Date: 2022-05-19 11:27:23.189652

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd601ce9a9590'
down_revision = 'abde0b0c2840'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('servicio', sa.Column('cliente_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'servicio', 'clientes', ['cliente_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'servicio', type_='foreignkey')
    op.drop_column('servicio', 'cliente_id')
    # ### end Alembic commands ###