"""empty message

Revision ID: 7272cd93cc2b
Revises: fa0a8006c6c1
Create Date: 2022-05-17 17:46:19.684482

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7272cd93cc2b'
down_revision = 'fa0a8006c6c1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('solicitud', sa.Column('sorvic', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'solicitud', 'servicio', ['sorvic'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'solicitud', type_='foreignkey')
    op.drop_column('solicitud', 'sorvic')
    # ### end Alembic commands ###
