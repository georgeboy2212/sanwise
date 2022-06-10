"""empty message

Revision ID: 0e8f6b8c25cf
Revises: c202e2abb3d8
Create Date: 2022-06-01 17:30:02.343143

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '0e8f6b8c25cf'
down_revision = 'c202e2abb3d8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('servicio', 'costo_servicio')
    op.add_column('solicitud', sa.Column('costo_servicio', sa.Integer(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('solicitud', 'costo_servicio')
    op.add_column('servicio', sa.Column('costo_servicio', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False))
    # ### end Alembic commands ###
