"""empty message

Revision ID: 7ea01639363e
Revises: 9d0503d43977
Create Date: 2022-06-01 10:26:22.345886

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '7ea01639363e'
down_revision = '9d0503d43977'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('cotizacion_ibfk_2', 'cotizacion', type_='foreignkey')
    op.drop_column('cotizacion', 'cotizacion_id')
    op.add_column('servicio', sa.Column('cotizacion_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'servicio', 'cotizacion', ['cotizacion_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'servicio', type_='foreignkey')
    op.drop_column('servicio', 'cotizacion_id')
    op.add_column('cotizacion', sa.Column('cotizacion_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.create_foreign_key('cotizacion_ibfk_2', 'cotizacion', 'servicio', ['cotizacion_id'], ['id'])
    # ### end Alembic commands ###
