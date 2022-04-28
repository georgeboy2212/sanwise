"""empty message

Revision ID: a1e6fc61cc3b
Revises: 1e6baf3d13a3
Create Date: 2022-04-27 16:49:23.095693

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'a1e6fc61cc3b'
down_revision = '1e6baf3d13a3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('asesor_ibfk_1', 'asesor', type_='foreignkey')
    op.drop_column('asesor', 'soli_id')
    op.drop_constraint('clientes_ibfk_1', 'clientes', type_='foreignkey')
    op.drop_column('clientes', 'solicitud_cliente')
    op.drop_constraint('servicio_ibfk_1', 'servicio', type_='foreignkey')
    op.drop_column('servicio', 'solicitud_id')
    op.add_column('solicitud', sa.Column('solicitud_cliente', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'solicitud', 'clientes', ['solicitud_cliente'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'solicitud', type_='foreignkey')
    op.drop_column('solicitud', 'solicitud_cliente')
    op.add_column('servicio', sa.Column('solicitud_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.create_foreign_key('servicio_ibfk_1', 'servicio', 'solicitud', ['solicitud_id'], ['id'])
    op.add_column('clientes', sa.Column('solicitud_cliente', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.create_foreign_key('clientes_ibfk_1', 'clientes', 'solicitud', ['solicitud_cliente'], ['id'])
    op.add_column('asesor', sa.Column('soli_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.create_foreign_key('asesor_ibfk_1', 'asesor', 'solicitud', ['soli_id'], ['id'])
    # ### end Alembic commands ###
