"""empty message

Revision ID: fb0e54046cb2
Revises: 069e911ba528
Create Date: 2022-05-19 09:15:04.601347

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'fb0e54046cb2'
down_revision = '069e911ba528'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('servicio', sa.Column('servicio_id', sa.Integer(), nullable=True))
    op.drop_constraint('servicio_ibfk_1', 'servicio', type_='foreignkey')
    op.drop_constraint('servicio_ibfk_2', 'servicio', type_='foreignkey')
    op.create_foreign_key(None, 'servicio', 'solicitud', ['servicio_id'], ['id'])
    op.drop_column('servicio', 'solicitud_servicio_id')
    op.drop_column('servicio', 'servicio_cliente')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('servicio', sa.Column('servicio_cliente', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.add_column('servicio', sa.Column('solicitud_servicio_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.drop_constraint(None, 'servicio', type_='foreignkey')
    op.create_foreign_key('servicio_ibfk_2', 'servicio', 'clientes', ['servicio_cliente'], ['id'])
    op.create_foreign_key('servicio_ibfk_1', 'servicio', 'solicitud', ['solicitud_servicio_id'], ['id'])
    op.drop_column('servicio', 'servicio_id')
    # ### end Alembic commands ###
