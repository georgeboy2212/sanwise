"""empty message

Revision ID: e8abccf53846
Revises: db3217a26898
Create Date: 2022-05-03 15:25:04.522937

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'e8abccf53846'
down_revision = 'db3217a26898'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('cotizacion', sa.Column('solicitud_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'cotizacion', 'solicitud', ['solicitud_id'], ['id'])
    op.drop_column('cotizacion', 'valor_personas')
    op.drop_column('cotizacion', 'numero_personas')
    op.drop_column('cotizacion', 'valor_hora')
    op.create_foreign_key(None, 'solicitud', 'clientes', ['solicitud_cliente'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'solicitud', type_='foreignkey')
    op.add_column('cotizacion', sa.Column('valor_hora', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False))
    op.add_column('cotizacion', sa.Column('numero_personas', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False))
    op.add_column('cotizacion', sa.Column('valor_personas', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False))
    op.drop_constraint(None, 'cotizacion', type_='foreignkey')
    op.drop_column('cotizacion', 'solicitud_id')
    # ### end Alembic commands ###
