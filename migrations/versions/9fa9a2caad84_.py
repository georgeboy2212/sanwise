"""empty message

Revision ID: 9fa9a2caad84
Revises: 2dd3c5eb158f
Create Date: 2022-05-23 14:14:15.228282

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '9fa9a2caad84'
down_revision = '2dd3c5eb158f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('servicio', sa.Column('solicitudes_id', sa.Integer(), nullable=True))
    op.drop_constraint('servicio_ibfk_2', 'servicio', type_='foreignkey')
    op.create_foreign_key(None, 'servicio', 'solicitud', ['solicitudes_id'], ['id'])
    op.drop_column('servicio', 'solicitud_id')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('servicio', sa.Column('solicitud_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.drop_constraint(None, 'servicio', type_='foreignkey')
    op.create_foreign_key('servicio_ibfk_2', 'servicio', 'solicitud', ['solicitud_id'], ['id'])
    op.drop_column('servicio', 'solicitudes_id')
    # ### end Alembic commands ###
