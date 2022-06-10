"""empty message

Revision ID: 522f2f77b26d
Revises: 5d9bd94b1854
Create Date: 2022-06-01 17:10:53.527949

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '522f2f77b26d'
down_revision = '5d9bd94b1854'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('solicitud_ibfk_2', 'solicitud', type_='foreignkey')
    op.drop_column('solicitud', 'servicios_cliente')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('solicitud', sa.Column('servicios_cliente', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.create_foreign_key('solicitud_ibfk_2', 'solicitud', 'servicio', ['servicios_cliente'], ['id'])
    # ### end Alembic commands ###