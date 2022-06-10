"""empty message

Revision ID: 292bf16bc6e4
Revises: 0075cc06cb52
Create Date: 2022-05-25 17:17:29.682176

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '292bf16bc6e4'
down_revision = '0075cc06cb52'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('cotizacion_ibfk_3', 'cotizacion', type_='foreignkey')
    op.drop_column('cotizacion', 'servicio_id')
    op.add_column('servicio', sa.Column('cotizacion_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'servicio', 'cotizacion', ['cotizacion_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'servicio', type_='foreignkey')
    op.drop_column('servicio', 'cotizacion_id')
    op.add_column('cotizacion', sa.Column('servicio_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.create_foreign_key('cotizacion_ibfk_3', 'cotizacion', 'servicio', ['servicio_id'], ['id'])
    # ### end Alembic commands ###
