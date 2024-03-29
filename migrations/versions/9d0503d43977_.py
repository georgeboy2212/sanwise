"""empty message

Revision ID: 9d0503d43977
Revises: 26b19285f4e8
Create Date: 2022-05-25 17:35:07.197994

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9d0503d43977'
down_revision = '26b19285f4e8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('asesor',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('primernombre_asesor', sa.String(length=120), nullable=False),
    sa.Column('apellido_asesor', sa.String(length=120), nullable=False),
    sa.Column('correo_asesor', sa.String(length=150), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('clientes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombres', sa.String(length=80), nullable=False),
    sa.Column('apellidos', sa.String(length=80), nullable=False),
    sa.Column('correo', sa.String(length=120), nullable=False),
    sa.Column('empresa', sa.String(length=120), nullable=False),
    sa.Column('celular', sa.String(length=50), nullable=False),
    sa.Column('mensaje', sa.String(length=500), nullable=False),
    sa.Column('checkbox', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('solicitud',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('servicio_campo', sa.String(length=120), nullable=False),
    sa.Column('asesore', sa.String(length=120), nullable=False),
    sa.Column('solicitud_cliente', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['solicitud_cliente'], ['clientes.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('servicio',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre_servicio', sa.String(length=120), nullable=False),
    sa.Column('costo_servicio', sa.Integer(), nullable=False),
    sa.Column('solicitudes_id', sa.Integer(), nullable=True),
    sa.Column('cliente_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['cliente_id'], ['clientes.id'], ),
    sa.ForeignKeyConstraint(['solicitudes_id'], ['solicitud.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('cotizacion',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('numero_horas', sa.Integer(), nullable=False),
    sa.Column('descuento', sa.Integer(), nullable=False),
    sa.Column('cliente_id', sa.Integer(), nullable=True),
    sa.Column('solicitud_id', sa.Integer(), nullable=True),
    sa.Column('cotizacion_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['cliente_id'], ['clientes.id'], ),
    sa.ForeignKeyConstraint(['cotizacion_id'], ['servicio.id'], ),
    sa.ForeignKeyConstraint(['solicitud_id'], ['solicitud.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('cotizacion')
    op.drop_table('servicio')
    op.drop_table('solicitud')
    op.drop_table('clientes')
    op.drop_table('asesor')
    # ### end Alembic commands ###
