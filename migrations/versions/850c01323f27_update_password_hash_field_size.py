"""Update password_hash field size

Revision ID: 850c01323f27
Revises: a47d0e758198
Create Date: 2025-03-26 15:27:46.630805

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '850c01323f27'
down_revision = 'a47d0e758198'
branch_labels = None
depends_on = None


def upgrade():
    # Изменяем длину столбца password_hash с 120 на 255 символов
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('password_hash',
               existing_type=sa.String(length=120),  # Текущий тип
               type_=sa.String(length=255),          # Новый тип
               existing_nullable=False)

def downgrade():
    # Возвращаем длину столбца password_hash обратно с 255 на 120 символов
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('password_hash',
               existing_type=sa.String(length=255),  # Текущий тип
               type_=sa.String(length=120),          # Новый тип
               existing_nullable=False)