import os
import datetime
from app import app, db, Usuarios
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash

migrate = Migrate(app, db)
manager = Manager(app)

app.config['SECRET_KEY'] = '6&GhN4$qAo68-jE+_xY3erty69dpdof*3gdfgfgdjfjekesaassasaas4$'
app.config['SECURITY_PASSWORD_SALT'] ='9HDg49$=_QKHWPYNKRHjnthro903jxidjshñkñjkhshsqj47-'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://PLJlQvbfL9:Pf4IB3DyTM@remotemysql.com/PLJlQvbfL9"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True, "pool_recycle": 300}
#Configuracion de Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_DEBUG'] = app.debug
app.config['MAIL_USERNAME'] = 'jeromero7884@misena.edu.co' 
app.config['MAIL_PASSWORD'] = 'Holly2022+'
app.config['USER_EMAIL_SENDER_EMAIL'] = 'jeromero7884@misena.edu.co'
app.config['MAIL_DEFAULT_SENDER'] = 'jeromero7884@misena.edu.co'
app.config['MAIL_ASCII_ATTACHMENTS'] = True

# migrations
manager.add_command('db', MigrateCommand)

#Crea el usuario admin
@manager.command
def create_admin():
    db.session.add(Usuarios(
        nombres="admin",
        apellidos="admin",
        correo="sanwise@admin.com",
        password=generate_password_hash("sanwiseadmin", method='sha256'),
        role=True,
        registrado_en=datetime.datetime.now(),
        confirmado=True,
        confirmado_en=datetime.datetime.now())
    )
    db.session.commit()

if __name__ == '__main__':
    manager.run()
