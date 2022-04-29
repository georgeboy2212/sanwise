import os
from itsdangerous import URLSafeTimedSerializer
from datetime import timedelta, datetime
from typing import Optional
from flask import Flask, render_template, redirect, url_for, flash, request, abort, session, g, current_app
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, validators, IntegerField, SelectField, DateTimeField, TextAreaField, SelectMultipleField
from wtforms.validators import DataRequired, InputRequired, Email, Length, Regexp, Optional, EqualTo, ValidationError
from flask_sqlalchemy  import SQLAlchemy, BaseQuery
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_migrate import Migrate

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError,
)
from werkzeug.routing import BuildError
from flask_mail import Mail, Message
from functools import wraps
from flask_principal import Principal, RoleNeed, UserNeed, Permission, Identity, identity_changed, identity_loaded, AnonymousIdentity
from werkzeug.utils import cached_property


app = Flask(__name__)
app.config['SECRET_KEY'] = '6&GhN4$qAo68-jE+_xY3erty69dpdof*3gdfgfgdjfjekesaassasaas4$'
app.config['SECURITY_PASSWORD_SALT'] ='9HDg49$=_QKHWPYNKRHjnthro903jxidjshñkñjkhshsqj47-'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://PLJlQvbfL9:Pf4IB3DyTM@remotemysql.com/PLJlQvbfL9"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True, "pool_recycle": 300}
app.config['WHOOSH_BASE'] = '/home/georgeboy/jose-project/whoosh'
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

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)
#wa.whoosh_index(app, Clientes)


class Usuarios(UserMixin, db.Model):
    __tablename__ = "usuarios"

    admin = 1
    member = 0
    
    id = db.Column(db.Integer, primary_key=True)
    nombres = db.Column(db.String(80), nullable=False)
    apellidos = db.Column(db.String(80), nullable=False)
    correo = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)
    registrado_en = db.Column(db.DateTime, nullable=False)
    role = db.Column(db.Boolean, nullable=False, default=False)
    confirmado = db.Column(db.Boolean, nullable=False, default=False)
    confirmado_en = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String, nullable=True)


    
    def __repr__(self):
        return '<Usuarios %r>' % self.correo



class Clientes(db.Model):
  
    __tablename__ = "clientes"


    id = db.Column(db.Integer, primary_key=True)
    nombres = db.Column(db.String(80), nullable=False)
    apellidos = db.Column(db.String(80), nullable=False)
    correo = db.Column(db.String(120), nullable=False)
    empresa = db.Column(db.String(120), nullable=False)
    celular = db.Column(db.String(50), nullable=False)
    mensaje = db.Column(db.String(500), nullable=False)
    checkbox = db.Column(db.Boolean, nullable=False)
    cotizaciones = db.relationship('Cotizacion', backref='clientes_cotizan', lazy=True)
    solicitudes = db.relationship('Solicitud', backref='sol_client', lazy=True)

    
    

    def __init__(self, nombres, apellidos, correo, empresa, celular, mensaje, checkbox, sol_client):
        
        self.nombres = nombres
        self.apellidos = apellidos
        self.correo = correo
        self.empresa = empresa
        self.celular = celular
        self.mensaje = mensaje
        self.checkbox = checkbox
        self.sol_client = sol_client
        
        
    

    def __repr__(self):
        return '<Clientes %r>' % self.id


class Solicitud(db.Model):
    __tablename__ = "solicitud"

    id = db.Column(db.Integer, primary_key=True)
    
    servicio_campo = db.Column(db.String(120), nullable=False)
    asesore = db.Column(db.String(120), nullable=False)

     # LLAVE FORANEA
    solicitud_cliente = db.Column(db.Integer, db.ForeignKey("clientes.id"), nullable=True)

    

    def __init__(self, servicio_campo, asesore, sol_client):
       
        self.servicio_campo = servicio_campo
        self.asesore = asesore
        self.sol_client = sol_client
       



class Cotizacion(db.Model):
    __tablename__ = "cotizacion"

    id = db.Column(db.Integer, primary_key=True)
    numero_personas = db.Column(db.Integer, nullable=False)
    valor_personas = db.Column(db.Integer, nullable=False)
    numero_horas = db.Column(db.Integer, nullable=False)
    valor_hora = db.Column(db.Integer, nullable=False)
    descuento = db.Column(db.Integer, nullable=False)

    # LLAVE FORANEA
    cliente_id = db.Column(db.Integer, db.ForeignKey("clientes.id"), nullable=True)
    
    

    def __init__(self, numero_personas, valor_personas, numero_horas, valor_hora, descuento, clientes_cotizan):
        self.numero_personas = numero_personas
        self.valor_personas = valor_personas
        self.numero_horas = numero_horas
        self.valor_hora = valor_hora
        self.descuento = descuento
        self.clientes_cotizan = clientes_cotizan
      
       

    def __repr__(self):
        return '<Cotizacion %r>' % self.id





class Servicio(db.Model):
    __tablename__ = "servicio"

    id = db.Column(db.Integer, primary_key=True)
    nombre_servicio = db.Column(db.String(120), nullable=False)
    costo_servicio = db.Column(db.Integer, nullable=False)
    


    def __init__(self, nombre_servicio, costo_servicio, service_client):
        self.nombre_servicio = nombre_servicio
        self.costo_servicio = costo_servicio
        self.service_client = service_client
        
        


class Asesor(db.Model):
    __tablename__ = "asesor"

    id = db.Column(db.Integer, primary_key=True)
    primernombre_asesor = db.Column(db.String(120), nullable=False)
    apellido_asesor = db.Column(db.String(120), nullable=False)
    correo_asesor = db.Column(db.String(150), nullable=False)

   

    def __init__(self, primernombre_asesor, apellido_asesor, correo_asesor, asesor_client):
        self.primernombre_asesor = primernombre_asesor
        self.apellido_asesor = apellido_asesor
        self.correo_asesor = correo_asesor
        self.asesor_client = asesor_client


class form_solicitudes(FlaskForm):

    
    servicio_campo = SelectField('Selecciona el servicio', choices=[])

    
    asesore = SelectField('Selecciona un asesor', choices=[])
    
    numero_solicitud = IntegerField('Número de Solicitud', validators=[DataRequired(message='Campo Mandatorio'), Length(min=0, max=100000, message="")])

    submit = SubmitField('Crear Solicitud')

    def __init__(self, numero_solicitud):
        super(form_solicitudes, self).__init__()
        self.servicio_campo.choices=[(c.nombre_servicio) for c in Servicio.query.all()]
        self.asesore.choices=[(c.primernombre_asesor) for c in Asesor.query.all()]
        self.numero_solicitud=numero_solicitud



class form_servicios(FlaskForm):
    
        
    nombre_servicio = StringField("Ingresa el nombre del servicio a incluir", validators=[InputRequired(), Email(message="Nombre de servicio inválido, por favor intenta nuevamente"), Length(min=1, max=120)])
    costo_servicio = IntegerField('Ingresa el costo del servicio', validators=[DataRequired(message='Campo Mandatorio'), Length(min=0, max=100000, message="")])

    submit = SubmitField('Crear Servicio')

class creacion_Asesor(FlaskForm):
    
    primernombre_asesor = StringField('Nombres',
        validators=[
            InputRequired(),
            Length(2, 80, message="Por favor ingresa un nombre válido mayor a 2 caracteres"),
        ]
    )
    apellido_asesor = StringField('Apellidos',
        validators=[
            InputRequired(),
            Length(2, 80, message="Por favor ingresa un apellido válido mayor a 2 caracteres"),
        ]
    )
    correo_asesor = StringField("Correo", validators=[InputRequired(), Email(message="Correo Inválido, por favor intenta nuevamente"), Length(min=1, max=120)])
    
    submit = SubmitField('Crear Asesor')


class creacion_Cotizacion(FlaskForm):

    numero_personas = IntegerField('Número total de personas', validators=[DataRequired(message='Campo Mandatorio'), Length(min=0, max=100000, message="")])
    valor_personas = IntegerField('Valor por persona', validators=[DataRequired(message='Campo Mandatorio'), Length(min=0, max=100000, message="")])
    numero_horas = IntegerField('No de horas', validators=[DataRequired(message='Campo Mandatorio'), Length(min=0, max=100000, message="")])
    valor_hora = IntegerField('Valor por hora', validators=[DataRequired(message='Campo Mandatorio'), Length(min=0, max=100000, message="")])
    descuento = IntegerField('Ingrese el % de descuento', validators=[DataRequired(message='Campo Mandatorio'), Length(min=0, max=100000, message="")])
        
    submit = SubmitField('Crear Cotizacion')


class form_clientes(FlaskForm):
   

    nombres = StringField('Nombres',
        validators=[
            InputRequired(),
            Length(3, 80, message="Por favor ingresa un nombre válido"),
        ]
    )
    
    apellidos = StringField('Apellidos',
        validators=[
            InputRequired(),
            Length(3, 80, message="Por favor ingresa un apellido válido"),
        ]
    )

  
    
    correo = StringField("Correo", validators=[InputRequired(), Email(message="Correo Inválido, por favor intenta nuevamente"), Length(min=1, max=120)])
    
    empresa = StringField('Empresa',
        validators=[
            InputRequired(),
            Length(3, 120, message="Por favor ingresa un nombre de empresa válido"),
        ]
    )

    celular = StringField("Celular", validators=[DataRequired(message='Campo Mandatorio'), Length(min=10, max=30, message="Lo sentimos, el número de celular ingresado es inválido, no debe ser menor a 10 dígitos")])

    mensaje = TextAreaField("Ingresa tu mensaje", validators=[DataRequired(message='Oops, este campo es mandatorio'), Length(min=1, max=500, message="Lo sentimos, Has superado el límite máximo de 500 caracteres")])

    checkbox = BooleanField("Sí, Me gustaría recibir comunicaciones de Sanwise SAS sobre los servicios ofrecidos que pudieran ser de interés para mí. Dando click abajo, estoy de acuerdo con la política de tratamiento de datos y privacidad de Sanwise SAS")
    
    submit = SubmitField('Enviar')





class form_login(FlaskForm):
    nombres = StringField(
        validators=[Optional()]
    )
    apellidos = StringField(
        validators=[Optional()]
    )
    correo = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    password = PasswordField('Contraseña', validators=[InputRequired(), Length(min=8, max=72)])
    submit = SubmitField('Continuar')



#Clase para crear formulario de registro

class formRegistro(FlaskForm):
    nombres = StringField('Nombres',
        validators=[
            InputRequired(),
            Length(3, 20, message="Por favor ingrese un nombre válido"),
        ]
    )
    
    apellidos = StringField('Apellidos',
        validators=[
            InputRequired(),
            Length(3, 20, message="Por favor ingrese un dato de apellido válido"),
        ]
    )
    correo = StringField(validators=[InputRequired(), Email(message="Correo Inválido"), Length(1, 64)])
    password = PasswordField('Contraseña', validators=[InputRequired(), Length(8, 72, message="La contraseña debe tener al menos 8 caracteres y máximo 72 de longitud")])
    cpassword = PasswordField('Confirma tu contraseña', validators=[InputRequired(), Length(8, 72), EqualTo("password", message="Las contraseñas no coinciden")])
    submit = SubmitField('Registrar datos')

    def validate_email(self, correo):
        if Usuarios.query.filter_by(correo=correo.data).first():
            raise ValidationError("Email already registered!")


#clase formulario de recordar password

class correoForm(FlaskForm):
    correo = StringField(validators=[InputRequired(), Email(message="Correo Inválido"), Length(1, 64)])
    submit = SubmitField('Cambiar Password')

class formResetPassword(FlaskForm):
    password = PasswordField('Contraseña', validators=[InputRequired(), Length(8, 72, message="La contraseña debe tener al menos 8 caracteres y máximo 72 de longitud")])
    cpassword = PasswordField('Confirma tu contraseña', validators=[InputRequired(), Length(8, 72), EqualTo("password", message="Las contraseñas no coinciden")])
    submit = SubmitField('Reiniciar Password')


# clase para crear formulario creacion de admin users

class creacion_Usuario(FlaskForm):
    nombres = StringField('Nombres',
        validators=[
            InputRequired(),
            Length(3, 20, message="Por favor ingrese un nombre válido"),
        ]
    )
    
    apellidos = StringField('Apellidos',
        validators=[
            InputRequired(),
            Length(3, 20, message="Por favor ingrese un dato de apellido válido"),
        ]
    )
    role = SelectField('Rol', choices=[(''),('1'),('0')])
    registrado_en=DateTimeField('Registrado en', format='%Y-%m-%d %H:%M:%S', validators=[validators.DataRequired()])
    confirmado=SelectField('Rol', choices=[(''),('1'),('0')])
    confirmado_en=DateTimeField('Registrado en', format='%Y-%m-%d %H:%M:%S')
    correo = StringField(validators=[InputRequired(), Email(message="Correo Inválido"), Length(1, 64)])
    password = PasswordField('Contraseña', validators=[InputRequired(), Length(8, 72, message="La contraseña debe tener al menos 8 caracteres y máximo 72 de longitud")])
    cpassword = PasswordField('Confirma tu contraseña', validators=[InputRequired(), Length(8, 72), EqualTo("password", message="Las contraseñas no coinciden")])
    submit = SubmitField('Crear')

    def validate_email(self, correo):
        if Usuarios.query.filter_by(correo=correo.data).first():
            raise ValidationError("Email already registered!")


class creacion_Cliente(FlaskForm):
    

    nombres = StringField('Nombres',
        validators=[
            InputRequired(),
            Length(3, 20, message="Por favor ingrese un nombre válido"),
        ]
    )
    
    apellidos = StringField('Apellidos',
        validators=[
            InputRequired(),
            Length(3, 20, message="Por favor ingrese un dato de apellido válido"),
        ]
    )
    correo = StringField(validators=[InputRequired(), Email(message="Correo Inválido"), Length(1, 64)])
    empresa = StringField(validators=[InputRequired(), Length(3, 120, message="El dato empresa debe tener al menos 8 caracteres y max 120 de longitud")])
    celular = StringField("Celular", validators=[DataRequired(message='Campo Mandatorio'), Length(min=10, max=30, message="Lo sentimos, el número de celular ingresado es inválido, no debe ser menor a 10 dígitos")])
    mensaje = TextAreaField("Ingresa tu mensaje", validators=[DataRequired(message='Oops, este campo es mandatorio'), Length(min=1, max=500, message="Lo sentimos, Has superado el límite máximo de 500 caracteres")])
    checkbox = BooleanField("Sí, Me gustaría recibir comunicaciones de Sanwise SAS sobre los servicios ofrecidos que pudieran ser de interés para mí. Dando click abajo, estoy de acuerdo con la política de tratamiento de datos y privacidad de Sanwise SAS")
    submit = SubmitField('Crear')

#Mantiene el objeto user cargado en la sesion basado en el id almacenado
@login_manager.user_loader
def load_user(user_id):
    return Usuarios.query.get(int(user_id))  

@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)



def check_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.confirmado is False:
            flash('Por favor confirma tu cuenta', 'warning')
            return redirect(url_for('unconfirmed'))
        return func(*args, **kwargs)

    return decorated_function
        
@app.route('/inicio', methods=("GET", "POST"))
def inicio():
    return render_template("inicio.html")

@app.route('/olvidopassword', methods=("GET","POST"))
def olvidopassword():
    form = correoForm(request.form)
    if form.validate_on_submit():
        user = Usuarios.query.filter_by(correo=form.correo.data).first()
        token = generate_confirmation_token(user.correo)
        user.password_reset_token = token
        db.session.commit()
        reset_url = url_for('olvidopassnuevo', token=token, _external=True)
        msg = Message(subject="Cambia tu contraseña", recipients=[form.correo.data])
        msg.html = render_template('email-reset.html', **request.form, reset_url=reset_url)
        mail.send(msg)
        flash('Correo para reinicio de contraseña fue enviado a su correo electrónico', 'success')
        return redirect(url_for('login'))
    return render_template('reset.html', form=form)

@app.route('/olvidopassword/nuevo/<token>', methods=['GET', 'POST'])
def olvidopassnuevo(token):
    correo = confirm_token(token)
    user = Usuarios.query.filter_by(correo=correo).first_or_404()

    if user.password_reset_token is not None:
        form = formResetPassword(request.form)
        if form.validate_on_submit():
            user = Usuarios.query.filter_by(correo=correo).first()
            if user:
                user.password = generate_password_hash(form.password.data)
                user.password_reset_token = None
                db.session.commit()
                login_user(user)
                flash('Tu Contraseña ha sido cambiada con éxito', 'success')
                return redirect(url_for('login'))
            else:
                flash('Cambio de contraseña no fue exitoso', 'danger')
                return redirect(url_for('login'))
    else:
        flash('No fue posible reiniciar su password, por favor intenta de nuevo', 'danger')
    return redirect(url_for('login'))

@app.route('/homecrm', methods=("GET", "POST"))
@login_required
@check_confirmed
def homecrm():
    return render_template("profile.html", nombres=current_user.nombres, correo=current_user.correo, role=current_user.role)


@app.route('/', methods=["GET", "POST"])
def index():
    form = form_clientes(request.form)

    if form.validate_on_submit() and form.validate():
       
        servicios = form.servicios.data
        nombres = form.nombres.data
        apellidos = form.apellidos.data
        correo = form.correo.data
        empresa = form.empresa.data
        celular = form.celular.data
        mensaje = form.mensaje.data
        checkbox = form.checkbox.data
        nuevoCliente = Clientes(servicios, nombres, apellidos, correo, empresa, celular, mensaje, checkbox)
        db.session.add(nuevoCliente)
        db.session.commit()
        messages = flash('Tus datos ha sido registrados exitosamente!')
        msg = Message(subject="Te damos la bienvenida a Sanwise", recipients=[form.correo.data], cc=['jorge.romero.saray@gmail.com'])
        msg.html = render_template('correoiniciocliente.html', **request.form)
        mail.send(msg)
        return render_template('contactformgreetings.html', form=form, messages=messages,)
    return render_template('index.html', form=form)

@app.route('/login', methods=("GET", "POST"))
def login():
    form = form_login()
    nombres = form.nombres.data

    if form.validate_on_submit():
        try:
            user = Usuarios.query.filter_by(correo=form.correo.data).first()
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('homecrm', nombres=nombres))
            else:
                flash("Datos de usuario o password erróneos", "danger")
            

        except Exception as e:
            flash(e,"danger")

    return render_template('login.html', form=form)
    
    

@app.route('/registro', methods=("GET", "POST"))
def registro():
    form = formRegistro(request.form)         
    if form.validate_on_submit():
        try:
            user = Usuarios(nombres=form.nombres.data, apellidos=form.apellidos.data, correo=form.correo.data, registrado_en=datetime.now(), admin=False, confirmado=False, confirmado_en=datetime.now(), password=generate_password_hash(form.password.data, method='sha256'))
            db.session.add(user)
            db.session.commit()
            flash('Cuenta de usuario creada exitosamente!', 'success')
            token = generate_confirmation_token(user.correo)
            confirm_url = url_for('confirm_email', token=token, _external=True)
            msg = Message(subject="Confirma tu correo", recipients=[form.correo.data])
            msg.html = render_template('email-activate.html', **request.form, confirm_url=confirm_url)
            mail.send(msg)
            login_user(user)
            return redirect(url_for('unconfirmed'))
        
        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong!", "danger")

        except IntegrityError:
            db.session.rollback()
            flash(f"Correo ingresado ya existe!.", "warning")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry", "warning")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except DatabaseError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured!", "danger")
    return render_template('registro.html', form=form)

def generate_confirmation_token(correo):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(correo, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        correo = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return correo

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        correo= confirm_token(token)
    except:
        flash('El link de confirmación es inválido o a expirado', 'danger')
    user = Usuarios.query.filter_by(correo=correo).first_or_404()
    if user.confirmado:
        flash('Tu cuenta ha sido confirmada, Por favor inicia tu sesión para continuar', 'success')
        return redirect(url_for('login'))
    else:
        user.confirmado= True
        user.confirmado_en = datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('Tu cuenta ha sido confirmada exitosamente, muchas gracias!', 'success')
    return redirect(url_for('login'))
    
@app.route('/admin')
@login_required
def admin():
    if current_user.role == True:
        return render_template('admin.html')
    else:
        abort(401)

@app.route('/crearusuario', methods=("GET", "POST"))
@login_required
def crearusuario():
    form = creacion_Usuario(request.form)
    user1= Usuarios(
            nombres=form.nombres.data,
            apellidos=form.apellidos.data,
            correo=form.correo.data,
            password=generate_password_hash(form.password.data, method='sha256'),
            role=True,
            registrado_en=datetime.now(),
            confirmado=True,
            confirmado_en=datetime.now())
    if current_user.role == True:
        if request.method == 'POST':
            try:
                db.session.add(user1)
                db.session.commit()
                flash('El usuario ha sido creado exitosamente', 'success')
                return render_template('crearusuario.html', form=form)
            except InvalidRequestError:
                db.session.rollback()
                flash(f"Something went wrong!", "danger")

            except IntegrityError:
                db.session.rollback()
                flash(f"Correo ingresado ya existe!.", "warning")
            except DataError:
                db.session.rollback()
                flash(f"Invalid Entry", "warning")
            except InterfaceError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
            except DatabaseError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
            except BuildError:
                db.session.rollback()
                flash(f"An error occured!", "danger")
    else:
        abort(401)

    return render_template('crearusuario.html', form=form, nombres=current_user.nombres, correo=current_user.correo, role=current_user.role)


#listar asesor

@app.route('/listarasesor')
@login_required
def listarasesor():
    if current_user.role == True:
        asesors= db.session.query(Asesor).all()
        return render_template('listarasesor.html', asesors=asesors, nombres=current_user.nombres, correo=current_user.correo)

#crear asesor
@app.route('/crearasesor', methods=("GET", "POST"))
@login_required
def crearasesor():
    clints = db.session.query(Clientes).filter_by(id=id).first()
    form = creacion_Asesor(request.form)
    crearasesore= Asesor(
            primernombre_asesor=form.primernombre_asesor.data,
            apellido_asesor=form.apellido_asesor.data,
            correo_asesor=form.correo_asesor.data,
            asesor_client = clints
            )
         
    if current_user.role == True:
        if request.method == 'POST':
            db.session.add(crearasesore)
            db.session.commit()
            flash('El Asesor ha sido creado exitosamente!', 'success')
            return redirect(url_for('listarasesor', form=form, clints=clints, nombres=current_user.nombres, correo=current_user.correo, role=current_user.role))
          
    else:
        abort(401)

    return render_template('crearasesor.html', form=form, nombres=current_user.nombres, correo=current_user.correo, role=current_user.role, clints=clints)

# eliminar asesor

@app.route('/listarasesor/eliminar/<int:id>', methods=("GET", "POST"))
@login_required
def eliminarasesor(id):
    borrarAsesor= db.session.query(Asesor).filter_by(id=id).one()
    if current_user.role == True:
        if request.method == 'POST':
            db.session.delete(borrarAsesor)
            db.session.commit()
            message = f"El Asesor ha sido eliminado exitosamente"
            flash(message, 'success')
            return redirect(url_for('listarasesor', borrarAsesor=borrarAsesor, nombres=current_user.nombres, correo=current_user.correo))
    else:
        abort(401)

    return render_template('eliminarasesor.html', borrarAsesor=borrarAsesor, nombres=current_user.nombres, correo=current_user.correo)

# editar asesor

@app.route('/listarasesor/editar/<int:id>', methods=("GET", "POST"))
@login_required
def editarasesor(id):
    form = creacion_Asesor(request.form)
    editarAsesor= db.session.query(Asesor).filter_by(id=id).one()
    if current_user.role == True:
        if request.method == 'POST':
            if request.form['primernombre_asesor']:
                editarAsesor.primernombre_asesor = request.form['primernombre_asesor']
                editarAsesor.apellido_asesor = request.form['apellido_asesor']
                editarAsesor.correo_asesor = request.form['correo_asesor']
            db.session.add(editarAsesor)
            db.session.commit()
            message = f"El Asesor {editarAsesor.primernombre_asesor} ha sido editado exitosamente"
            flash(message, 'success')
           
            return redirect(url_for('listarasesor', editarAsesor=editarAsesor, nombres=current_user.nombres, correo=current_user.correo, id=id))
    else:
        abort(401)

    return render_template('editarAsesor.html', editarAsesor=editarAsesor, nombres=current_user.nombres, correo=current_user.correo, id=id)


#listar servicio

@app.route('/lista_de_servicios')
@login_required
def listarservicios():
    if current_user.role == True:
        serv= db.session.query(Servicio).all()
        return render_template('listarservicio.html', serv=serv, nombres=current_user.nombres, correo=current_user.correo)

#crear servicio
@app.route('/crearservicio', methods=("GET", "POST"))
@login_required
def crearservicio():

    servi = db.session.query(Servicio).filter_by(id=id).first()
    form = form_servicios(request.form)
    crearservice= Servicio(
            nombre_servicio=form.nombre_servicio.data,
            costo_servicio=form.costo_servicio.data,
            service_client = servi
            )
         
    if current_user.role == True:
        if request.method == 'POST':
            db.session.add(crearservice)
            db.session.commit()
            message = f"El Servicio {crearservice.nombre_servicio} ha sido creado exitosamente"
            flash(message, 'success')
            return redirect(url_for('listarservicios',  nombres=current_user.nombres, correo=current_user.correo))
          
    else:
        abort(401)

    return render_template('crearservicio.html', form=form, role=current_user.role)

# eliminar servicio

@app.route('/lista_de_servicios/eliminar/<int:id>', methods=("GET", "POST"))
@login_required
def eliminarservicio(id):
    borrarServicio= db.session.query(Servicio).filter_by(id=id).one()
    if current_user.role == True:
        if request.method == 'POST':
            db.session.delete(borrarServicio)
            db.session.commit()
            message = f"El Servicio ha sido eliminado exitosamente"
            flash(message, 'success')
            return redirect(url_for('listarservicios', borrarServicio=borrarServicio, nombres=current_user.nombres, correo=current_user.correo, id=id))
    else:
        abort(401)

    return render_template('eliminarservicio.html', borrarServicio=borrarServicio, nombres=current_user.nombres, correo=current_user.correo)

# editar asesor

@app.route('/lista_de_servicios/editar/<int:id>', methods=("GET", "POST"))
@login_required
def editarservicio(id):
    form = form_servicios(request.form)
    editarServicio= db.session.query(Servicio).filter_by(id=id).one()
    if current_user.role == True:
        if request.method == 'POST':
            if request.form['nombre_servicio']:
                editarServicio.nombre_servicio = request.form['nombre_servicio']
               
            db.session.add(editarServicio)
            db.session.commit()
            message = f"El Asesor {editarServicio.nombre_servicio} ha sido editado exitosamente"
            flash(message, 'success')
           
            return redirect(url_for('listarservicios', editarServicio=editarServicio, nombres=current_user.nombres, correo=current_user.correo, id=id))
    else:
        abort(401)

    return render_template('editarServicio.html', editarServicio=editarServicio, nombres=current_user.nombres, correo=current_user.correo, id=id)



@app.route('/listarclientes')
@login_required
def listarclientes():
    if current_user.role == True:
        clientes= db.session.query(Clientes).all()
        return render_template('listaclientes.html', clientes=clientes, nombres=current_user.nombres, correo=current_user.correo)

@app.route('/listarclientes/<int:id>/eliminar', methods=("GET", "POST"))
@login_required
def eliminarcliente(id):
    borrarCliente= db.session.query(Clientes).filter_by(id=id).one()
    if current_user.role == True:
        if request.method == 'POST':
            db.session.delete(borrarCliente)
            db.session.commit()
            flash('El usuario ha sido eliminado exitosamente', 'success')
            return redirect(url_for('listarclientes', borrarCliente=borrarCliente, nombres=current_user.nombres, correo=current_user.correo))
    else:
        abort(401)

    return render_template('eliminarcliente.html', borrarCliente=borrarCliente, nombres=current_user.nombres, correo=current_user.correo)

@app.route('/listarclientes/<int:id>/editar', methods=("GET", "POST"))
@login_required
def editarcliente(id):
    editarCliente= db.session.query(Clientes).filter_by(id=id).one()
    form = creacion_Cliente(request.form)
    if current_user.role == True:
        if request.method == 'POST':
            if request.form['nombres']:
                editarCliente.nombres = request.form['nombres']
                editarCliente.apellidos = request.form['apellidos']
                editarCliente.correo = request.form['correo']
                editarCliente.empresa = request.form['empresa']
                editarCliente.celular = request.form['celular']
                db.session.add(editarCliente)
                db.session.commit()
                flash('El usuario ha sido editado exitosamente', 'success')
                return redirect(url_for('listarclientes', editarCliente=editarCliente, nombres=current_user.nombres, correo=current_user.correo, id=id, form=form))
    else:
        abort(401)

    return render_template('editarcliente.html', editarCliente=editarCliente, nombres=current_user.nombres, correo=current_user.correo, id=id, form=form)

@app.route('/crearcliente', methods=("GET", "POST"))
@login_required
def crearcliente():
    clint = db.session.query(Clientes).filter_by(id=id).first()
    form = creacion_Cliente(request.form)
    client= Clientes(
            nombres=form.nombres.data,
            apellidos=form.apellidos.data,
            correo=form.correo.data,
            empresa=form.empresa.data,
            celular=form.celular.data,
            mensaje = form.mensaje.data,
            checkbox = form.checkbox.data,
            sol_client = clint )


    if current_user.role == True:
        if request.method == 'POST':
            try:
                db.session.add(client)
                db.session.commit()
                flash('El cliente ha sido creado exitosamente', 'success')
                return redirect(url_for('listarclientes', form=form))
            except InvalidRequestError:
                db.session.rollback()
                flash(f"Something went wrong!", "danger")

            except IntegrityError:
                db.session.rollback()
                flash(f"Correo ingresado ya existe!.", "warning")
            except DataError:
                db.session.rollback()
                flash(f"Invalid Entry", "warning")
            except InterfaceError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
            except DatabaseError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
            except BuildError:
                db.session.rollback()
                flash(f"An error occured!", "danger")
    else:
        abort(401)

    return render_template('crearcliente.html', form=form, nombres=current_user.nombres, correo=current_user.correo, role=current_user.role)


@app.route('/listarcotizacion')
@login_required
def listarcotizacion():
    if current_user.role == True:
        clientes= db.session.query(Clientes).all()
        return render_template('listacotizacion.html', clientes=clientes, nombres=current_user.nombres, correo=current_user.correo)


@app.route('/listarsolicitud')
@login_required
def listarsolicitud():
    if current_user.role == True:
        clientes= db.session.query(Solicitud.id, Solicitud.servicio_campo, Solicitud.asesore, Clientes.nombres, Clientes.apellidos, Clientes.correo, Clientes.empresa).join(Clientes).all()
      
       
        
        return render_template('listarsolicitudes1.html', clientes=clientes, nombres=current_user.nombres, correo=current_user.correo)

@app.route('/crearsolicitudes')
@login_required
def listarsolicitudes():
    if current_user.role == True:
        clientes= db.session.query(Clientes).all()
        
        return render_template('listarsolicitudes.html', clientes=clientes, nombres=current_user.nombres, correo=current_user.correo)


@app.route('/crearsolicitudes/crear/<int:id>', methods=("GET", "POST"))
@login_required
def crearsolicitud(id):
    
    client = (db.session.query(Clientes).filter_by(id=id).one())
    form = form_solicitudes(request.form)
    

    if current_user.role == True:
        
        if request.method == 'POST':
            

            solicitan = Solicitud(
              
                servicio_campo = form.servicio_campo.data,
                asesore = form.asesore.data,
                sol_client = client
                )
            
            
            print(solicitan)
            db.session.add(solicitan)
            db.session.commit()
            message = f"La solicitud {solicitan.id} ha sido creada exitosamente"
            flash(message, 'success')
            return redirect(url_for('listarsolicitud', client=client, id=id, form=form, nombres=current_user.nombres, correo=current_user.correo, role=current_user.role,))
            
    else:
        abort(401)

    return render_template('crearsolicitudes.html', nombres=current_user.nombres, correo=current_user.correo, role=current_user.role, id=id, client=client, form=form)



@app.route('/cotizaciones/crear/<int:id>', methods=("GET", "POST"))
@login_required
def crearcotizacion(id):
    client = (db.session.query(Clientes).filter_by(id=id).one())
    
    form = creacion_Cotizacion(request.form)


    if current_user.role == True:
        
        if request.method == 'POST':

            cotizan = Cotizacion(
            numero_personas=form.numero_personas.data,
            valor_personas=form.valor_personas.data,
            numero_horas=form.numero_horas.data,
            valor_hora=form.valor_hora.data,
            descuento=form.descuento.data,
            clientes_cotizan = client
            )
            
            db.session.add(cotizan)
            db.session.commit()
            flash('La cotización ha sido creado exitosamente', 'success')
            return render_template('crearcotizacion.html', client=client, form=form, id=id)
            
    else:
        abort(401)

    return render_template('crearcotizacion.html', nombres=current_user.nombres, correo=current_user.correo, role=current_user.role, id=id, client=client, form=form)

@app.route('/listarusuarios')
@login_required
def listarusuarios():
    if current_user.role == True:
        users= db.session.query(Usuarios).all()
        return render_template('listausuarios.html', users=users, nombres=current_user.nombres, correo=current_user.correo)



@app.route('/listarusuarios/<int:id>/eliminar', methods=("GET", "POST"))
@login_required
def eliminarusuario(id):
    borrarUser= db.session.query(Usuarios).filter_by(id=id).one()
    if current_user.role == True:
        if request.method == 'POST':
            db.session.delete(borrarUser)
            db.session.commit()
            flash('El usuario ha sido eliminado exitosamente', 'success')
            return redirect(url_for('listarusuarios', borrarUser=borrarUser, nombres=current_user.nombres, correo=current_user.correo))
    else:
        abort(401)

    return render_template('eliminarusuarios.html', borrarUser=borrarUser, nombres=current_user.nombres, correo=current_user.correo)

@app.route('/listarusuarios/<int:id>/editar', methods=("GET", "POST"))
@login_required
def editarusuario(id):
    editarUser= db.session.query(Usuarios).filter_by(id=id).one()
    if current_user.role == True:
        if request.method == 'POST':
            if request.form['nombres']:
                editarUser.nombres = request.form['nombres']
                editarUser.apellidos = request.form['apellidos']
                editarUser.correo = request.form['correo']
                #editarUser.role = request.form['rol']
                db.session.add(editarUser)
                db.session.commit()
                flash('El usuario ha sido editado exitosamente', 'success')
                return redirect(url_for('listarusuarios', editarUser=editarUser, nombres=current_user.nombres, correo=current_user.correo, id=id))
    else:
        abort(401)

    return render_template('editarusuarios.html', editarUser=editarUser, nombres=current_user.nombres, correo=current_user.correo, id=id)


@app.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.confirmado:
        return redirect('login')
    flash('Por favor confirma tu cuenta para poder ingresar!', 'warning')
    return render_template('unconfirmed.html')

@app.route("/logout")
def logout():
    logout_user()
    message = f"Has cerrado la sesión exitosamente"
    flash(message, "success")
    return redirect(url_for('login')) 

@app.route('/reenviar')
@login_required
def reenviar_Confirmacion():
    token= generate_confirmation_token(current_user.correo)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    msg = Message(subject="Confirma tu correo", recipients=[current_user.correo])
    msg.html = render_template('email-activate.html', **request.form, confirm_url=confirm_url)
    mail.send(msg)
    flash('Un nuevo correo de confirmacion fue enviado', 'success')
    return redirect(url_for('unconfirmed'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template("error.html", error="Página no encontrada..."), 404 

@app.errorhandler(401)
def unauthorized(e):
    flash('Usted no está autorizado para ingresar a esa página', 'danger')
    return redirect(url_for('login', next=request.path))


if __name__ == "__main__":
    app.run(debug=True)
