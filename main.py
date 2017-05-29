
import datetime
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_security import current_user, login_required, RoleMixin, Security, \
    SQLAlchemyUserDatastore, UserMixin, utils
from flask_admin import Admin
from flask_admin.contrib import sqla

from wtforms.fields import PasswordField

from flask_security.forms import LoginForm
from wtforms import StringField
from wtforms.validators import InputRequired


app = Flask(__name__)
app.config['DEBUG']=True
app.config['SECRET_KEY'] = 'super-secret'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://jekanchik:literbolik@localhost/flask_test'
app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = ('email', 'username')

app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
app.config['SECURITY_PASSWORD_SALT'] = 'qwertyqwerty'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True


db = SQLAlchemy(app)

# Create a table to support a many-to-many relationship between Users and Roles
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


# Role class
class Role(db.Model, RoleMixin):
    '''Our Role has three fields, ID, name and description'''
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash(self.name)


# User class
class User(db.Model, UserMixin):
    '''Our User has six fields: ID, email, password, active, confirmed_at and roles. The roles field represents a
    many-to-many relationship using the roles_users table. Each user may have no role, one role, or multiple roles.'''
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column('confirmed_at', db.DateTime, default=datetime.datetime.now)
    roles = db.relationship(
        'Role',
        secondary=roles_users,
        backref=db.backref('users', lazy='dynamic')
    )

class ExtendedLoginForm(LoginForm):
    email = StringField('Username', [InputRequired()])

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, login_form=ExtendedLoginForm)


# Executes before the first request is processed.
@app.before_first_request
def before_first_request():

    # Create any database tables that don't exist yet.
    db.create_all()

    # Create the Roles "admin" and "end-user" -- unless they already exist
    user_datastore.find_or_create_role(name='admin', description='Administrator')
    user_datastore.find_or_create_role(name='end-user', description='End user')

    # Create two Users for testing purposes -- unless they already exists.
    # In each case, use Flask-Security utility function to encrypt the password.
    
    if not user_datastore.get_user('test'):
        encrypted_password = utils.encrypt_password('test')
        user_datastore.create_user(username='test', email='test@example.com', password=encrypted_password)
    if not user_datastore.get_user('admin'):
        encrypted_password = utils.encrypt_password('admin')
        user_datastore.create_user(username='admin', email='admin@example.com', password=encrypted_password)

    # Commit any database changes; the User and Roles must exist before we can add a Role to the User
    db.session.commit()

    # Give one User has the "end-user" role, while the other has the "admin" role. (This will have no effect if the
    # Users already have these Roles.) Again, commit any database changes.
    # import ipdb; ipdb.set_trace()
    user_datastore.add_role_to_user(user_datastore.get_user('test'), 'end-user')
    user_datastore.add_role_to_user(user_datastore.get_user('admin'), 'admin')
    db.session.commit()


#  home page.
@app.route('/')
@login_required
def index():
    return render_template('index.html')


class UserAdmin(sqla.ModelView):

    # Don't display the password on the list of Users
    column_exclude_list = ('password',)

    # Don't include the standard password field when creating or editing a User (but see below)
    form_excluded_columns = ('password',)

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    # Prevent administration of Users unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

    def scaffold_form(self):
        form_class = super(UserAdmin, self).scaffold_form()
        form_class.password2 = PasswordField('New Password')
        return form_class

    def on_model_change(self, form, model, is_created):
        if len(model.password2):
            model.password = utils.encrypt_password(model.password2)


class RoleAdmin(sqla.ModelView):

    def is_accessible(self):
        return current_user.has_role('admin')

admin = Admin(app)

admin.add_view(UserAdmin(User, db.session))
admin.add_view(RoleAdmin(Role, db.session))


if __name__ == '__main__':
    app.run(
        host='localhost',
        port=int('5000'),
        debug=app.config['DEBUG']
    )
