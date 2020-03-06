import datetime

from flask import Flask, render_template, request, make_response, session, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from werkzeug.utils import redirect
from wtforms import PasswordField, StringField, TextAreaField, SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired

import user_api
from data import db_session
from data.users import User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=365)
db_session.global_init("db/blogs.sqlite")

login_manager = LoginManager()
login_manager.init_app(app)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/login")

@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        s = db_session.create_session()
        if not s.query(User).filter(User.email == form.email.data).first():
            return render_template('login.html', title='Login',
                                   form=form,
                                   message="No such person found")
        user = s.query(User).filter(User.email == form.email.data).first()
        if user.check_password(form.password.data):
            login_user(user)
            if 'svisits' in session:
                session['svisits'] = session.get('svisits')+1
            else:
                session['svisits'] = 1
            visits = int(request.cookies.get('visits',0))
            if visits:
                visits+=1
            else:
                visits=1
            ans = make_response(render_template('/logged_in.html', visit_count=visits, v=session['svisits']))
            ans.set_cookie('visits',str(visits))
            return ans
        return render_template('login.html', title='Login',
                               form=form,
                               message="incorrect password")
    return render_template('login.html', title='Login', form=form)

@app.route('/', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('index.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        session = db_session.create_session()
        if session.query(User).filter(User.email == form.email.data).first():
            return render_template('index.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User(
            name=form.name.data,
            email=form.email.data,
            about=form.about.data
        )
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        return redirect('/login')
    return render_template('index.html', title='Регистрация', form=form)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

def main():

    app.register_blueprint(user_api.blueprint)
    app.run()

class RegisterForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password_again = PasswordField('Повторите пароль', validators=[DataRequired()])
    name = StringField('Имя пользователя', validators=[DataRequired()])
    about = TextAreaField("Немного о себе")
    submit = SubmitField('Войти')

class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

if __name__ == '__main__':
    main()