from flask import Flask, url_for, render_template, request, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from sqlalchemy.orm import Session

from werkzeug.security import check_password_hash, generate_password_hash

import os

from myconfig import data_config

app = Flask(__name__, static_url_path='')
app.secret_key = "*"

with app.test_request_context():

    static_files_names = []
    for static_file in os.walk('static'):
        static_files_names.extend(static_file[2])

    [url_for('static', filename=it) for it in static_files_names]

app.config["SQLALCHEMY_DATABASE_URI"] = data_config["URL_CONFIG"]

db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    login = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(200), nullable = False)

    chats = db.Column(db.JSON)

    def __init__(self, name, login, password):
        self.name = name
        self.login = login
        self.password = password


class Chat(db.Model):
    chat_id = db.Column(db.Integer, primary_key = True)
    chat_name = db.Column(db.String(20), nullable = False)
    chat_password = db.Column(db.String(20))


class Messages(db.Model):
    message_id = db.Column(db.Integer, primary_key = True)
    data_json = db.Column(db.JSON)
    sender = db.Column(db.String(20), nullable = False)
    date_time = db.Column(db.DATETIME, nullable = False)
    message_chatId = db.Column(db.Integer, nullable = False)


manager = LoginManager(app)
with app.app_context():
    db.create_all()


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# @app.route("/")
# def hui():
#     return render_template('hui.html')


@app.route("/")
@login_required
def main():
    return render_template("Chats.html")


@app.route("/login", methods=['GET'])
def login():
    return render_template("Login.html")


@app.route("/login", methods=['POST'])
def log_in():
    __login = request.form.get('login')
    __password = request.form.get('password')
    print(__login, __password)

    user = User.query.filter_by(login=__login).first()
    if not(__login and __password):
        flash('Login or password is not entered')
        return render_template("Login.html")
    elif not user:
        flash('Login or password is not correct')

    elif check_password_hash(user.password, __password):
        login_user(user)
        return redirect(url_for("main"))
    else:
        flash('Login or password is not correct')

    return render_template("Login.html")


@app.route("/registration", methods=['POST'])
def registration_POST():
    __name = request.form.get('name')
    __login = request.form.get('login')
    __password = request.form.get('password')
    __rpassword = request.form.get('rpassword')
    print (__login, __password, __rpassword)

    user = User.query.filter_by(login=__login).first()
    if not (__login and __password and __password):
        flash("Не заполнены поля")
    elif (user):
        flash("Данный логин уже существует")
    elif not(__password == __rpassword):
        flash("Пароли не совпадают")
    else:
        __name = ''
        hash_pwd = generate_password_hash(__password)
        new_User = User(__name, __login, hash_pwd)
        db.session.add(new_User)
        db.session.commit()

        return redirect('login')
    return render_template("Registration.html")


@app.route("/registration", methods=['GET'])
def registration_GET():
    return render_template("Registration.html")


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login'))

    return response


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10)
