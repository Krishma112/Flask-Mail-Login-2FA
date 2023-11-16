from flask import *
from flask_bootstrap import Bootstrap
from flask_login import *
from flask_migrate import *
import pyotp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
from pathlib import Path
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from Models.db import *

app = Flask(__name__, static_folder="static")


# obslugiwanie managera uzytkownikow
login_manager = LoginManager(app)
# powrot do danej strony w przypadku denial of access
login_manager.login_view = "/login"
login_manager.login_message = "Please log in"
login_manager.login_message_category = "warning"


@login_manager.user_loader # znajdowanie uzytkownika na podstawie jego id przez flask
def load_user(user_id):
    # user = db.session.query(User).get(int(user_id))
    user = User.query.filter_by(id=user_id).first()
    # user = User.get_by_id(user_id)
    if user:
        return user
    else:
        return None


login_manager.init_app(app)

# koniec inicjalizacji managera

# obsluga maila

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'pracainzynierska097@gmail.com'
app.config['MAIL_PASSWORD'] = 'aeyk zrax fgvo fbgq'
app.config['MAIL_DEFAULT_SENDER'] = 'pracainzynierska097@gmail.com'

mail = Mail(app)


def send_confirmation_email(user):
    confirmation_url = url_for('confirm_email', confirmation_code=user.confirmation_code, _external=True)

    msg = Message('Potwierdzenie e-maila', recipients=[user.email])
    msg.body = f'Aby potwierdzić swój e-mail, kliknij w poniższy link:\n\n{confirmation_url}'
    msg.html = f'Aby potwierdzić swój e-mail, kliknij w <a href="{confirmation_url}">ten link</a>.'

    mail.send(msg)


def send_password_reset_email(user):
    user.login_code = secrets.token_urlsafe(16)
    db.session.commit()
    reset_url = url_for('password_redirect', login_code = user.login_code, _external=True)

    msg = Message('Reset your password', recipients=[user.email])
    msg.body = f'Click on this link to reset your password: \n{reset_url}'
    mail.send(msg)


def send_password_reset_notification(user):
    msg = Message('Your password has been changed', recipients=[user.email])
    msg.body = f'We inform you that your password has been changed'
    mail.send(msg)


def send_confirmation_code(user):
    confirmation_code = secrets.token_urlsafe(16)
    user.login_code = confirmation_code
    db.session.commit()

    msg = Message('Confirmation code', recipients=[user.email])
    msg.body = f'Copy your confirmation code: \n{confirmation_code}'
    mail.send(msg)

# koniec obslugi maila


app.config["SECRET_KEY"] = "APP_SECRET_KEY"
Bootstrap(app)
# sciezka do katalogu projektu
p_dir = Path(__file__).resolve().parent
# sciezka do bazy danych
database_uri = f"sqlite:///{p_dir}/Models/database.db"
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri

# inicjalizowanie bazy danych
db.init_app(app)
# with app.app_context():
# db.create_all()
migrate = Migrate(app, db)


@app.route('/')
def home():
    return render_template("home.html")

# czesc dotyczaca redirectow od maili
@app.route('/confirm_email/<confirmation_code>')
def confirm_email(confirmation_code):
    user = User.query.filter_by(confirmation_code=confirmation_code).first()
    if user:
        user.email_confirmed = True
        user.confirmation_code = None
        db.session.commit()
        flash('Twój adres e-mail został potwierdzony.', 'success')
        return redirect(url_for('login'))
    else:
        flash('Nieprawidłowy kod potwierdzający.', 'danger')
        return redirect(url_for('login'))


@app.route('/password_redirect/<login_code>')
def password_redirect(login_code):
    user = User.query.filter_by(login_code=login_code).first()
    if user:
        user.login_code = None
        db.session.commit()
        flash('Wprowadzony kod jest poprawny', 'success')
        return redirect(url_for('reset_password', user_id=user.id))
    else:
        flash('nieprawidlowy kod potwierdzajacy', 'danger')
        return redirect(url_for('login'))

# koniec redirectow


# czesc dotyczaca zarzadzania swoimi danymi i wysylanie maili

@app.route('/login/send_email_confirmation', methods=["GET" , "POST"])
def send_email_confirmation():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash("Email does not exist", "danger")
            return redirect(url_for("send_email_confirmation"))
        elif user.confirmation_code is None:
            flash("your email has been already confirmed", "danger")
            return redirect(url_for("send_email_confirmation"))
        else:
            send_confirmation_email(user)
            flash("Your confirmation email has been sent", "success")
            return redirect(url_for("login"))
    return render_template("email_confirmation.html")


@app.route('/fpassword', methods=["GET", "POST"])
def fpassword():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash("Email does not exist", "danger")
            return redirect(url_for("fpassword"))
        else:
            send_password_reset_email(user)
            flash("Confirmation email has been sent. Please check your email", "success")
            return redirect(url_for("fpassword"))

        # send email about changing password -> then 2FA this change. Either 2fa code before sending or secret question
        # depending on users choice of settings. (anyway 2FA must have - reconeissance danger)

    return render_template("fpassword.html")


@app.route('/reset_password/<user_id>', methods=["GET", "POST"])
def reset_password(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        flash('blad, nieprawidlowy uzytkownik', 'danger')
        return redirect(url_for('login'))
    if request.method == "POST":
        password = request.form.get("password")
        cpassword = request.form.get("cpassword")
        if password == cpassword:
            user.password = generate_password_hash(password)
            db.session.commit()

            send_password_reset_notification(user)
            flash('your password has been changed, please log in', 'success')
            return redirect(url_for('login'))
        else:
            flash("Password dont match", 'danger')
            return render_template('reset_password.html', user_id=user.id)
    return render_template('reset_password.html', user_id=user.id)

@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        cpassword = request.form.get("cpassword")


        # wyszukanie uzytkownika w bazie
        user = User.query.filter_by(username=username).first()
        if user:
            flash("Username is already taken", "danger")
            return redirect(url_for("signup"))

        user = User.query.filter_by(email=email).first()
        if user:
            flash("email is already taken", "danger")
            return redirect(url_for("signup"))

        if password == cpassword:
            # zapisywanie w bazie danych
            new_user = User(username=username, email=email, password=password)

            db.session.add(new_user)
            db.session.commit()
            send_confirmation_email(new_user)
            flash("Your account has been created, please confirm your email to login", "success")
            return redirect(url_for("login"))
        else:
            flash("Password dont match", "danger")
    return render_template("signup.html")



# koniec zarzadzania danymi


# czesc dotyczaca logowania

@app.route('/login/')
def login():
    return render_template("login.html")


@app.route('/login/', methods=["POST"])
def login_form():
    # credentials = {"username": "pudzian", "password": "password"}
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # wyszukanie uzytkownika w bazie
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash("invalid login credentials", "danger")
            return redirect(url_for("login"))

        # sprawdzenie, czy e-mail użytkownika został potwierdzony
        if not user.email_confirmed:
            flash("Please confirm your email before logging in", "warning")
            return redirect(url_for("login"))

        # authentykacja
        if user and user.check_password(password):
            # informacja czy creds are valid
            login_user(user)
            flash("The credentials are valid", "success")
            return redirect(url_for("account", username=current_user.username))
        else:
            flash("invalid login credentials", "danger")
            return redirect(url_for("login"))


@app.route('/login_2fa/')
def login_2fa():
    secret = pyotp.random_base32()
    return render_template("login_2fa.html", secret=secret)


@app.route('/login_2fa/', methods=["POST"])
def login_2fa_form():
    # getting secret used by user
    secret = request.form.get("secret")
    # getting OTP provided by user
    otp = int(request.form.get("otp"))

    # verifying submitted OTP with PyOTP
    if pyotp.TOTP(secret).verify(otp):
        # informs if OTP is valid
        flash("The TOTP 2FA token is valid", "success")
        return redirect(url_for("account"))
    else:
        flash("You have supplied invalid 2FA token!", "danger")
        return redirect(url_for("login_2fa"))

# koniec logowania


# czesc inside czyli po zalogowaniu

@app.route('/account/<username>')
@login_required
def account(username):
    if current_user.username == username:
        return render_template("account.html", username=current_user.username)
    return "Brak dostępu!", 403


@app.route('/account/settings/<username>', methods=["GET", "POST"])
@login_required
def settings(username):
    if current_user.username == username:
        if request.method == "POST":
            new_username = request.form["username"]
            # new_password = request.form["password"]
            new_email = request.form["email"]

            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user and existing_user.id != current_user.id:
                flash('Ta nazwa użytkownika jest już zajęta.', 'danger')
                return redirect(url_for('settings', username=current_user.username))

            # if uzytkownik chce zmienic maila to wyslij kod na obecnego maila by potwierdzic request
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user and existing_user.id != current_user.id:
                flash('Ta nazwa email jest już zajęta.', 'danger')
                return redirect(url_for('settings', username=current_user.username))

            user = current_user
            user.username = new_username
            # user.password = new_password
            user.email = new_email
            user.email_confirmed = False
            user.confirmation_code = secrets.token_urlsafe(32)

            db.session.commit()

            flash('Twoje ustawienia zostały zaktualizowane.', 'success')

        return render_template("settings.html", username=current_user.username, password=current_user.password, email=current_user.email)
    return "Brak dostępu!", 403


# pomocnicza funkcja do ajax
@app.route('/validate_code', methods=["POST"])
def change_email():
    confirmation_code = request.json['confirmation_code']
    code_valid = 1
    # tutaj sprawdzanie poprawnosci kodu maila

    if code_valid:
        return jsonify({"success": True, "message": "kod jest poprawny"})
    else:
        return jsonify({"failure": True, "message": "kod jest niepoprawny"})


@app.route('/logout')
@login_required
def logout():
    logout_user()  # Zakończ sesję użytkownika
    return redirect(url_for('login'))

# koniec czesci po zalogowaniu


if __name__ == '__main__':
    app.run(debug=True)
