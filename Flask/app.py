from flask import Flask, render_template, redirect, url_for, request, session, flash
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=5)
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class users(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    def __init__(self,name,email):
        self.name=name
        self.email=email

@app.route("/view")
def view():
    return render_template("view.html",value=users.query.all())
        


@app.route("/user", methods=["POST", "GET"])
def user():
    email=None
    if "user" in session:
        user = session["user"]
    
        if request.method == "POST":
            email = request.form["email"]
            session["email"] = email
            found_user = users.query.filter_by(name = user).first()
            found_user.email=email
            db.session.commit()
            flash("Email was sucessfully saved!")
        else:
            if "email" in session:
                email = session["email"]
        return render_template("user.html", email=email)
    else:
        flash("You're not logged in!!")
        return redirect(url_for("login"))

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/Login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        user = request.form["nm"]
        session["user"] = user
        found_user = users.query.filter_by(name = user).first()
        if found_user :
            session["email"] = found_user.email
        else:
            usr = users(user,"")
            db.session.add(usr)
            db.session.commit()
        flash("Login! Successful...", "info")
        return redirect(url_for("user"))
    else:
        if "user" in session:
            flash("Already Logged in.....", "info")
            return redirect(url_for("user")) 
        return render_template("login.html")

@app.route("/Logout")
def logout():
    flash("You have been logged out!", "info")
    session.pop("user", None)
    session.pop("email",None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)



