from flask import Flask, render_template, request, redirect, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from helpers import login_required, username_validate, password_validate
from cs50 import SQL

# Initializes the app
app = Flask(__name__)
app.config["SECRET_KEY"] = "thisisasecretkey"
app.config['UPLOADED_PHOTOS_DEST'] = 'uploads'

# Initializes the contacts database
db = SQL("sqlite:///contacts.db")


@app.route("/")
@login_required
def index():
    # saves the all the contact details into a variable

    contact_table = db.execute("SELECT * FROM user_contacts WHERE user_id = (?) ORDER BY first_name", session["user_id"])

    return render_template("index.html", contact_table=contact_table)


@app.route("/search")
def search():
    q = request.args.get("q")
    q_fav = request.args.get("q_fav")
    if q:
        search_result = db.execute("SELECT * FROM user_contacts WHERE first_name LIKE ? OR last_name LIKE ? OR phone_primary LIKE ? OR phone_secondary LIKE ? AND user_id = ? ORDER BY first_name;", "%" + q + "%", "%" + q + "%", "%" + q + "%", "%" + q + "%", session["user_id"])
    elif q_fav:
        fav_result = db.execute("SELECT * FROM user_contacts WHERE first_name LIKE ? OR last_name LIKE ? OR phone_primary LIKE ? OR phone_secondary LIKE ? AND user_id = ? AND favorite = 1 ORDER BY first_name;", "%" + q_fav + "%", "%" + q_fav + "%", "%" + q_fav + "%", "%" + q_fav + "%", session["user_id"])
        return render_template("favorites.html", fav_result=fav_result)
    else:
        search_result = []
    return render_template("search.html", search_result=search_result)


@app.route("/favorites")
def favorites():
        rm_fav = request.args.get("rm_fav")
        fav_first_name = request.args.get("fav_first_name")

        if rm_fav is not None:
            db.execute("UPDATE user_contacts SET favorite = 0 WHERE first_name = ? AND user_id = ?", rm_fav, session["user_id"])
            rm_fav = None
        elif fav_first_name is not None:
            db.execute("UPDATE user_contacts SET favorite = 1 WHERE first_name = ? AND user_id = ?", request.args.get("fav_first_name"), session["user_id"])
            fav_first_name = None
            
        fav_result = db.execute("SELECT * FROM user_contacts WHERE favorite = 1 AND user_id = ? ORDER BY first_name", session["user_id"])
        return render_template("favorites.html", fav_result=fav_result)


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            error_title="Username missing"
            error_explain="Please make sure that you entered your username"
            return render_template("apology.html", error_title=error_title, error_explain=error_explain)
        # Ensure password was submitted
        elif not request.form.get("password"):
            error_title="Password missing"
            error_explain="Please make sure that you entered your password"
            return render_template("apology.html", error_title=error_title, error_explain=error_explain)
        
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            error_title="Invalid username or password" 
            error_explain="Please make sure that your username and passwords are correct"
            return render_template("apology.html", error_title=error_title, error_explain=error_explain)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Obtaining the user input
        reg_user_name = request.form.get("reg-username")
        reg_password = request.form.get("reg-password")
        reg_password_confirm = request.form.get("reg-password-confirm")

        # Validating the username and password
        similar_username = db.execute("SELECT username FROM users WHERE username = ?", reg_user_name)
        if len(similar_username) != 0:
            error_title="Username not available"
            error_explain="There is a user with the username you provided. Please choose another username"
            return render_template("apology.html", error_title=error_title, error_explain=error_explain)
        
        if not reg_user_name or not reg_password or not reg_password_confirm:
            error_title="Please fill in all the details"
            error_explain="Please check whether you filled in all the details"
            return render_template("apology.html", error_title=error_title, error_explain=error_explain)
        elif reg_password != reg_password_confirm:
            error_title="Password mismatch"
            error_explain="Please check whether your password matches confirmation password"
            return render_template("apology.html", error_title=error_title, error_explain=error_explain)
        elif username_validate(reg_user_name) != 0:
            error_title="Username Invalid"
            error_explain="Please check whether your username is correct"
            return render_template("apology.html", error_title=error_title, error_explain=error_explain)
        elif password_validate(reg_password) != 0:
            error_title="Password Invalid"
            error_explain="Please check whether your password meets all the requirements"
            return render_template("apology.html", error_title=error_title, error_explain=error_explain)
        
        # Inserts the username and hashed password to the users database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?);", reg_user_name, generate_password_hash(reg_password, method="scrypt", salt_length=16))

        # After reg is successful, redirect to login page
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/add", methods=["GET", "POST"])
def add_contact():
    if request.method == "POST":

        # Getting all the user input
        first_name = request.form.get("first_name").capitalize()
        last_name = request.form.get("last_name").capitalize()
        company = request.form.get("company")
        job_title = request.form.get("job_title").capitalize()
        email = request.form.get("email")
        phone_primary = request.form.get("phone_primary")
        phone_secondary = request.form.get("phone_secondary")
        notes = request.form.get("notes")


        # Validating the first_name and phone_primary
        if not first_name or not phone_primary:
            error_title="At least first name and phone number"
            error_explain="In order to save a contact, you need to at least fill in the First Name and Primary Phone Number fields"
            return render_template("apology.html", error_title=error_title, error_explain=error_explain)
        
        
        # Adding the inputs to the user_contact database
        db.execute("INSERT INTO user_contacts (first_name, last_name, company, job_title, email, phone_primary, phone_secondary, notes, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);", first_name, last_name, company, job_title, email, phone_primary, phone_secondary, notes, session["user_id"])

        # After the add_contact is successful, return to the index page
        return redirect("/")
    
    else:
        return render_template("add_contacts.html")
    

@app.route("/thanks")
def thanks():
    return render_template("thanks.html")


@app.route("/remove")
def remove():
    rm_contact = request.args.get("rm_contact")
    db.execute("DELETE FROM user_contacts WHERE first_name = ? AND user_id = ?", rm_contact, session["user_id"])
    return redirect("/")


