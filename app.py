import os
import sys
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, session, request, url_for
from flask_session import Session
from tempfile import mkdtemp
from functools import wraps
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

#Uploads
UPLOAD_FOLDER = 'static/image/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///velas.db")

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

@app.route("/about")
def aboutUs():
    return render_template("about.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session['user_type'] = rows[0]["tipo"]

        rows = db.execute("select * from users where id = :id", id=session.get("user_id"))
        if len(rows) != 1 or rows[0]["tipo"] == "admin":
            return redirect("/admin")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("deve indicar o username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("deve indicar a password", 400)

        # Ensure mail was submitted
        elif not request.form.get("mail"):
            return apology("deve indicar o email", 400)

        # Ensure password and confirmation match
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords não coincidem", 400)

        # Hash the password and insert a new user in the database
        hash = generate_password_hash(request.form.get("password"))
        new_user_id = db.execute("INSERT INTO users (username, hash, mail, tipo) VALUES(:username, :hash, :mail, :tipo)",
                                 username=request.form.get("username"),
                                 hash=hash,
                                 mail=request.form.get("mail"),
                                 tipo = ("user"))

        # Check if unique username constraint violated
        if not new_user_id:
            return apology("username já em uso", 400)

        if not new_user_id:
            return apology("mail já em uso", 400)

        # Remember which user has logged in
        session["user_id"] = new_user_id

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if session.get("user_id") is None:
            return redirect("/login")

        if request.form.get('submit_button') != 'a':
            productid = int(request.form.get('submit_button'))
            db.execute("INSERT INTO cart (user_id, product_id) VALUES(:username, :product_id)",
                                 username=session.get("user_id"),
                                 product_id=productid)

            return redirect("/")

    produtos = db.execute("select id, name, desc, price, image from produtos")
    
    return render_template("index.html", produtos=produtos)

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def admin_login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        else:
            rows = db.execute("select * from users where id = :id", id=session.get("user_id"))
            if len(rows) != 1 or rows[0]["tipo"] != "admin":
                return apology("Não és admin", 400)
        return f(*args, **kwargs)
    return decorated_function

@app.route("/admin", methods=["GET", "POST"])
@admin_login_required
def admin():
    produtos = db.execute("select id, name, desc, price, image from produtos")
    users = db.execute("select id, username, mail from users")
    return render_template("adminIndex.html", produtos=produtos, users = users)

@app.route("/admin/inserirProdutos", methods=["GET", "POST"])
@admin_login_required
def adminInserirProdutos():
    if request.method == "POST":
        # Ensure name was submitted
        if not request.form.get("name"):
            return apology("Deve indicar o Nome", 400)

        # Imagem upload
        # check if the post request has the file part
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        db.execute("INSERT INTO produtos (name, desc, price, image) VALUES(:name, :desc, :price, :image)",
                                 name=request.form.get("name"),
                                 desc = request.form.get("desc"),
                                 price=request.form.get("price"),
                                 image=filename)
        return redirect("/admin/inserirProdutos")
    
    produtos = db.execute("select id, name, desc, price, image from produtos")

    return render_template("inserirProdutos.html", produtos=produtos)

@app.route("/admin/apagarProdutos", methods=["GET", "POST"])
@admin_login_required
def adminApagarProdutos():
    if request.method == "POST":
        # Ensure name was submitted
        if not request.form.get("id"):
            return apology("Deve indicar o ID", 400)

        # Apagar imagem
        rows = db.execute("select * from produtos where id = :id", id=request.form.get("id"))
        if len(rows) == 1:
            image = rows[0]["image"]
            os.remove("static/image/uploads/%s" % (image))
        
        # Apagar da base de dados
        db.execute("DELETE FROM produtos WHERE id = :id",
                                 id=request.form.get("id"))
        
        return redirect("/admin/apagarProdutos")
    
    produtos = db.execute("select id, name, desc, price, image from produtos")

    return render_template("apagarProdutos.html", produtos=produtos)

@app.route("/contacto")
def contacto():
    return render_template("contacto.html")

@app.route("/cart", methods=["GET", "POST"])
@login_required
def cart():
    if request.method == "POST":
        if request.form.get('submit_button-') is not None:
            productid = int(request.form.get('submit_button-'))
            rows = db.execute("select quantities from cart where product_id = :productID and user_id = :userid",
                                        productID = productid,
                                        userid=session.get("user_id"))
            quantities = rows[0]["quantities"]
            if quantities == 1:
                db.execute("delete from cart where user_id = :userid and product_id=:product_id",
                                 userid=session.get("user_id"),
                                 product_id=productid)
            else:
                db.execute("update cart set quantities=:quant where user_id = :userid and product_id=:product_id",
                                 userid=session.get("user_id"),
                                 product_id=productid,
                                 quant= quantities-1)
        if request.form.get('submit_button+') is not None:
            productid = int(request.form.get('submit_button+'))
            rows = db.execute("select quantities from cart where product_id = :productID and user_id = :userid",
                                        productID = productid,
                                        userid=session.get("user_id"))
            quantities = rows[0]["quantities"]
            
            db.execute("update cart set quantities=:quant where user_id = :userid and product_id=:product_id",
                                 userid=session.get("user_id"),
                                 product_id=productid,
                                 quant= quantities+1)

        return redirect("/cart")

    produtos = db.execute("Select cart.quantities, produtos.name, produtos.price, produtos.image, produtos.id from cart inner join produtos on cart.product_id = produtos.id where user_id = :user",
                            user = session.get("user_id"))
    return render_template("cart.html", produtos=produtos)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)