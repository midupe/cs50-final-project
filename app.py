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
        return redirect("/conta")

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
    produto = db.execute("select count(id) from produtos")
    user = db.execute("select count(id) from users")
    produtos=0
    users = 0
    if len(produto) ==1:
        produtos=produto[0]["count(id)"]

    if len (user)==1:
        users = user[0]["count(id)"]
    
    return render_template("adminIndex.html", produtos=produtos, users = users)
    
@app.route("/admin/produtos", methods=["GET", "POST"])
@admin_login_required
def adminProdutos():
    produtos = db.execute("select id, name, desc, price, image from produtos")
    return render_template("adminProdutos.html", produtos=produtos)

@app.route("/admin/clientes", methods=["GET", "POST"])
@admin_login_required
def adminClientes():
    users = db.execute("select id, username, mail, zip, city, street, nome from users left join morada on user_id=id")
    return render_template("adminClientes.html", users=users)

@app.route("/admin/encomendasPorCliente", methods=["GET", "POST"])
@admin_login_required
def adminEncomendasPorUser():
    users = db.execute("select id, username, mail, nome from users left join morada on user_id=users.id order by users.id")
    encomendas_datas = ''
    encomendas = ''
    if request.method == "POST":
        if not request.form.get("id"):
            return apology("Deve indicar o ID", 400)
        
        encomendas_datas = db.execute("select data, id from encomenda where user_id = :user_id group by data", user_id=int(request.form.get("id")))
        encomendas = db.execute("select * from encomenda where user_id = :user_id", user_id=int(request.form.get("id")))
        return render_template("adminEncomendasUser.html", users=users, encomendas_datas=encomendas_datas, encomendas=encomendas)

    return render_template("adminEncomendasUser.html", users=users, encomendas_datas=encomendas_datas, encomendas=encomendas)

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
        rows = db.execute("select image from produtos where id = :id", id=request.form.get("id"))
        if len(rows) == 1:
            image = rows[0]["image"]
            if os.path.exists(image):
                os.remove("static/image/uploads/%s" % (image))
        
        # Apagar da base de dados
        db.execute("DELETE FROM produtos WHERE id = :id",
                                 id=request.form.get("id"))
        
        return redirect("/admin/apagarProdutos")
    
    produtos = db.execute("select id, name, desc, price, image from produtos")

    return render_template("apagarProdutos.html", produtos=produtos)
    
@app.route("/admin/editarPrecoProdutos", methods=["GET", "POST"])
@admin_login_required
def adminEditarPrecoProdutos():
    if request.method == "POST":
        if not request.form.get("preco"):
            return apology("Deve indicar o preço", 400)

        if not request.form.get("id"):
            return apology("Deve indicar o id", 400)

        db.execute("update produtos set price = :preco WHERE id = :id",
                                 id=request.form.get("id"),
                                 preco=float(request.form.get("preco")))
        
        return redirect("/admin/editarPrecoProdutos")
    
    produtos = db.execute("select id, name, desc, price, image from produtos")

    return render_template("editarPrecoProdutos.html", produtos=produtos)

@app.route("/contacto")
def contacto():
    return render_template("contacto.html")

@app.route("/cart", methods=["GET", "POST"])
@login_required
def cart():
    userID = session.get("user_id")
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
                                        userid=userID)
            quantities = rows[0]["quantities"]
            
            db.execute("update cart set quantities=:quant where user_id = :userid and product_id=:product_id",
                                 userid=userID,
                                 product_id=productid,
                                 quant= quantities+1)

        return redirect("/cart")

    produtos = db.execute("Select cart.quantities, produtos.name, produtos.price, produtos.image, produtos.id from cart inner join produtos on cart.product_id = produtos.id where user_id = :user",
                            user = userID)

    rows0 = db.execute("SELECT SUM(cart.quantities * produtos.price) FROM cart inner join produtos on cart.product_id = produtos.id where user_id = :user", user = session.get("user_id"))
    totalcart = rows0[0]["SUM(cart.quantities * produtos.price)"]
    if totalcart is None:
        totalcart=0

    return render_template("cart.html", produtos=produtos, totalcart=totalcart)

@app.route("/cart/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    # Check if exists morada
    rows = db.execute("select * from morada where user_id = :userid", userid = session.get("user_id"))
    if len(rows) != 1:
        return redirect("/conta")

    produtos = db.execute("Select cart.quantities, produtos.name, produtos.price, produtos.image, produtos.id from cart inner join produtos on cart.product_id = produtos.id where user_id = :user",
                            user = session.get("user_id"))
    rows0 = db.execute("SELECT SUM(cart.quantities * produtos.price) FROM cart inner join produtos on cart.product_id = produtos.id where user_id = :user", user = session.get("user_id"))
    totalcart = rows0[0]["SUM(cart.quantities * produtos.price)"]
    if totalcart is None:
        totalcart=0

    # Finalizar compra
    if request.method == "POST":
        for i in range(len(produtos)):
            product_id = produtos[i]["id"]
            price = produtos[i]["price"]
            product_name = produtos[i]["name"]
            quantities = produtos[i]["quantities"]

            new_encomenda = db.execute("Insert into encomenda (user_id, product_id, quantities, price, product_name) values (:user_id, :product_id, :quantities, :price, :product_name) ", 
                        user_id=session.get("user_id"),
                        product_id=product_id,
                        quantities=quantities,
                        price=price,
                        product_name=product_name)

            if not new_encomenda:
                return apology("Erro ao processar compra", 400)

            # Apagar carrinho
            db.execute("delete from cart where user_id = :user_id", user_id=session.get("user_id"))
        
        return redirect("/cart/checkout/thanks")

    return render_template("checkout.html", produtos=produtos, totalcart=totalcart)

@app.route("/cart/checkout/thanks", methods=["GET", "POST"])
@login_required
def thanks():
    return render_template("thanks.html")

@app.route("/conta", methods=["GET", "POST"])
@login_required
def conta():
    user_id = session.get("user_id")
    rows = db.execute ("select username, mail from users where id = :user_id", user_id=user_id)
    username = rows[0]["username"]
    mail = rows[0]["mail"]
    zipcode=''
    city=''
    street=''
    nome=''



    encomendas_datas = db.execute("select data, id from encomenda where user_id = :user_id group by data", user_id=user_id)
    encomendas = db.execute("select * from encomenda where user_id = :user_id", user_id=user_id)

    # Check if has adress:
    exists_adress = False
    check_adress = db.execute("select * from morada where user_id=:user_id", user_id=user_id)
    if len(check_adress) == 1 and check_adress[0]["user_id"] == user_id:
        exists_adress = True
        zipcode=check_adress[0]["zip"]
        city=check_adress[0]["city"]
        street=check_adress[0]["street"]
        nome=check_adress[0]["nome"]


    if request.method == "POST":
        if request.form.get('alterar_button') == 'a':
            db.execute("delete from morada where user_id = :user_id", user_id=user_id)
            return redirect("/conta")

        if not request.form.get("zip"):
            return apology("deve indicar o código postal", 400)

        elif not request.form.get("city"):
            return apology("deve indicar a cidade ou localidade", 400)

        elif not request.form.get("street"):
            return apology("deve indicar o rua e porta", 400)

        elif not request.form.get("nome"):
            return apology("deve indicar o seu nome completo", 400)
        
        zipcode=request.form.get("zip")
        city=request.form.get("city")
        street=request.form.get("stret")
        nome=request.form.get("nome")

        db.execute("INSERT INTO morada (user_id, zip, city, street, nome) VALUES(:user_id, :zipcode, :city, :street, :nome)",
                                 user_id=user_id,
                                 zipcode=request.form.get("zip"),
                                 city=request.form.get("city"),
                                 street=request.form.get("street"),
                                 nome=request.form.get("nome"))
            
        return redirect("/conta")


    return render_template("conta.html", username=username, mail=mail, exists_adress=exists_adress, zipcode=zipcode, city=city, street=street, nome=nome, encomendas=encomendas, encomendas_datas=encomendas_datas)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)