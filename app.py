import os

import datetime
from decimal import Decimal, ROUND_HALF_EVEN
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import pytz
from helpers import login_required, apology
from flask import jsonify
from datetime import datetime, timezone, timedelta
# Configure application
app = Flask(__name__)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")



@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# index
@app.route("/")
def index():
    return redirect("login")

# login
@app.route("/login",methods=["GET","POST"])
def login():
    session.clear()

    if request.method=="GET":
        return render_template("/login.html")
    else:
        username = request.form.get("username")
        password = request.form.get("hash")

        if not username:
            error_username = "Username is required."
            return render_template("login.html", error_username=error_username)

        if not password:
            error_password = "Password is required."
            return render_template("login.html", error_password=error_password)

        rows = db.execute("SELECT hash,id,disable FROM users WHERE username = ?", username)
        if rows:
          if rows[0]["disable"] == 1:
            error_general = "User is disabled"
            return render_template("login.html", error_general=error_general)
          if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            error_general = "Invalid username or password."
            return render_template("login.html", error_general=error_general)
        else:
          error_general = "Invalid username or password."
          return render_template("login.html", error_general=error_general)
        # Remember which user has logged in
        
        session["user_id"] = rows[0]["id"]

        # import data from db the view the table and nav
        userdata = db.execute("select * from users where username = ?", request.form.get("username"))
       
        timestamp = datetime.now()
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("insert into user_movements (user_id, store_id,movement_type,timestamp) values(?,?,?,?)",session.get("user_id"),userdata[0]['store_id'],"Login",timestamp)
        if userdata[0]['is_admin'] == 1:
            # Get stores name's from database
            users = db.execute("select username,store_id,name from users join stores on users.store_id = stores.id")
            role = "admin"
            # Redirect user to register page
            return redirect("/users",code=302)

        elif userdata[0]['is_manager'] == 1:
          return redirect("/home",code = 302)
        elif userdata[0]['is_accounting'] == 1:
          return redirect("/acchome",code=302)

# register
@app.route("/register", methods=["GET", "POST"])
@login_required
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        pass1 = request.form.get("hash1")
        pass2 = request.form.get("hash2")
        store = request.form.get("store")
        unames = db.execute("select username from users")

        # JUST MAKING SURE OF SOME THINGS :D
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username",)
        # Ensure password was submitted
        elif not request.form.get("hash1"):
            return apology("must provide password",)
        # Ensure confirmation was submitted
        elif not request.form.get("hash2"):
            return apology("must re-type the password",)
        # Ensure passwords fields is matched
        elif (request.form.get("hash1") != request.form.get("hash2")):
            return apology("The password fields must match!",)
        # Ensure the username is not exists
        for name in unames:
            if username == name["username"]:
                return apology("username already exists",)
        # create passowrd and update the db
        hpass = generate_password_hash(pass1, salt_length=12)
        # get rule to pass navbar
        roles = db.execute("select * from users where id = ?", session.get("user_id"))
        if roles[0]['is_admin'] == 1:
            role = "admin"
        # create condition to get store name and user role role and insert user to users
        if store == "Administration":
            storeNumber = 0
            db.execute("insert into users (username, hash, is_admin, is_super, is_accounting, is_manager, store_id) values (?, ?, ?, ?, ?, ?, ?)", username, hpass, 1, 0, 0, 0, storeNumber)
            store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
            timestamp = datetime.now()
            timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description,timestamp) values (?, ?, ?, ?, ?,?)",session.get("user_id"), store_id, "Create New User", "Users", (f"Username: {username} on store: {store}"),timestamp)
        elif store =="Accounting":
            storeNumber = 99
            store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
            timestamp = datetime.now()
            timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description,timestamp) values (?, ?, ?, ?, ?,?)",session.get("user_id"), store_id, "Create New User", "Users", (f"Username: {username} on store: {store}"),timestamp)
            db.execute("insert into users (username, hash, is_admin, is_super, is_accounting, is_manager, store_id) values (?, ?, ?, ?, ?, ?, ?)", username, hpass,0, 0, 1, 0, storeNumber)
        else:
          store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
          timestamp = datetime.now()
          timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
          db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description,timestamp) values (?, ?, ?, ?, ?,?)",session.get("user_id"), store_id, "Create New User", "Users",  (f"Username: {username} on store: {store}"),timestamp)
          storeNumber = db.execute("select id from stores where name = ?" ,store)[0]['id']
          db.execute("insert into users (username, hash, is_admin, is_super, is_accounting, is_manager, store_id) values (?, ?, ?, ?, ?, ?, ?)", username, hpass, 0,0, 0, 1, storeNumber)

        flash(f"Created user: {username} at store {store}.")
        return redirect("register", 302)
    else:
        roles = db.execute("select * from users where id = ?", session.get("user_id"))
        if roles[0]['is_admin'] == 1:
            # get rule to pass navbar
            role = "admin"
        stores = db.execute("select name from stores where id != 0 and id != 100 order by id")

        names = db.execute("select username from users")
        return render_template("register.html", role=role,  stores=stores, names=names)

# logout user
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    id = session.get("user_id")
    if id:
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))
      store_id = store_id[0]['store_id']
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (user_id, store_id,movement_type,timestamp) values(?,?,?,?)", session.get("user_id"), store_id, "Logout",timestamp)
    session.clear()

    # Redirect user to login form
    return render_template("/login.html")

# Add Cashier
@app.route("/addcashier", methods=["GET","POST"])
@login_required
def addCashier():
  roles = db.execute("select * from users where id = ?", session.get("user_id"))
  if roles[0]['is_admin'] == 1:
    role = "admin"
    if request.method == "GET":
      # get rule to pass navbar
      existing_cashiers = db.execute("SELECT id, name FROM cashiers")
      stores = db.execute("select name from stores where id != 99 and id != 0 and id != 100")
      return render_template("/addcashier.html", role=role, existing_cashiers=existing_cashiers, stores=stores)
    else:
      name = request.form.get("cashiername")
      number = request.form.get("cashiernumber")
      store = request.form.get("store")
      if store:
        storenumber= db.execute("select id from stores where name = ?",store)
        if storenumber:
          storenumber = storenumber[0]['id']
        else:
          flash("Store not found!")
          return redirect("addcashier",code=302)
      else:
        flash("Store not found, Make sure to Select Store")
        return redirect("addcashier",code=302)
      # check_if_exists
      cashiers = db.execute("select * from cashiers")
      if cashiers:
        for cashier in cashiers:
          if number == cashier['id']:
            flash("username already exists")
            return redirect("addcashier",code=302)
      # insert new cashier
      db.execute("insert into cashiers (id, name,store_id) values(?,?,?)", number, name, storenumber)
      store_id = db.execute("select store_id from users where id = ?",session.get('user_id'))[0]['store_id']
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (timestamp, user_id, store_id, movement_type, m_table, m_description) values (? ,?, ?, ?, ?, ?)",timestamp, session.get("user_id"), store_id, "Add Cashier","cashiers",f"cashier {name} with number {number} has been added to the cashiers at store {store}." )
      flash(f"User: {name} with number {number} has been added to the cashiers at store {store}.")

      return redirect("/addcashier", code=302)
  else:
    return apology("UR NOT ADMING GET OUT OF HERE")
  
  
# report table
@app.route("/users",methods = ["GET","POST"])
@login_required
def users():
    # import data from db the view the table and nav
    if request.method == "GET":
      roles = db.execute("select * from users where id = ?", session.get("user_id"))
      if roles[0]['is_admin'] == 1:
          # Get stores name's from database
          users = db.execute("select username,store_id,name from users join stores on users.store_id = stores.id order by stores.id")
          role = "admin"
          stores = db.execute("select * from stores order by id")
          usersInfo = db.execute("select users.username,users.id,stores.name from users join stores on users.store_id = stores.id order by stores.id")
          srole = ['Administration','Accounter','Manager','Cashier','Chain']
          return render_template("/users.html",users = users , role = role, stores=stores, usersInfo=usersInfo,srole=srole)
      else:
        return apology("YOUR NOT ADMIN")
      
# View users by store
@app.route("/ubstore", methods = ["GET","POST"])
@login_required
def ubstore():
  roles = db.execute("select * from users where id = ?", session.get("user_id"))
  if roles[0]['is_admin'] == 1:
    role = "admin"
    if request.method == "POST":
      store = request.form.get("store")
      if not store:
        flash("Must select store!")
        return redirect("users",code=302)
      store_id = db.execute("select id from stores where name = ?",store)
      if store_id:
        store_id = store_id[0]['id']
      else:
        flash("Store not found!")
        return redirect("users",code=302)
      data = db.execute("select users.username, stores.name as store_name, stores.id  from users join stores on users.store_id = stores.id where users.store_id = ? order by stores.id , users.username COLLATE NOCASE;",store_id)
      cashiers = db.execute("select cashiers.name, cashiers.id, stores.name as store_name from cashiers join stores on cashiers.store_id = stores.id where store_id = ? order by stores.name, cashiers.name COLLATE NOCASE", store_id)
      return render_template("/ubstore.html",role=role,data=data, cashiers=cashiers)
    else:
      return apology("Method Not Allowed!!")
  else:
    return apology("YOUR NOT ADMIN")

# view users by role
@app.route("/ubrole",methods=["GET","POST"])
@login_required
def ubrole():
  roles = db.execute("select * from users where id = ?", session.get("user_id"))
  if roles[0]['is_admin'] == 1:
    role = "admin"
    if request.method == "POST":
      Role = request.form.get("role")
      if not Role:
        flash("Must select a role!")
        return redirect("users",code=302)
      if Role == 'Administration':
        RoleId = 0
        data = db.execute("select username from users where store_id = ? and disable = 0 order by username COLLATE NOCASE",RoleId)
        if data:
          for i in data:
            i['store_name'] ='Administration'
            i['role'] ='Admin'    
          return render_template("/ubrole.html",role=role,data=data)
        else:
          flash("Role not found!")
          return redirect("users",code=302)
        
      elif Role == 'Accounter':
        RoleId = 99
        data = db.execute("select username from users where store_id = ? and disable = 0 order by username COLLATE NOCASE",RoleId)
        if data:
          for i in data:
            i['store_name'] ='Accounting'
            i['role'] ='Accounter'    
          return render_template("/ubrole.html",role=role,data=data)
        else:
          flash("Role not found!")
          return redirect("users",code=302)
        
      elif Role == 'Manager':
        RoleId = 1
        data = db.execute("select users.username, stores.name as store_name, stores.id from users join stores on users.store_id = stores.id where users.is_manager = ? and users.disable = 0 order by stores.id, users.username COLLATE NOCASE",RoleId)
        if data:
          for i in data:
            i['role'] ='Manager'    
          return render_template("/ubrole.html",role=role,data=data)
        else:
          flash("Role not found!")
          return redirect("users",code=302)
        
      elif Role == 'Cashier':
        data = db.execute("select cashiers.id, cashiers.name as username, stores.name as store_name from cashiers join stores on cashiers.store_id = stores.id where cashiers.disable = 0 order by stores.id , cashiers.name COLLATE NOCASE")
        if data:
          for i in data:
            i['role'] ='Cashier'    
          return render_template("/ubrole.html",role=role,data=data)
        else:
          flash("Role not found!")
          return redirect("users",code=302)
        
      elif Role == 'Chain':
        data = db.execute("select users.username, users.is_admin, users.is_accounting, users.is_manager, stores.name as store_name from users join stores on users.store_id = stores.id where users.disable = 0 order by stores.id, users.username COLLATE NOCASE")
        if data:
          for i in data:
            if i['is_admin'] == 1:
              i['role'] = 'Admin'
            elif i['is_accounting'] == 1:
              i['role'] ='Accounter'
            elif i['is_manager'] == 1:
              i['role'] ='Manager'
          cashiers =  db.execute("select cashiers.id, cashiers.name as username, stores.name as store_name from cashiers join stores on cashiers.store_id = stores.id where cashiers.disable = 0 order by stores.id , cashiers.name COLLATE NOCASE")
          if cashiers:
            for i in cashiers:
              i['role'] ='Cashier'
              return render_template("/ubrole.html",role=role,data=data,cashiers=cashiers)
          else:
            cashiers = {}
            return render_template("/ubrole.html",role=role,data=data,cashiers=cashiers)
        else:
          flash("Role not found!")
          return redirect("users",code=302)
      
      else:
        flash("Role not found!")
        return redirect("users",code=302)

    else:
      return apology("Method Not Allowed!!")
  else:
      return apology("YOUR NOT ADMIN")

# report generater-user :D 
@app.route("/adminreport", methods=["GET","POST"])
@login_required
def adminreport():
  if request.method == "POST":
    roles = db.execute("select * from users where id = ?", session.get("user_id"))
    if roles[0]['is_admin'] == 1:
      role="admin"
      store = request.form.get("currentStore")
      if not store:
        flash("Must select store!")
        return redirect("/users",code=302)
      username = request.form.get("username")
      if not username:
        flash("Must select username!")
        return redirect("/users",code=302)
      username = str(username)
      fromDate = request.form.get("fromDate1")
      if not fromDate:
        flash("Must select From Date!")
        return redirect("/users",code=302)
      toDate = request.form.get("toDate1")
      if not toDate:
        flash("Must select To Date!")
        return redirect("/users",code=302)
      
      fdate = datetime.strptime(fromDate + " 00:00:00","%Y-%m-%d %H:%M:%S")
      tdate = datetime.strptime(toDate + " 23:59:59","%Y-%m-%d %H:%M:%S")

      user_id = db.execute("select id from users where username = ?",username)[0]['id']
      
      report = db.execute("select users.username, stores.name ,user_movements.movement_type, user_movements.m_table, user_movements.m_description, user_movements.movement_date, user_movements.timestamp from  user_movements join stores on user_movements.store_id = stores.id join users on user_movements.user_id = users.id  where user_movements.timestamp >= ? and user_movements.timestamp <=? and user_movements.user_id = ?",fdate,tdate,user_id)
      if report:
        return render_template("/adminreport.html",role=role,report=report)
      flash("Theres no data to be viewed")
      return redirect("/users",code=302)
    else:
      return apology("YOUR NOT ADMIN")

# report generater-store :D 
@app.route("/storereport", methods=["GET","POST"])
@login_required
def storereport():
  if request.method == "POST":
    roles = db.execute("select * from users where id = ?", session.get("user_id"))
    if roles[0]['is_admin'] == 1:
      role="admin"
      store = request.form.get("selectedStore")
      if not store:
        flash("Must select store!")
        return redirect("/users",code=302)
      fromDate = request.form.get("fromDate2")
      if not fromDate:
        flash("Must select From Date!")
        return redirect("/users",code=302)
      toDate = request.form.get("toDate2")
      if not toDate:
        flash("Must select To Date!")
        return redirect("/users",code=302)
      
      fdate = datetime.strptime(fromDate + " 00:00:00","%Y-%m-%d %H:%M:%S")
      tdate = datetime.strptime(toDate + " 23:59:59","%Y-%m-%d %H:%M:%S")
      
      
      store_id = db.execute("select id from stores where name = ?",store)[0]['id']
      report = db.execute("select users.username, stores.name ,user_movements.movement_type, user_movements.m_table, user_movements.m_description, user_movements.movement_date, user_movements.timestamp from  user_movements join stores on user_movements.store_id = stores.id join users on user_movements.user_id = users.id  where user_movements.timestamp >= ? and user_movements.timestamp <=? and user_movements.store_id = ?",fdate,tdate,store_id)
      if report:
        return render_template("/storereport.html",role=role,report=report)
      flash("Theres no data to be viewed")
      return redirect("/users",code=302)
    else:
      return apology("YOUR NOT ADMIN")

# add store
@app.route("/addstore", methods=["GET","POST"])
@login_required
def addstore():
    if request.method == "GET":
        roles = db.execute("select * from users where id = ?", session.get("user_id"))
        role = "admin"
        if roles[0]['is_admin'] == 1:
            stores = db.execute("select * from stores")
            return render_template("/addstore.html", role = role, stores = stores)
    else:
        number = request.form.get("storenumber")
        name = request.form.get("storename")
        stores = db.execute("select * from stores")

        # Check if exists
        if stores:
            for store in stores:
                if number == store['id']:
                    return apology("Store is already exists!")
        if not name:
            return apology("must provide name")

        # insert new store to stores
        store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
        timestamp = datetime.now()
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description) values (?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id, "Add Store", "stores",f"Store: {name} with number {number} has been added to Stores.")
        db.execute("insert into stores (id, name) values(?,?)", number, name)
        flash(f"Store: {name} with number {number} has been added to Stores.")

        return redirect("/addstore", code=302)
      
# change status
@app.route("/changestatus",methods=["GET","POST"])
@login_required
def changestatus():
  roles = db.execute("select * from users where id = ? ", session.get("user_id"))
  if roles[0]['is_admin'] == 1:
    role = "admin"
    if request.method == "GET":
      stores = db.execute("select * from stores where id != 0 and id != 100")
      userInfo = db.execute("select users.username,users.id,stores.name, users.disable from users join stores on users.store_id = stores.id where users.store_id != 0 and users.store_id != 100")
      cashiersInfo = db.execute("select cashiers.name as username, cashiers.id, stores.name, cashiers.disable from cashiers join stores on cashiers.store_id = stores.id")
      return render_template("changestatus.html", role=role, stores=stores, userInfo=userInfo,cashiersInfo=cashiersInfo)
    else:
      if request.form.get("action") == "disablem":
        username = request.form.get("username")
        if username:
          
          store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
          userstoreid = db.execute("select store_id from users where username = ?", username)[0]['store_id']
          if userstoreid == 99:
            userstoreid = "Accountent"
          timestamp = datetime.now()
          timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
          db.execute("update users set disable = 1 where username = ?",username)
          db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description) values (?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Disable User","users",f"user: {username} has been diabled from store {userstoreid}")
          flash(f"User {username} has been disabled")
          return redirect('changestatus',code=302)
        else:
          flash("User not found!")
          return redirect('changestatus',code=302)
        
      elif request.form.get("action") == "enablem":
        username = request.form.get("username")
        if username:
          
          store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
          userstoreid = db.execute("select store_id from users where username = ?", username)[0]['store_id']
          if userstoreid == 99:
            userstoreid = "Accountent"
          timestamp = datetime.now()
          timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
          db.execute("update users set disable = 0 where username = ?",username)
          db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description) values (?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Enable User","users",f"user: {username} has been enabled from store {userstoreid}")
          flash(f"User {username} has been enabled")
          return redirect('changestatus',code=302)
        else:
          flash("User not found!")
          return redirect('changestatus',code=302)
        
      elif request.form.get("action") == "disableCashier":
        username = request.form.get("username")
        if username:
          store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
          userstoreid = db.execute("select store_id from cashiers where name = ?", username)[0]['store_id']
          timestamp = datetime.now()
          timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
          db.execute("update cashiers set disable = 1 where name = ?",username)
          db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description) values (?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Disable Cashier","Cashiers",f"cashier: {username} has been diabled from store {userstoreid}")
          flash(f"Cashier {username} has been disabled")
          return redirect('changestatus',code=302)
        else:
          flash("User not found!")
          return redirect('changestatus',code=302)
        
      elif request.form.get("action") == "enableCashier":
        username = request.form.get("username")
        if username:
          store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
          userstoreid = db.execute("select store_id from cashiers where name = ?", username)[0]['store_id']
          timestamp = datetime.now()
          timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
          db.execute("update cashiers set disable = 0 where name = ?",username)
          db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description) values (?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Enable Cashier","Cashiers",f"cashier: {username} has been enabled from store {userstoreid}")
          flash(f"Cashier {username} has been enabled")
          return redirect('changestatus',code=302)
        else:
          flash("User not found!")
          return redirect('changestatus',code=302)
      else:
        flash("METHOD NOT AVAILABLE")
        return redirect('changestatus',code=302)
  else:
    
    return apology("YOUR NOT WELCOME HERE")


# change store
@app.route("/changestore", methods=["GET","POST"])
@login_required
def changestore():
  if request.method == "GET":
    roles = db.execute("select * from users where id = ? and disable = 0 ", session.get("user_id"))
    if roles[0]['is_admin'] == 1:
      role = "admin"
      stores = db.execute("select * from stores where id != 99 and id != 0 and id != 100")
      usersInfo = db.execute("select users.username,users.id,stores.name from users join stores on users.store_id = stores.id where users.is_manager = 1 and users.store_id != 0 and users.store_id != 99 and users.disable = 0")
      return render_template("/changestore.html",role=role,stores=stores,usersInfo=usersInfo)
    else:
      return apology("YOUR NOT WELCOME HERE")
  else:
    current = request.form.get("currentStore")
    username = request.form.get("username")
    storeSelect= request.form.get("storeSelect")
    if not current or not username or not storeSelect:
      flash("Make sure to fill all the inputs")
      return redirect("/changestore",code=302)
    store_id = db.execute("select * from stores")
    if store_id:
      store_id = store_id[0]['id']
    else:
      flash("store not found!")
      return redirect("/changestore",code=302)
    
    store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
    timestamp = datetime.now()
    timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    sstore_id = db.execute("select id from stores where name = ?",storeSelect)
    if sstore_id:
      sstore_id = sstore_id[0]['id']
    else:
      flash("store not found!")
      return redirect("/changestore",code=302)
    flash(f"User {username} was moved from store {current} to store {storeSelect}")
    db.execute("update users set store_id = ? where username = ?",sstore_id,username)
    db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description) values (?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Change Store","users",f"User {username} has been moved from store {current} to store {storeSelect}")
    return redirect("/changestore",code=302)
  
  
  
#update password
@app.route("/changepassword",methods=["GET","POST"])
@login_required
def changepassword():
    if request.method == "POST":
        username = request.form.get("username")
        pass1 = request.form.get("hash1")
        pass2 = request.form.get("hash2")
        if pass1 != pass2:
            flash("Password didnt match!")
            return redirect("/changepassword", code=302)
        names = db.execute("select username from users")
        if names:
            for name in names:
                if username == name['username']:
                    id = db.execute("select id from users where username =?",username)[0]['id']
                    hashp = generate_password_hash(pass1, salt_length=12)
                    store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
                    timestamp = datetime.now()
                    timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description) values (?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Change password","users",f"Password updated for user: {username}")
                    db.execute("update users set hash = ? where id= ? and username = ?",hashp, id, username)
                    flash(f"Password updated for user: {username}")
                    return redirect("/changepassword", code=302)
        else:
            flash("No names in db")
            return redirect("/changepassword", code=302)
    else:
        names = db.execute("select username from users")
        roles = db.execute("select * from users where id = ?", session.get("user_id"))
        if roles[0]['is_admin'] == 1:
          role = "admin"
          return render_template("/changepassword.html", names=names, role=role)
        else:
          return apology("YOUR NOT ADMIN.. OUT ->")


# manager home
@app.route("/home")
@login_required
def home():
  checkid = db.execute("select is_manager from users where id = ?", session.get("user_id"))
  if checkid[0]['is_manager'] == 1:
    role ="manager"
    uname = db.execute("select username,store_id from users where id = ?", session.get("user_id"))
    store = db.execute("select name from stores where id = ?", uname[0]['store_id'])[0]['name']
    cashiers = db.execute("select cashiers.name,cashiers.id  from cashiers where store_id = ? and disable = 0 order by cashiers.name COLLATE NOCASE",uname[0]['store_id'])
    cdate = db.execute("select cdate from c_date where store_id = ?", uname[0]['store_id'])
    if cdate:
      zdate = cdate[0]['cdate']
    else:
      zdate=""
    info = db.execute("select rate.id,rate.jod,rate.usd,c_date.cdate,rate.user_id from rate join c_date on rate.rdate = c_date.cdate where rate.store_id = ? and c_date.store_id = ?", uname[0]['store_id'],uname[0]['store_id'])
    if info:
      rateCheck = db.execute("select * from rate where id = ?", info[0]['id'])
      if rateCheck:
        if rateCheck[0]['disable'] == 1:
          sstore=store
          return homeview(cdate[0]['cdate'],sstore)
      name = db.execute("select username from users where id = ?", info[0]['user_id'])
      cname = db.execute("select username from users where id = ?",info[0]['user_id'])
      if name:
        dname = name[0]['username']
        cashrep = db.execute("select * from cashreport where store_id = ? and cdate = ? order by cash_number" , uname[0]['store_id'], info[0]['cdate'])
        zrep = db.execute("select * from cashzreport where store_id = ? and cdate = ? order by cash_number", uname[0]['store_id'], zdate)
        ttlzview = {
              'ils': 0.0,
              'usd': 0.0,
              'jod': 0.0,
              'visa_palestine': 0.0,
              'credit': 0.0,
              'easy_life': 0.0,
              'bcheck': 0.0,
              'coupon': 0.0,
              'jawwal_pay': 0.0,
              'visa_arabi': 0.0,
              'ttl_ils': 0.0,
              'ttl_x_report': 0.0,
              'diff': 0.0
            }
        for i in zrep:
          for x in ttlzview:
            ttlzview[x] += i[x]
            ttlzview[x] = round(ttlzview[x], 2)

        zrepview = {}
        if cashrep:
          ttlx = db.execute("select * from cashreport where store_id = ? and cdate = ? order by cash_number", uname[0]['store_id'],zdate)
          ttlview = {
              'ils': 0.0,
              'usd': 0.0,
              'jod': 0.0,
              'visa_palestine': 0.0,
              'credit': 0.0,
              'easy_life': 0.0,
              'bcheck': 0.0,
              'coupon': 0.0,
              'jawwal_pay': 0.0,
              'visa_arabi': 0.0,
              'ttl_ils': 0.0,
              'x_report': 0.0,
              'diff': 0.0
          }
        
          for i in ttlx:
            for x in ttlview:
              ttlview[x] += i[x]
              ttlview[x] = round(ttlview[x], 2)
          for entry in cashrep:
            Found = False
            for z in zrep:
              if z['cash_number'] == entry['cash_number']:
                Found = True
                break
            cash_number = entry['cash_number']
            if not Found:
              if cash_number in zrepview:
                zrepview[cash_number]['x_report'] += entry['x_report']
                zrepview[cash_number]['ttl_ils'] += entry['ttl_ils']
                zrepview[cash_number]['diff'] += entry['diff']
              else:
                zrepview[cash_number] = {
                  'x_report' : entry['x_report'],
                  'ttl_ils' : entry['ttl_ils'],
                  'diff': entry['diff']
                }
          
          if zrep:
            ttlzview = {
              'ils': 0.0,
              'usd': 0.0,
              'jod': 0.0,
              'visa_palestine': 0.0,
              'credit': 0.0,
              'easy_life': 0.0,
              'bcheck': 0.0,
              'coupon': 0.0,
              'jawwal_pay': 0.0,
              'visa_arabi': 0.0,
              'ttl_ils': 0.0,
              'ttl_x_report': 0.0,
              'diff': 0.0
            }
            for i in zrep:
              for x in ttlzview:
                ttlzview[x] += i[x]
                ttlzview[x] = round(ttlzview[x], 2)
            deposit = db.execute("select * from deposit where store_id = ? and cdate = ?", uname[0]['store_id'], zdate)

            return render_template("/home.html",role=role, cashiers=cashiers, info=info, uname=uname, dname=dname, store = store, cashrep = cashrep, cdate=cdate, zrepview=zrepview, zrep = zrep, ttlview=ttlview, ttlzview=ttlzview,deposit=deposit,cname=cname)
          else:
            return render_template("/home.html",role=role, cashiers=cashiers, info=info, uname=uname, dname=dname, store = store, cashrep = cashrep, cdate=cdate, zrepview=zrepview, ttlview=ttlview, ttlzview=ttlzview,cname=cname)
        else:
          return render_template("/home.html",role=role, cashiers=cashiers, info=info, uname=uname, dname=dname, store = store,  cdate=cdate,cname=cname)
        
    return render_template("/home.html",role=role, cashiers=cashiers, uname=uname, store = store, cdate=cdate)
  else:
    return apology("YOUR NOT MANAGER GOT OUT OF HERE!")


# update/create current_date
@app.route("/update_current_date", methods=["GET","POST"])
@login_required
def update_current_date():
  if request.method == "POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      store_id = int(db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id'])
      cdate = request.form.get("selected_date")
      if not cdate:
        flash("You must select date!")
        return redirect("/home", code=302)
      checkRate = db.execute("select * from rate where store_id = ? and rdate = ?",store_id,cdate)
      if checkRate:
        if checkRate[0]['disable'] == 1:
          sstore = db.execute("select name from stores where id = ?", store_id)[0]['name']
          return homeview(cdate,sstore)
      
      cd_obj = datetime.strptime(cdate, "%Y-%m-%d")
      try:
        current_date = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      except IndexError:
        db.execute("insert into c_date (store_id, user_id, cdate) values (?, ?, ?)", store_id, session.get("user_id"), cdate)
        store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
        timestamp = datetime.now()
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"insert", "c_date",f"date created on store number {store_id}",cdate)
      current_date = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      fcd_obj = datetime.strptime(current_date, "%Y-%m-%d")

      if cd_obj == fcd_obj:
          return redirect("/home", code=302)
      else:
          db.execute("update c_date set cdate = ? where store_id = ?", cdate, store_id)
          store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
          timestamp = datetime.now()
          timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
          db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Update", "c_date",f"update date on store number {store_id}",cdate)
          return redirect("/home", code=302)
    else:
        return redirect("/home", code=302)
  else:
    return apology("GET OUT OF HERE!")

# add/update rate
@app.route("/update_rate", methods=["GET","POST"])
@login_required
def update_rate():
    if request.method == "POST":
      uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
      if uinfo[0]['is_manager'] == 1:
        gusd = request.form.get("rate_usd")
        gjod = request.form.get("rate_jod")
        if not gusd:
            flash("Make sure to fill the rate fields!")
            return redirect("/home", code=302)
        elif not gjod:
            flash("Make sure to fill the rate fields!")
            return redirect("/home", code=302)
        else:
            usd = float(gusd)
            jod = float(gjod)
            if usd < 0 or jod < 0:
                flash("rates must be greater than 0!")
                return redirect("/home", code=302)

            store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
            try:
              cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
            except:
              flash("Make sure to pick date first")
              return redirect("/home",code=302)
            checkifexists = db.execute("select * from rate where rdate = ? and store_id = ?", cdate , store_id)
            if checkifexists:
                db.execute("update rate set user_id = ?, timestamp = CURRENT_TIMESTAMP,  usd = ? , jod = ?, timestamp = CURRENT_TIMESTAMP where rdate = ?", session.get("user_id"), usd, jod, cdate)
                store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
                timestamp = datetime.now()
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Update", "rate",f"rate update: usd : {usd}, jod: {jod}",cdate)
                return redirect("/home", code=302)
            else:
                db.execute("insert into rate (store_id, user_id, usd, jod, rdate) values (?, ?, ?, ?, ?)", store_id, session.get("user_id"), usd, jod, cdate)
                store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
                timestamp = datetime.now()
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Insert", "rate",f"rate created: usd : {usd}, jod: {jod}",cdate)
                return redirect("/home", code=302)
    else:
      return apology("YOUR NOT MANAGER GET OUT OF HERE!")
            
@app.route("/cashxreport", methods=["GET","POST"])
@login_required
def cashxreport():
  if request.method =="POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      store_id = int(db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id'])
      ccdate = db.execute("select cdate from c_date where store_id = ?", store_id)
      crate = db.execute("select usd,jod from rate join c_date on rate.rdate = c_date.cdate where c_date.store_id = ?", store_id)
      if not ccdate:
        flash("must select date first!")
        return redirect("/home",code=302)
      if not crate:
        flash("must update rate first!")
        return redirect("/home",code=302)
      cdate = str(ccdate[0]['cdate'])
      rusd = crate[0]['usd']
      rjod = crate[0]['jod']
      cash_number = request.form.get("cash_number")
      if not cash_number:
        flash("select cash!")
        return redirect("/home",code=302)
      cashier_name = request.form.get("cashier_name")
      if not cashier_name:
        flash("select cashier!")
        return redirect("/home",code=302)
      dcashier_number = db.execute("select id from cashiers where store_id = ? and name = ?",store_id, cashier_name)
      if not dcashier_number:
        flash("Cashier not found!")
        return redirect("/home", code=302)

      cashier_number = dcashier_number[0]['id']
      
      iils = (request.form.get("ils"))
      if not iils:
        ils = 0
      else:
        ils = float(iils)
      iusd = (request.form.get("usd"))
      if not iusd:
        usd = 0
      else:
        usd = float(iusd)
      ijod = (request.form.get("jod"))
      if not ijod:
        jod = 0
      else:
        jod = float(ijod)
      ips_visa = (request.form.get("ps_visa"))
      if not ips_visa:
        ps_visa = 0
      else:
        ps_visa = float(ips_visa)
      icredit = (request.form.get("credit"))
      if not icredit:
        credit = 0
      else:
        credit = float(icredit)
      ieasylife = (request.form.get("easylife"))
      if not ieasylife:
        easylife = 0
      else:
        easylife = float(ieasylife)
      ibcheck = (request.form.get("bcheck"))
      if not ibcheck:
        bcheck = 0
      else:
        bcheck = float(ibcheck)
      icoupon = (request.form.get("coupon"))
      if not icoupon:
        coupon = 0
      else:
        coupon = float(icoupon)
      ijawwal_pay = (request.form.get("jawwal_pay"))
      if not ijawwal_pay:
        jawwal_pay = 0
      else:
        jawwal_pay = float(ijawwal_pay)
      iarabi_visa = (request.form.get("arabi_visa"))
      if not iarabi_visa:
        arabi_visa = 0
      else:
        arabi_visa = float(iarabi_visa)
      ix_report =( request.form.get("x_report"))
      if not ix_report:
        flash("make sure to the Fill x-report field")
        return redirect("/home", code=302)
      else:
        x_report = float(ix_report)
      
        
      cash_number = int(cash_number)
      ttl_cash = ils + (usd * rusd) + (jod * rjod) + ps_visa + credit + easylife + bcheck + coupon + jawwal_pay + arabi_visa

      ttl_cash = round(ttl_cash, 2)
      diff = ttl_cash - x_report
      diff = round(diff, 2)   
      
      db.execute("insert into cashreport (user_id, store_id, cash_number, cashier_name, cashier_id, ils, usd, jod, visa_palestine, credit, easy_life, bcheck, coupon, jawwal_pay, visa_arabi, ttl_ils, x_report, diff, rate_usd, rate_jod, cdate) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", session.get("user_id"), store_id, cash_number, cashier_name, cashier_number ,ils ,usd, jod,  ps_visa, credit, easylife, bcheck, coupon, jawwal_pay,arabi_visa, ttl_cash, x_report, diff,rusd,rjod,cdate )
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Insert", "cashreport",f"inserted values: cash_number {cash_number} , cashier_name {cashier_name} , cashier_id {cashier_number} , ils {ils} , usd {usd} , jod {jod} , visa_palestine {ps_visa} , credit {credit} , easy_life {easylife} , bcheck {bcheck} , coupon {coupon} , jawwal_pay {jawwal_pay} , visa_arabi {arabi_visa} , ttl_ils {ttl_cash} , x_report {x_report} , diff {diff} , rate_usd {rusd} , rate_jod {rjod} ",cdate)
      return redirect("/home",code=302)
    else:
      return apology("YOUR NOT MANAGER GET OUT OF HERE!")
  
@app.route("/editx", methods=["GET", "POST"])
@login_required
def editx():
  if request.method =="POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      role = "manager"
    else:
      return apology("YOUR NOT MANAGER GOT OUT OF HERE!")
    row_id = int(request.form.get('row_id'))
    store = db.execute("select name from stores where id = ?", uinfo[0]['store_id'])[0]['name']
    cashiers = db.execute("select cashiers.name,cashiers.id  from cashiers where store_id = ? and disable = 0",uinfo[0]['store_id'])
    cdate = db.execute("select cdate from c_date where store_id = ?", uinfo[0]['store_id'])
    info = db.execute("select jod,usd,cdate,c_date.user_id from rate join c_date on rate.rdate = c_date.cdate where rate.store_id = ? and c_date.store_id = ?", uinfo[0]['store_id'] , uinfo[0]['store_id'])
    cashrep = db.execute("select * from cashreport where id =?",row_id)
    dname = db.execute ("select username from users join cashreport on users.id = cashreport.user_id where cashreport.id = ?", row_id)[0]['username']
    return render_template("/editx.html", role=role, cashrep=cashrep, cashiers=cashiers, uname=uinfo, store = store, cdate=cdate, info=info, dname = dname)


@app.route("/updatecashxreport", methods=["GET","POST"])
@login_required
def updatecashxreport():
  if request.method=="POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      info = db.execute("select username, store_id from users where id = ?",session.get("user_id"))
      store_id = int(info[0]["store_id"])
      username = info[0]["username"]
      crate = db.execute("select usd,jod from rate join c_date on rate.rdate = c_date.cdate where c_date.store_id = ?", store_id)
      rusd = crate[0]['usd']
      rjod = crate[0]['jod']
      iils = (request.form.get("ils"))
      if not iils:
        ils = 0
      else:
        ils = float(iils)
      iusd = (request.form.get("usd"))
      if not iusd:
        usd = 0
      else:
        usd = float(iusd)
      ijod = (request.form.get("jod"))
      if not ijod:
        jod = 0
      else:
        jod = float(ijod)
      ips_visa = (request.form.get("ps_visa"))
      if not ips_visa:
        ps_visa = 0
      else:
        ps_visa = float(ips_visa)
      icredit = (request.form.get("credit"))
      if not icredit:
        credit = 0
      else:
        credit = float(icredit)
      ieasylife = (request.form.get("easylife"))
      if not ieasylife:
        easylife = 0
      else:
        easylife = float(ieasylife)
      ibcheck = (request.form.get("bcheck"))
      if not ibcheck:
        bcheck = 0
      else:
        bcheck = float(ibcheck)
      icoupon = (request.form.get("coupon"))
      if not icoupon:
        coupon = 0
      else:
        coupon = float(icoupon)
      ijawwal_pay = (request.form.get("jawwal_pay"))
      if not ijawwal_pay:
        jawwal_pay = 0
      else:
        jawwal_pay = float(ijawwal_pay)
      iarabi_visa = (request.form.get("arabi_visa"))
      if not iarabi_visa:
        arabi_visa = 0
      else:
        arabi_visa = float(iarabi_visa)
      ix_report = request.form.get("x_report")
      if not ix_report:
        uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
        if uinfo[0]['is_manager'] == 1:
          role = "manager"
        else:
          return apology("YOUR NOT MANAGER GOT OUT OF HERE!")
        row_id = int(request.form.get('row_id'))
        store = db.execute("select name from stores where id = ?", uinfo[0]['store_id'])[0]['name']
        cashiers = db.execute("select cashiers.name,cashiers.id  from cashiers where store_id = ? and disable = 0",uinfo[0]['store_id'])
        cdate = db.execute("select cdate from c_date where store_id = ?", uinfo[0]['store_id'])
        info = db.execute("select jod,usd,cdate,c_date.user_id from rate join c_date on rate.rdate = c_date.cdate where c_date.store_id = ? and rate.store_id = ?", uinfo[0]['store_id'], uinfo[0]['store_id'])
        cashrep = db.execute("select * from cashreport where id =?",row_id)
        dname = db.execute ("select username from users join cashreport on users.id = cashreport.user_id where cashreport.id = ?", row_id)[0]['username']
        flash("make sure to the Fill x-report field")
        return render_template("/editx.html", role=role, cashrep=cashrep, cashiers=cashiers, uname=uinfo, store = store, cdate=cdate, info=info, dname = dname)
      else:
        x_report = float(ix_report)
      
        
      row_id = int(request.form.get("row_id"))
      ttl_cash = ils + (usd * rusd) + (jod * rjod) + ps_visa + credit + easylife + bcheck + coupon + jawwal_pay + arabi_visa

      ttl_cash = round(ttl_cash, 2)
      diff = ttl_cash - x_report
      diff = round(diff, 2)
      
      db.execute( "UPDATE cashreport SET  ils=?, usd=?, jod=?, visa_palestine=?, credit=?, easy_life=?, bcheck=?, coupon=?, jawwal_pay=?, visa_arabi=?, ttl_ils=?, x_report=?, diff=?,timestamp = CURRENT_TIMESTAMP WHERE id=?", ils, usd, jod, ps_visa, credit, easylife, bcheck, coupon, jawwal_pay, arabi_visa, ttl_cash, x_report, diff, row_id)
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id, "Update", "cashreport",f"updated values: ils {ils} ,usd {usd} ,jod {jod} ,visa_palestine {ps_visa} ,credit {credit} ,easy_life {easylife} ,bcheck {bcheck} ,coupon {coupon} ,jawwal_pay {jawwal_pay} ,visa_arabi {arabi_visa} ,ttl_ils {ttl_cash} ,x_report {x_report} ,diff {diff} ,row_id {row_id} ",cdate)
      return redirect("/home", code=302)
    else:
      return apology("YOUR NOT MANAGER GET OUT OF HERE!")


@app.route("/deletexrep", methods=["GET", "POST"])
@login_required
def deletexrep():
  if request.method == "POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
    
      row_id = int(request.form.get("row_id"))
      if row_id:
        db.execute("delete from cashreport where id = ?", row_id)
        store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
        cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
        timestamp = datetime.now()
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Delete","cashreport",f"X-report with row_id {row_id} has been deleted",cdate)
        return redirect("/home", code=302)
      else:
        return apology("GOTCH UA HAHA")
    else:
      return apology("YOUR NOT MANAGER GET OUT OF HERE!")

@app.route("/zreport", methods=["GET","POST"])
@login_required
def zreport():
  if request.method=="POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      store_id = int(db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id'])
      ccdate = db.execute("select cdate from c_date where store_id = ?", store_id)
      crate = db.execute("select usd,jod from rate join c_date on rate.rdate = c_date.cdate where c_date.store_id = ?", store_id)
      if not ccdate:
        flash("Date Not Found!!!")
        return redirect("/home",code=302)
      if not crate:
        flash("must update rate first!")
        return redirect("/home",code=302)
      cdate = str(ccdate[0]['cdate'])
      rusd = crate[0]['usd']
      rjod = crate[0]['jod']
      cash_number = str(request.form.get("row_cash_number"))
      if not cash_number:
        flash("Cash Not Found!!")
        return redirect("/home",code=302)
      # change zils_{cash_number}
      cash_number = str(cash_number)
      iils = (request.form.get("zils_" + cash_number))
      if not iils:
        ils = 0
      else:
        ils = float(iils)
      iusd = (request.form.get("zusd_" + cash_number))
      if not iusd:
        usd = 0
      else:
        usd = float(iusd)
      ijod = (request.form.get("zjod_" + cash_number))
      if not ijod:
        jod = 0
      else:
        jod = float(ijod)
      ips_visa = (request.form.get("zps_visa_" + cash_number))
      if not ips_visa:
        ps_visa = 0
      else:
        ps_visa = float(ips_visa)
      icredit = (request.form.get("zcredit_" + cash_number))
      if not icredit:
        credit = 0
      else:
        credit = float(icredit)
      ieasylife = (request.form.get("zeasylife_" + cash_number))
      if not ieasylife:
        easylife = 0
      else:
        easylife = float(ieasylife)
      ibcheck = (request.form.get("zbcheck_" + cash_number))
      if not ibcheck:
        bcheck = 0
      else:
        bcheck = float(ibcheck)
      icoupon = (request.form.get("zcoupon_" + cash_number))
      if not icoupon:
        coupon = 0
      else:
        coupon = float(icoupon)
      ijawwal_pay = (request.form.get("zjawwal_pay_" + cash_number))
      if not ijawwal_pay:
        jawwal_pay = 0
      else:
        jawwal_pay = float(ijawwal_pay)
      iarabi_visa = (request.form.get("zarabi_visa_" + cash_number))
      if not iarabi_visa:
        arabi_visa = 0
      else:
        arabi_visa = float(iarabi_visa)
      
      cash_number = int(cash_number)
      
      ttl_cash = ils + (usd * rusd) + (jod * rjod) + ps_visa + credit + easylife + bcheck + coupon + jawwal_pay + arabi_visa

      ttl_cash = round(ttl_cash, 2)
      ttl_x = 0
      ttlx = db.execute("select * from cashreport where cash_number = ? and store_id = ? and cdate = ?", cash_number, store_id, cdate)
      for t in ttlx:
        ttl_x = ttl_x + t['x_report']
        
      diff = ttl_cash - ttl_x
      diff = round(diff, 2)  
      ttl_x = round(ttl_x, 2)
      cdate = db.execute("select c_date.cdate from c_date join users on c_date.store_id = users.store_id where users.id = ?", session.get("user_id"))
      
      db.execute("insert into cashzreport (user_id, store_id, cash_number, ils, usd, jod, visa_palestine, credit, easy_life, bcheck, coupon, jawwal_pay, visa_arabi, cdate, ttl_ils, ttl_x_report, diff, rate_usd, rate_jod) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", session.get("user_id"), store_id, cash_number,ils ,usd, jod,  ps_visa, credit, easylife, bcheck, coupon, jawwal_pay, arabi_visa, cdate[0]['cdate'], ttl_cash, ttl_x, diff, rusd, rjod )
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Insert", "cashzreport",f"inserted values: cash_number {cash_number} , ils {ils} , usd {usd} , jod {jod} , visa_palestine {ps_visa} , credit {credit} , easy_life {easylife} , bcheck {bcheck} , coupon {coupon} , jawwal_pay {jawwal_pay} , visa_arabi {arabi_visa} , ttl_ils {ttl_cash} , ttl_x_report {ttl_x} , diff {diff} , rate_usd {rusd} , rate_jod {rjod}",cdate )
      return redirect("/home",code=302)
    else:
      return apology("YOUR NOT MANAGER GET OUT OF HERE!")  
 
  
@app.route("/editzrep", methods=["GET", "POST"])
@login_required
def editxrep():
  if request.method =="POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      role = "manager"
    else:
      return apology("YOUR NOT MANAGER GET OUT OF HERE!")
    row_id = int(request.form.get('row_id'))
    store = db.execute("select name from stores where id = ?", uinfo[0]['store_id'])[0]['name']
    cdate = db.execute("select cdate from c_date where store_id = ?", uinfo[0]['store_id'])
    if cdate:
      zdate = cdate[0]['cdate']
    else:
      zdate = ""
    info = db.execute("select jod,usd,cdate,c_date.user_id from rate join c_date on rate.rdate = c_date.cdate where rate.store_id = ? and c_date.store_id = ?", uinfo[0]['store_id'], uinfo[0]['store_id'])
    
    cashzrep = db.execute("select * from cashzreport where id = ?",row_id)
    dname = db.execute ("select username from users join cashzreport on users.id = cashzreport.user_id where cashzreport.id = ?", row_id)[0]['username']
    return render_template("/editzrep.html", role=role, cashzrep=cashzrep, uname=uinfo, store = store, cdate=cdate, info=info, dname = dname)
  
@app.route("/cashzrep2", methods=["GET","POST"])
@login_required
def updatecashzreport():
  if request.method=="POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      store_id = int(db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id'])
      ccdate = db.execute("select cdate from c_date where store_id = ?", store_id)
      crate = db.execute("select usd,jod from rate join c_date on rate.rdate = c_date.cdate where c_date.store_id = ?", store_id)
      if not ccdate:
        flash("Date Not Found!!!")
        return redirect("/home",code=302)
      if not crate:
        flash("must update rate first!")
        return redirect("/home",code=302)
      cdate = str(ccdate[0]['cdate'])
      rusd = crate[0]['usd']
      rjod = crate[0]['jod']
      cash_number = str(request.form.get("row_cash_number"))
      if not cash_number:
        flash("Cash Not Found!!")
        return redirect("/home",code=302)
      # change zils_{cash_number}
      cash_number = str(cash_number)
      iils = (request.form.get("zils_" + cash_number))
      if not iils:
        ils = 0
      else:
        ils = float(iils)
      iusd = (request.form.get("zusd_" + cash_number))
      if not iusd:
        usd = 0
      else:
        usd = float(iusd)
      ijod = (request.form.get("zjod_" + cash_number))
      if not ijod:
        jod = 0
      else:
        jod = float(ijod)
      ips_visa = (request.form.get("zps_visa_" + cash_number))
      if not ips_visa:
        ps_visa = 0
      else:
        ps_visa = float(ips_visa)
      icredit = (request.form.get("zcredit_" + cash_number))
      if not icredit:
        credit = 0
      else:
        credit = float(icredit)
      ieasylife = (request.form.get("zeasylife_" + cash_number))
      if not ieasylife:
        easylife = 0
      else:
        easylife = float(ieasylife)
      ibcheck = (request.form.get("zbcheck_" + cash_number))
      if not ibcheck:
        bcheck = 0
      else:
        bcheck = float(ibcheck)
      icoupon = (request.form.get("zcoupon_" + cash_number))
      if not icoupon:
        coupon = 0
      else:
        coupon = float(icoupon)
      ijawwal_pay = (request.form.get("zjawwal_pay_" + cash_number))
      if not ijawwal_pay:
        jawwal_pay = 0
      else:
        jawwal_pay = float(ijawwal_pay)
      iarabi_visa = (request.form.get("zarabi_visa_" + cash_number))
      if not iarabi_visa:
        arabi_visa = 0
      else:
        arabi_visa = float(iarabi_visa)
      
      cash_number = int(cash_number)
      
      ttl_cash = ils + (usd * rusd) + (jod * rjod) + ps_visa + credit + easylife + bcheck + coupon + jawwal_pay + arabi_visa

      ttl_cash = round(ttl_cash, 2)
      ttl_x = 0
      #ttlx = db.execute("select x_report from cashreport join c_date on cashreport.cdate = c_date.cdate where cashreport.cash_number = ? and cashreport.store_id = ?",cash_number , store_id)
      ttlx = db.execute("select * from cashreport where cash_number = ? and store_id = ? and cdate = ?", cash_number, store_id, cdate)
      for t in ttlx:
        ttl_x = ttl_x + t['x_report']
      
      diff = ttl_cash - ttl_x
      diff = round(diff, 2)  
      ttl_x = round(ttl_x, 2)

      cdate = db.execute("select c_date.cdate from c_date join users on c_date.store_id = users.store_id where users.id = ?", session.get("user_id"))[0]['cdate']
      cid = db.execute("select id from cashzreport where cash_number = ? and cdate = ? and store_id = ?", cash_number, cdate, store_id)

      row_id = int(request.form.get("row_id"))

      db.execute("update cashzreport set user_id = ?, store_id = ?, ils = ?, usd = ?, jod = ?, visa_palestine = ?, credit = ?, easy_life = ?, bcheck = ?, coupon = ?, jawwal_pay = ?, visa_arabi = ?, ttl_ils = ?, ttl_x_report = ?, diff = ?, rate_usd = ?, rate_jod = ?, timestamp = CURRENT_TIMESTAMP where id = ?",session.get("user_id"), store_id,ils ,usd, jod,  ps_visa, credit, easylife, bcheck, coupon, jawwal_pay, arabi_visa, ttl_cash, ttl_x, diff, rusd, rjod, row_id)
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Update","cashxreport",f"updated values: ils {ils} , usd {usd} , jod {jod} , visa_palestine {ps_visa} , credit {credit} , easy_life {easylife} , bcheck {bcheck} , coupon {coupon} , jawwal_pay {jawwal_pay} , visa_arabi {arabi_visa} , ttl_ils {ttl_cash} , ttl_x_report {ttl_x} , diff {diff} , rate_usd {rusd} , rate_jod {rjod} , row_id {row_id} ",cdate)
      return redirect("/home",code=302)
    else:
      return apology("YOUR NOT MANAGER GET OUT OF HERE!")

@app.route("/deletezrep", methods=["GET","POST"])
@login_required
def deletezrep():
  if request.method=="POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      row_id = int(request.form.get("row_id"))
      if row_id:
        db.execute("delete from cashzreport where id = ?", row_id)
        store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
        cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
        timestamp = datetime.now()
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Delete", "cashzreport",f"z-report with row_id {row_id} has been deleted",cdate)
        return redirect("/home",code=302)
      else:
        return apology("GOTCHUA HAHA!")
    else:
      return apology("YOUR NOT MANAGER GET OUT OF HERE!")   
    
@app.route("/deposit", methods = ["GET","POST"])
@login_required
def deposit():
  if request.method == "POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      
      store_id = int(db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id'])
      ccdate = db.execute("select cdate from c_date where store_id = ?", store_id)
      crate = db.execute("select usd,jod from rate join c_date on rate.rdate = c_date.cdate where c_date.store_id = ?", store_id)
      if not ccdate:
        flash("Date Not Found!!!")
        return redirect("/home",code=302)
      if not crate:
        flash("must update rate first!")
        return redirect("/home",code=302)
      cdate = str(ccdate[0]['cdate'])
      rusd = crate[0]['usd']
      rjod = crate[0]['jod']
      zrp = db.execute("select * from cashzreport where store_id = ? and cdate = ?", store_id, cdate)
      if not zrp:
        flash("must update z-report first!")
        return redirect("/home",code=302)
      
      # ILS
      ils200 = (request.form.get("rate_ils_200"))
      if not ils200:
        ils200 = 0
      else:
        ils200 = float(ils200)
      ils100 = (request.form.get("rate_ils_100"))
      if not ils100:
        ils100 = 0
      else:
        ils100 = float(ils100)
      ils50 = (request.form.get("rate_ils_50"))
      if not ils50:
        ils50 = 0
      else:
        ils50 = float(ils50)
      ils20 = (request.form.get("rate_ils_20"))
      if not ils20:
        ils20 = 0
      else:
        ils20 = float(ils20)
      ils10 = (request.form.get("rate_ils_10"))
      if not ils10:
        ils10 = 0
      else:
        ils10 = float(ils10)
      ils5 = (request.form.get("rate_ils_5"))
      if not ils5:
        ils5 = 0
      else:
        ils5 = float(ils5)
      ils2 = (request.form.get("rate_ils_2"))
      if not ils2:
        ils2 = 0
      else:
        ils2 = float(ils2)
      ils1 = (request.form.get("rate_ils_1"))
      if not ils1:
        ils1 = 0
      else:
        ils1 = float(ils1)
      ils05 = (request.form.get("rate_ils_05"))
      if not ils05:
        ils05 = 0
      else:
        ils05 = float(ils05)
        
      # USD
      usd100 = (request.form.get("rate_usd_100"))
      if not usd100:
        usd100 = 0
      else:
        usd100 = float(usd100)
      usd50 = (request.form.get("rate_usd_50"))
      if not usd50:
        usd50 = 0
      else:
        usd50 = float(usd50)
      usd20 = (request.form.get("rate_usd_20"))
      if not usd20:
        usd20 = 0
      else:
        usd20 = float(usd20)
      usd10 = (request.form.get("rate_usd_10"))
      if not usd10:
        usd10 = 0
      else:
        usd10 = float(usd10)
      usd5 = (request.form.get("rate_usd_5"))
      if not usd5:
        usd5 = 0
      else:
        usd5 = float(usd5)
      usd2 = (request.form.get("rate_usd_2"))
      if not usd2:
        usd2 = 0
      else:
        usd2 = float(usd2)
      usd1 = (request.form.get("rate_usd_1"))
      if not usd1:
        usd1 = 0
      else:
        usd1 = float(usd1)
        
      # JOD
      jod50 = (request.form.get("rate_jod_50"))
      if not jod50:
        jod50 = 0
      else:
        jod50 = float(jod50)
      jod20 = (request.form.get("rate_jod_20"))
      if not jod20:
        jod20 = 0
      else:
        jod20 = float(jod20)
      jod10 = (request.form.get("rate_jod_10"))
      if not jod10:
        jod10 = 0
      else:
        jod10 = float(jod10)
      jod5 = (request.form.get("rate_jod_5"))
      if not jod5:
        jod5 = 0
      else:
        jod5 = float(jod5)
      jod1 = (request.form.get("rate_jod_1"))
      if not jod1:
        jod1 = 0
      else:
        jod1 = float(jod1)
        
      check = db.execute("select * from deposit where store_id = ? and cdate = ?", store_id, cdate)
      if check:
        flash("Deposit already updated! you must delete the current deposit first")
        return redirect("/home",code=302)
      else:
        db.execute("insert into deposit (ils_200, ils_100, ils_50, ils_20, ils_10, ils_5, ils_2, ils_1, ils_05, usd_100, usd_50, usd_20, usd_10, usd_5, usd_2, usd_1, jod_50, jod_20, jod_10, jod_5, jod_1, store_id, user_id, cdate, rate_usd, rate_jod) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", ils200, ils100, ils50, ils20, ils10, ils5, ils2, ils1, ils05, usd100, usd50, usd20, usd10, usd5, usd2, usd1, jod50, jod20, jod10, jod5, jod1, store_id, session.get("user_id"), cdate, rusd,rjod)
        store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
        cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
        timestamp = datetime.now()
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Insert", "deposit", f"inserted values: ils_200 {ils200} , ils_100 {ils100} , ils_50 {ils50} , ils_20 {ils20} , ils_10 {ils10} , ils_5 {ils5} , ils_2 {ils2} , ils_1 {ils1} , ils_0.5 {ils05} , usd_100 {usd100} , usd_50 {usd50} , usd_20 {usd20} , usd_10 {usd10} , usd_5 {usd5} , usd_2 {usd2} , usd_1 {usd1} , jod_50 {jod50} , jod_20 {jod20} , jod_10 {jod10} , jod_5 {jod5} , jod_1 {jod1} , rate_usd {rusd} , rate_jod {rjod} ",cdate)
        flash("Deposit Updated")
        return redirect("/home",code=302)
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")
    
@app.route("/deletedeposit", methods=["GET", "POST"])
@login_required
def deletedeposit():
  if request.method == "POST":
    uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
    if uinfo[0]['is_manager'] == 1:
      
      row_id = request.form.get("deposit_id")
      if row_id:
        row_id = int(row_id)
        db.execute("delete from deposit where id= ?", row_id)
        store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
        cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
        timestamp = datetime.now()
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Delete", "deposit", f"Deposit with row_id {row_id} has been deleted",cdate)
        flash("Deposit deleted")
        return redirect("/home", code=302)
    else:
      return apology("YOUR NOT MANAGER GET OUT OF HERE!")

@app.route("/acchome")
@login_required
def acchome():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
    role = 'is_accounting'
    stores = db.execute("select * from stores where id != 99 and id != 0 and id != 100")
    if stores:
      return render_template("/acchome.html",role=role,stores=stores)
    return render_template("/acchome.html",role=role)
  else:
    return apology("YOUR NOT ACCOUNTING GET OUT OF HERE!")


@app.route("/report", methods=["GET","POST"])
@login_required
def report():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
    role = 'is_accounting'
    if request.method =="POST":
      sdate = request.form.get("selected_date")
      sstore = request.form.get("storeSelect")
      if not sdate or not sstore:
        flash("Must select both date and store!")
        return redirect("/acchome")
      store_id = db.execute("select id from stores where name =?", sstore)
      if store_id:
        store_id = store_id[0]['id']
      else:
        flash("store not found!")
        return redirect("acchome",code=302)
      uname = db.execute("select username from users where id = ?",session.get("user_id"))[0]["username"]
      cashx = db.execute("select * from cashreport where store_id = ? and cdate = ? order by cash_number",store_id,sdate)
      stores = db.execute("select * from stores where id != 99 and id != 0 and id != 100")
      if cashx:
        ttlview = {
            'ils': 0.0,
            'usd': 0.0,
            'jod': 0.0,
            'visa_palestine': 0.0,
            'credit': 0.0,
            'easy_life': 0.0,
            'bcheck': 0.0,
            'coupon': 0.0,
            'jawwal_pay': 0.0,
            'visa_arabi': 0.0,
            'ttl_ils': 0.0,
            'x_report': 0.0,
            'diff': 0.0
        }
        for i in cashx:
          for x in ttlview:
            ttlview[x] += i[x]
            ttlview[x] = round(ttlview[x],2)
      cashz = db.execute("select * from cashzreport where store_id = ? and cdate = ? order by cash_number",store_id,sdate)
      if cashz:
        ttlzview = {
            'ils': 0.0,
            'usd': 0.0,
            'jod': 0.0,
            'visa_palestine': 0.0,
            'credit': 0.0,
            'easy_life': 0.0,
            'bcheck': 0.0,
            'coupon': 0.0,
            'jawwal_pay': 0.0,
            'visa_arabi': 0.0,
            'ttl_ils': 0.0,
            'ttl_x_report': 0.0,
            'diff': 0.0
        }
        for i in cashz:
          for x in ttlzview:
            ttlzview[x] += i[x]
            ttlzview[x] = round(ttlzview[x],2)
      deposit = db.execute("select * from deposit where store_id = ? and cdate = ?",store_id,sdate)
      rate = db.execute("select rate.disable,rate.id,rate.rdate,rate.usd, rate.jod,users.username from rate join users on rate.user_id = users.id where rate.rdate = ? and rate.store_id = ?",sdate,store_id)

      if deposit:

        return render_template("/report.html",role=role,store=sstore,cashx=cashx,cashz=cashz,deposit=deposit,uname=uname,sdate=sdate,rate=rate,ttlzview=ttlzview,ttlview=ttlview,stores=stores)
      elif cashz:
        return render_template("/report.html",role=role,store=sstore,cashx=cashx,cashz=cashz,uname=uname,rate=rate,ttlzview=ttlzview,ttlview=ttlview,stores=stores)
      elif cashx:
        return render_template("/report.html",role=role,store=sstore,cashx=cashx,uname=uname,rate=rate,ttlview=ttlview,stores=stores)
      elif rate:
        return render_template("/report.html",role=role,store=sstore,rate=rate,uname=uname,stores=stores)
      elif stores:
        return render_template("/report.html",role=role,store=sstore,uname=uname,stores=stores)
      else:
        return render_template("/report.html",role=role,store=sstore,uname=uname)
    else:
      if uinfo[0]['is_accounting'] == 1:
        role = 'is_accounting'
        uname = db.execute("select username from users where id = ?",session.get("user_id"))[0]["username"]
        return render_template("/report.html",role=role,uname=uname)
  else:
    return apology("YOUR NOT ACCOUNTING GET OUT OF HERE!")
  
#deposit report
@app.route("/rdeposit",methods=["GET","POST"])
@login_required
def rdeposit():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    if request.method=="GET":
      return render_template("rdeposit.html",role=role)
    else:
      fdate = request.form.get("fromDate2")
      if not fdate:
        flash("Must select From Date!")
        return redirect("/rdeposit",code=302)
      tdate = request.form.get("toDate2")
      if not tdate:
        flash("Must select To Date!")
        return redirect("/rdeposit",code=302)

      store_id = db.execute("select store_id from users where id = ?",session.get("user_id"))[0]['store_id']
      tdeposit = db.execute("select * from deposit where store_id = ? and cdate >= ? and cdate <= ?",store_id,fdate,tdate)
      if tdeposit:
        dates = []
        for i in tdeposit:
          dates.append(i['cdate'])
        ddeposit = {
        'ils_200': 0.0,
        'ils_100': 0.0,
        'ils_50': 0.0,
        'ils_20': 0.0,
        'ils_10': 0.0,
        'ils_5': 0.0,
        'ils_2': 0.0,
        'ils_1': 0.0,
        'ils_05': 0.0,
        'usd_100': 0.0,
        'usd_50': 0.0,
        'usd_20': 0.0,
        'usd_10': 0.0,
        'usd_5': 0.0,
        'usd_2': 0.0,
        'usd_1': 0.0,
        'jod_50': 0.0,
        'jod_20': 0.0,
        'jod_10': 0.0,
        'jod_5': 0.0,
        'jod_1': 0.0,
        }
        for item in tdeposit:
          for key in ddeposit.keys():
            if key in item:
              ddeposit[key] += item[key]

        deposit = []
        deposit.append(ddeposit)
            
        return render_template("/rdeposit.html", role=role, deposit=deposit,dates=dates)
      else:
        flash("Data Not Found")
        return redirect("/rdeposit",code=302)
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")
  
# Lock day work for manager
@app.route("/lockday",methods=["GET","POST"])
@login_required
def lockday():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
    role = 'is_accounting'
    if request.method =="POST":
      action = request.form.get('action')
      if action == 'lock':
        rateId = int(request.form.get("disableValue"))
        cstore_id = db.execute("select * from rate where id = ?",rateId)
        if cstore_id:
          sstore_id = cstore_id[0]['store_id']
        else:
          cstore_id = 'None!'
        store_id = db.execute("select store_id from users where id = ?",session.get("user_id"))[0]['store_id']
        timestamp = datetime.now()
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description, movement_date, timestamp) values(?,?,?,?,?,?,?)",session.get("user_id"),store_id,"Lock","rate",f"Day locked for manager at store {sstore_id}",cstore_id[0]['rdate'],timestamp)
        db.execute("update rate set disable = 1 where id = ? ", rateId)
        return redirect("/acchome",code=302)
      elif action == 'unlock':
        rateId = int(request.form.get("disableValue"))
        cstore_id = db.execute("select * from rate where id = ?",rateId)
        if cstore_id:
          sstore_id = cstore_id[0]['store_id']
        else:
          cstore_id = 'None!'
        store_id = db.execute("select store_id from users where id = ?",session.get("user_id"))[0]['store_id']
        timestamp = datetime.now()
        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description, movement_date, timestamp) values(?,?,?,?,?,?,?)",session.get("user_id"),store_id,"Unlock","rate",f"Day unlocked for manager at store {sstore_id}",cstore_id[0]['rdate'],timestamp)
        db.execute("update rate set disable = 0 where id = ? ", rateId)
        return redirect("/acchome",code=302)
    else:
      return apology("NOT IN THIS WAY :)")
  else:
    return apology("YOUR NOT ACCOUNTING GET OUT OF HERE!")
  
  
def homeview(sdate,sstore):
      if not sdate or not sstore:
        flash("Must select both date and store!")
        return redirect("/acchome")
      store_id = db.execute("select id from stores where name =?", sstore)
      role='manager'
      if store_id:
        store_id = store_id[0]['id']
      else:
        flash("store not found!")
        return redirect("acchome",code=302)
      uname = db.execute("select username from users where id = ?",session.get("user_id"))[0]["username"]
      cashx = db.execute("select * from cashreport where store_id = ? and cdate = ? order by cash_number",store_id,sdate)
      stores = db.execute("select * from stores where id != 99 and id != 0 and id != 100")
      if cashx:
        ttlview = {
            'ils': 0.0,
            'usd': 0.0,
            'jod': 0.0,
            'visa_palestine': 0.0,
            'credit': 0.0,
            'easy_life': 0.0,
            'bcheck': 0.0,
            'coupon': 0.0,
            'jawwal_pay': 0.0,
            'visa_arabi': 0.0,
            'ttl_ils': 0.0,
            'x_report': 0.0,
            'diff': 0.0
        }
        for i in cashx:
          for x in ttlview:
            ttlview[x] += i[x]
            ttlview[x] = round(ttlview[x],2)
      cashz = db.execute("select * from cashzreport where store_id = ? and cdate = ? order by cash_number",store_id,sdate)
      if cashz:
        ttlzview = {
            'ils': 0.0,
            'usd': 0.0,
            'jod': 0.0,
            'visa_palestine': 0.0,
            'credit': 0.0,
            'easy_life': 0.0,
            'bcheck': 0.0,
            'coupon': 0.0,
            'jawwal_pay': 0.0,
            'visa_arabi': 0.0,
            'ttl_ils': 0.0,
            'ttl_x_report': 0.0,
            'diff': 0.0
        }
        for i in cashz:
          for x in ttlzview:
            ttlzview[x] += i[x]
            ttlzview[x] = round(ttlzview[x],2)
      deposit = db.execute("select * from deposit where store_id = ? and cdate = ?",store_id,sdate)
      rate = db.execute("select rate.disable,rate.id,rate.rdate,rate.usd, rate.jod,users.username from rate join users on rate.user_id = users.id where rate.rdate = ? and rate.store_id = ?",sdate,store_id)

      if deposit:
        return render_template("/homeview.html",role=role,store=sstore,cashx=cashx,cashz=cashz,deposit=deposit,uname=uname,sdate=sdate,rate=rate,ttlzview=ttlzview,ttlview=ttlview,stores=stores)
      elif cashz:
        return render_template("/homeview.html",role=role,store=sstore,cashx=cashx,cashz=cashz,uname=uname,rate=rate,ttlzview=ttlzview,ttlview=ttlview,stores=stores)
      elif cashx:
        return render_template("/homeview.html",role=role,store=sstore,cashx=cashx,uname=uname,rate=rate,ttlview=ttlview,stores=stores)
      elif rate:
        return render_template("/homeview.html",role=role,store=sstore,rate=rate,uname=uname,stores=stores)
      elif stores:
        return render_template("/homeview.html",role=role,store=sstore,uname=uname,stores=stores)
      else:
        return render_template("/homeview.html",role=role,store=sstore,uname=uname)
      