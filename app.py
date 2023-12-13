from requirements import *
from login import login
from registration import register

# Set a secret key for the Flask application
app.secret_key = "your_secret_key_here"

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")

@app.route("/")
def index():
    return redirect("/login")

# login
@app.route("/login", methods=["GET", "POST"])
def handle_login():
    return login() 

# register
app.route("/register", methods=["GET", "POST"])(register)

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
        currentDate = datetime.now()
        currentDate = currentDate.strftime("%Y-%m-%d")
        db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description) values (?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id, "Add Store", "stores",f"Store: {name} with number {number} has been added to Stores.")
        db.execute("insert into stores (id, name) values(?,?)", number, name)
        db.execute("insert into bankAccounts (user_id, store_id) values (?, ?)",session.get("user_id"), number)
        db.execute("insert into c_date (store_id, user_id, cdate ) values (?, ?, ?)", number, session.get("user_id"), currentDate)
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
      userInfo = db.execute("select users.username,users.id,stores.name, users.disable from users join stores on users.store_id = stores.id where users.store_id != 0 and users.store_id != 100 order by users.username COLLATE NOCASE")
      cashiersInfo = db.execute("select cashiers.name as username, cashiers.id, stores.name, cashiers.disable from cashiers join stores on cashiers.store_id = stores.id order by cashiers.name COLLATE NOCASE")
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
  uinfo = db.execute("select username,store_id, is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = 'manager'
    store_id = uinfo[0]['store_id']
    store_name = db.execute("select name from stores where id = ?", store_id)
    if request.method == "GET":
      cashiers = db.execute("select cashiers.name,cashiers.id  from cashiers where store_id = ? and disable = 0 order by cashiers.name COLLATE NOCASE",store_id)
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      rate = db.execute("select * from rate where rdate = ? and store_id = ?", cdate, store_id)
      if rate:
        rate_user = db.execute("select username from users where id = ?", rate[0]['user_id'])
      cashrep = db.execute("select * from cashreport where store_id = ? and cdate = ? order by cash_number" , store_id, cdate)
      zrep = db.execute("select * from cashzreport where store_id = ? and cdate = ? order by cash_number", store_id, cdate)
      deposit = db.execute("select * from deposit where store_id = ? and cdate = ?", store_id, cdate)
      
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

      ttlx = db.execute("select * from cashreport where store_id = ? and cdate = ? order by cash_number", store_id, cdate)
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
            
      rateCheck = db.execute("select * from rate where store_id = ? and rdate = ?", store_id, cdate)
      if rateCheck:
        if rateCheck[0]['disable'] == 1:
          sstore=store_name[0]['name']
          return homeview(cdate,sstore)
      
     
      if deposit:
        return render_template("/home.html",role=role, store_name=store_name, cashiers=cashiers, uinfo=uinfo,  rate=rate, rate_user=rate_user, cdate=cdate, cashrep = cashrep, zrepview=zrepview,ttlview=ttlview, ttlzview=ttlzview , deposit=deposit, zrep = zrep)
      elif zrep:
        return render_template("/home.html",role=role, store_name=store_name, cashiers=cashiers, uinfo=uinfo,  rate=rate, rate_user=rate_user, cdate=cdate, cashrep = cashrep, zrepview=zrepview,ttlview=ttlview, ttlzview=ttlzview, zrep=zrep)
      elif cashrep:
        return render_template("/home.html",role=role, store_name=store_name, cashiers=cashiers, uinfo=uinfo,  rate=rate, rate_user=rate_user, cdate=cdate, cashrep = cashrep, zrepview=zrepview,ttlview=ttlview, ttlzview=ttlzview)
      elif rate:
        return render_template("/home.html",role=role, store_name=store_name, cashiers=cashiers, uinfo=uinfo,  rate=rate, rate_user=rate_user, cdate=cdate)
      else:
       return render_template("/home.html",role=role, store_name=store_name, cashiers=cashiers, uinfo=uinfo, cdate=cdate)
    else:
      return apology("GATCHUAA METHOD NOT ALLOWED!")
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")

# update current_date
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
      
      
      cd_obj = datetime.strptime(cdate, "%Y-%m-%d")
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
          checkRate = db.execute("select * from rate where store_id = ? and rdate = ?",store_id,cdate)
          
          if checkRate:
            if checkRate[0]['disable'] == 1:
              sstore = db.execute("select name from stores where id = ?", store_id)[0]['name']
              return homeview(cdate,sstore)
          
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
              checkRate = db.execute("select * from rate where store_id = ? and rdate = ?",store_id,cdate)
              if checkRate:
                if checkRate[0]['disable'] == 1:
                  sstore = db.execute("select name from stores where id = ?", store_id)[0]['name']
                  flash("day is locked!")
                  return homeview(cdate,sstore)
                db.execute("update rate set user_id = ?, timestamp = CURRENT_TIMESTAMP,  usd = ? , jod = ?, timestamp = CURRENT_TIMESTAMP where rdate = ? and store_id = ?", session.get("user_id"), usd, jod, cdate, store_id)
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
      
      row_id = int(request.form.get('row_id'))
      cdate = db.execute("select cdate from cashreport where id = ?", row_id)
      if cdate:
        cdate = cdate[0]['cdate']
      crate = db.execute("select * from rate where store_id = ? and rdate = ?", store_id,cdate)
      
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
      
      row_id = int(request.form.get('row_id'))
      cdate = db.execute("select cdate from cashzreport where id = ?", row_id)
      if cdate:
        cdate = cdate[0]['cdate']
      crate = db.execute("select * from rate where store_id = ? and rdate = ?", store_id,cdate)
      
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
        checkerKeys = db.execute("select cdate,store_id from deposit where id = ?", row_id)
        if not checkerKeys:
          return redirect("/home", code=302)
        disable = db.execute("select disable from rate where store_id = ? and rdate = ?",checkerKeys[0]['store_id'],checkerKeys[0]['cdate'] )
        if disable:
          if disable[0]['disable'] == 1:
            flash("Day is locked CANT BE DELETED")
            return redirect("/home", code=302)
          
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



# bank accounts
@app.route("/bankAccounts", methods=["GET","POST"])
@login_required
def bankAccounts():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
    role = 'is_accounting'
    user = db.execute("select username from users where id = ?", session.get("user_id"))[0]
    if request.method == "GET":
      banks = db.execute("select bankAccounts.id, bankAccounts.store_id, users.username, bankAccounts.bankName, bankAccounts.accountNumber, bankAccounts.timestamp from bankAccounts join users on bankAccounts.user_id = users.id where bankAccounts.store_id != 0 and bankAccounts.store_id != 99 and bankAccounts.store_id != 100 order by bankAccounts.store_id")
      if not banks:
        flash("banks not found, call support")
        return redirect("/acchome",code=302)

      return render_template("/bankAccounts.html",role=role, banks=banks, user=user)
  else:
    return apology("YOUR NOT ACCOUNTING GET OUT OF HERE!")


# update bank accounts
@app.route("/updateBankAccounts",methods=["POST"])
@login_required
def updateBankAccounts():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
    role = 'is_accounting'
    user = db.execute("select username from users where id = ?", session.get("user_id"))[0]
    if request.method == "POST":
      row_id = request.form.get("row_id")
      if not row_id:
        flash("Data not found! call support")
        return redirect("/bankAccounts",code=302)
        
      bank = db.execute("select * from bankAccounts where id = ?", row_id)
      if not bank:
        flash("Data not found! call support")
        return redirect("/bankAccounts",code=302)
      return render_template("/updateBankAccounts.html",role=role, user=user, bank=bank)
  else:
    return apology("YOUR NOT ACCOUNTING GET OUT OF HERE!")


# apply updates for bank account
@app.route("/updateBankAccountsdb",methods=["POST"])
@login_required
def updateBankAccountsdb():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
    if request.method == "POST":
      
      row_id = request.form.get("row_id")
      if not row_id:
        flash("Data not found! call support")
        return redirect("/bankAccounts",code=302)
      else:
        row_id = int(row_id)
      bankName = request.form.get("bankName")
      if not bankName:
        flash("Make sure to fill the Bank Name and must be numbers only!")
        return redirect("/bankAccounts",code=302)
        
      accountNumber = request.form.get("accountNumber")
      if accountNumber:
        accountNumber = int(accountNumber)
      else:
        flash("Make sure to fill Account Number and must be numbers only!")
        return redirect("/bankAccounts",code=302)
      
      store_id = db.execute("select store_id from bankAccounts where id = ?", row_id)
      if not store_id:
        flash("Data not found! call support")
        return redirect("/bankAccounts",code=302)
      
      store_id = store_id[0]['store_id']
      timestamp = datetime.now()
      db.execute("update bankAccounts set bankName = ? , accountNumber = ?, timestamp = ?, user_id = ? where id = ?",bankName , accountNumber, timestamp,session.get("user_id"), row_id)
      
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description) values (?,?,?,?,?,?)",timestamp, session.get("user_id"), 99,"Update", "bankAccounts", f"updated values Bank Name: {bankName} -- Account Number: {accountNumber} for Bravo {store_id}")

      return redirect("/bankAccounts",code=302)
  else:
    return apology("YOUR NOT ACCOUNTING GET OUT OF HERE!")


# JDECo Report
@app.route("/JDECoReport",methods=["POST"])
@login_required
def JDECoReport():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
    role = 'is_accounting'
    user = db.execute("select username from users where id = ?", session.get("user_id"))[0]
    if request.method=="POST":
      FromDate = request.form.get("FromDate")
      if not FromDate:
        flash("you must select From Date")
        return redirect("/acchome",code=302)
      
      ToDate = request.form.get("ToDate")
      if not ToDate:
        flash("you must select To Date")
        return redirect("/acchome",code=302)
      
      store = request.form.get("storeSelect")
      if not store:
        flash("you must select Store")
        return redirect("/acchome",code=302)
      
      fdate = datetime.strptime(FromDate ,"%Y-%m-%d")
      tdate = datetime.strptime(ToDate,"%Y-%m-%d")
      fdate -= timedelta(days=1) 
      if fdate > tdate:
        flash("From Date Error: The start date must be before the end date(To Date)")
        return redirect("/acchome",code=302)
      
      store_id = db.execute("select id from stores where name = ?", store)
      if not store_id:
        flash("Error Selecting store CATCH YUAA")
        return redirect("/acchome",code=302)
      else:
        store_id = store_id[0]['id']
        
      electricity = db.execute("select * from electricity where store_id = ? and cdate >= ? and cdate <= ? order by cdate",store_id, fdate, tdate)
      if not electricity:
        flash("no data found!")
        return redirect("/acchome",code=302)

      total = {
        "holley1":0,
        "holley2":0,
        "invoices":0,
        "actualSale":0,
        "systemSale":0,
        "diff":0
        }
      for line in electricity:
        for x in total:
            total[x] = total[x] + line[x]
           
      return render_template("/JDECoReport.html",role=role, electricity=electricity, total=total,user=user)
    else:
      return apology("NOT IN THIS WAY :)")
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
      rate = db.execute("select * from rate where rdate = ? and store_id = ?",sdate, store_id)
      if rate:
        rate_user = db.execute("select username from users where id = ?", rate[0]['user_id'])

      if deposit:

        return render_template("/report.html",role=role,store=sstore,cashx=cashx,cashz=cashz,deposit=deposit,uname=uname,sdate=sdate,rate=rate,rate_user=rate_user,ttlzview=ttlzview,ttlview=ttlview,stores=stores)
      elif cashz:
        return render_template("/report.html",role=role,store=sstore,cashx=cashx,cashz=cashz,uname=uname,rate=rate,rate_user=rate_user,ttlzview=ttlzview,ttlview=ttlview,stores=stores)
      elif cashx:
        return render_template("/report.html",role=role,store=sstore,cashx=cashx,uname=uname,rate=rate,rate_user=rate_user,ttlview=ttlview,stores=stores)
      elif rate:
        return render_template("/report.html",role=role,store=sstore,rate=rate,rate_user=rate_user,uname=uname,stores=stores)
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


# CDCR Report
@app.route("/CCRReport",methods=["POST"])
@login_required
def CCRReport():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
    role = 'is_accounting'
    if request.method =="POST":
      
      FromDate = request.form.get("FromDate")
      if not FromDate:
        flash("Must select From Date!")
        return redirect("/rdeposit",code=302)
      
      ToDate = request.form.get("ToDate")
      if not ToDate:
        flash("Must select To Date!")
        return redirect("/rdeposit",code=302)
      
      sstore = request.form.get("storeSelect")
      if not FromDate or not sstore:
        flash("Must select both date and store!")
        return redirect("/acchome")
      
      store_id = db.execute("select id from stores where name =?", sstore)
      if store_id:
        store_id = store_id[0]['id']
      else:
        flash("store not found!")
        return redirect("acchome",code=302)
      
      FromDate = datetime.strptime(FromDate ,"%Y-%m-%d")
      ToDate = datetime.strptime(ToDate,"%Y-%m-%d")
      tmp = FromDate
      
      dates=[]
      
      while tmp <= ToDate:
        FromDate = tmp
        FromDate = FromDate.strftime("%Y-%m-%d")
        dates.append({"cdate":FromDate})
        tmp += timedelta(days=1)
      
      DATA = False  
      ttlview = []
      for day in dates:
        cashx = db.execute("select * from cashreport where store_id = ? and cdate = ?",store_id, day['cdate'])
        if cashx:
          TTLV = {
              'cdate':"",
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
            for x in TTLV:
              if isinstance(TTLV[x],str):
                TTLV[x] = day['cdate']
              else:
                TTLV[x] += i[x]
                TTLV[x] = round(TTLV[x],2)
                DATA = True
              
          ttlview.append(TTLV)

        rate = db.execute("select * from rate where rdate = ?  and store_id = ?",day['cdate'], store_id)
        for ttl in ttlview:
            if day['cdate'] == ttl['cdate']:
              ttl['rate_usd'] = rate[0]['usd']
              ttl['rate_jod'] = rate[0]['jod']
              ttl['disable'] = rate[0]['disable']
        
        deposit = db.execute("select * from deposit where cdate = ? and store_id = ?", day['cdate'], store_id)
        for ttl2 in ttlview:
          if deposit:
            if day['cdate'] == ttl2['cdate']:
              ttl2['deposit'] = 1
              break
          else:
            if ttl2['cdate'] == day['cdate']:
              ttl2['deposit'] = 0
              break

      cashx = {}
      
      if DATA:
        return render_template("/CCRReport.html",role=role,sstore=sstore,ttlview=ttlview)
      else:
        flash("No Data Found!")
        return redirect("acchome",code=302)
    else:
      return apology("METHOD NOT ALLOWED!")
  else:
    return apology("YOUR NOT ACCOUNTING GET OUT OF HERE!")
  






#deposit report
@app.route("/rdeposit",methods=["GET","POST"])
@login_required
def rdeposit():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    store = db.execute("select name from stores where id = ?", uinfo[0]['store_id'])[0]['name']
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
      
      studNumber = request.form.get("studNumber")
      notes = request.form.get("notes")

        
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
        bankAccount = db.execute("select * from bankAccounts where store_id = ?", store_id)
              
        if bankAccount:

          electricity = db.execute("select * from electricity where store_id = ? and cdate >= ? and cdate <= ? order by cdate",store_id, fdate, tdate)
          palpay = db.execute("select * from palpay where store_id = ? and cdate >= ? and cdate <= ? order by cdate",store_id, fdate, tdate)
          
          if palpay:
            total_palpay = {"cash_ils":0, "cash_usd":0, "cash_jod":0}
            for line in palpay:
              for x in total_palpay:
                total_palpay[x] = total_palpay[x] + line[x]
                
          if electricity:
            total_electricity = {"actualSale":0}
            for line in electricity:
              for x in total_electricity:
                  total_electricity[x] = total_electricity[x] + line[x]
          
          #convert lists to json string (something hot and new :D)
          if tdeposit:
            deposit_json = json.dumps(tdeposit)
          else:
            deposit_json = None
            
          if bankAccount:
            bankAccount_json = json.dumps(bankAccount)
          else:
            bankAccount_json = None
          
          if electricity:
            electricity_json = json.dumps(electricity)
          else:
            electricity_json = None
            
          if palpay:
            palpay_json = json.dumps(palpay)
          else:
            palpay_json = None
            
          if dates: 
            dates_json = json.dumps(dates)
          else:
            dates_json = None
          
          
          timestamp = datetime.now()
          timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
          
          
          
          
          db.execute("insert into deposit_report (store_id, user_id, deposit_json, bankAccount_json, electricity_json, palpay_json, dates_json, role, store, fdate, tdate, studNumber, notes, timestamp) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", store_id, session.get("user_id"), deposit_json, bankAccount_json, electricity_json, palpay_json, dates_json, role, store, fdate, tdate, studNumber, notes, timestamp)
          db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Insert", "deposit_report", f"inserted values:\nstore_id: { store_id } user_id: { session.get('user_id') } deposit_json: { deposit_json } bankAccount_json: { bankAccount_json } electricity_json: { electricity_json } palpay_json: { palpay_json } dates_json: { dates_json } role: { role } store: { store } fdate: { fdate } tdate: { tdate } studNumber: { studNumber } notes: {notes  } timestamp: { timestamp }",fdate)
          
          bankAccount=bankAccount[0]
          
          if electricity and palpay:
            if studNumber and notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, studNumber=studNumber, total_electricity=total_electricity, notes=notes, total_palpay=total_palpay)
            elif notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, total_electricity=total_electricity, notes=notes, total_palpay=total_palpay)
            elif studNumber:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, studNumber=studNumber, total_electricity=total_electricity, total_palpay=total_palpay)
            else:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, total_electricity=total_electricity, total_palpay=total_palpay)
          elif electricity:
            if studNumber and notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, studNumber=studNumber, total_electricity=total_electricity, notes=notes)
            elif notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, total_electricity=total_electricity, notes=notes)
            elif studNumber:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, studNumber=studNumber, total_electricity=total_electricity)
            else:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, total_electricity=total_electricity)
          elif palpay:
            if studNumber and notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, studNumber=studNumber, notes=notes, total_palpay=total_palpay)
            elif notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, notes=notes, total_palpay=total_palpay)
            elif studNumber:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, studNumber=studNumber, total_palpay=total_palpay)
            else:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, total_palpay=total_palpay)
          else:
            if studNumber and notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, studNumber=studNumber, notes=notes)
            elif notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, notes=notes)
            elif studNumber:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount, studNumber=studNumber)
            else:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, bankAccount=bankAccount)
            
        else:
          electricity = db.execute("select * from electricity where store_id = ? and cdate >= ? and cdate <= ? order by cdate",store_id, fdate, tdate)
          palpay = db.execute("select * from palpay where store_id = ? and cdate >= ? and cdate <= ? order by cdate",store_id, fdate, tdate)
          
          if palpay:
            total_palpay = {"cash_ils":0, "cash_usd":0, "cash_jod":0}
            for line in palpay:
              for x in total_palpay:
                total_palpay[x] = total_palpay[x] + line[x]
                
          if electricity:
            total_electricity = {"actualSale":0}
            for line in electricity:
              for x in total_electricity:
                  total_electricity[x] = total_electricity[x] + line[x]
          
          #convert lists to json string (something hot and new :D)

          deposit_json = json.dumps(tdeposit)
          electricity_json = json.dumps(electricity)
          palpay_json = json.dumps(palpay)
          dates_json = json.dumps(dates)
          
          timestamp = datetime.now()
          timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
          
          db.execute("insert into deposit_report (store_id, user_id, deposit_json, electricity_json, palpay_json, dates_json, role, store, fdate, tdate, studNumber, notes, timestamp) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", store_id, session.get("user_id"), deposit_json, electricity_json, palpay_json, dates_json, role, store, fdate, tdate, studNumber, notes, timestamp)
          db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Insert", "deposit_report", f"inserted values:\nstore_id: { store_id } user_id: { session.get('user_id') } deposit_json: { deposit_json } electricity_json: { electricity_json } palpay_json: { palpay_json } dates_json: { dates_json } role: { role } store: { store } fdate: { fdate } tdate: { tdate } studNumber: { studNumber } notes: {notes  } timestamp: { timestamp }",fdate)

          if electricity and palpay:
           
            if studNumber and notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, studNumber=studNumber, total_electricity=total_electricity, notes=notes, total_palpay=total_palpay)
            elif notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, total_electricity=total_electricity, notes=notes, total_palpay=total_palpay)
            elif studNumber:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, studNumber=studNumber, total_electricity=total_electricity, total_palpay=total_palpay)
            else:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, total_electricity=total_electricity, total_palpay=total_palpay)
          elif electricity:
            if studNumber and notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, studNumber=studNumber, total_electricity=total_electricity, notes=notes)
            elif notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, total_electricity=total_electricity, notes=notes)
            elif studNumber:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, studNumber=studNumber, total_electricity=total_electricity)
            else:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, total_electricity=total_electricity)
          elif palpay:
            if studNumber and notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, studNumber=studNumber, notes=notes, total_palpay=total_palpay)
            elif notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, notes=notes, total_palpay=total_palpay)
            elif studNumber:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, studNumber=studNumber, total_palpay=total_palpay)
            else:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, total_palpay=total_palpay)
          else:
            if studNumber and notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, studNumber=studNumber, notes=notes)
            elif notes:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, notes=notes)
            elif studNumber:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store, studNumber=studNumber)
            else:
              return render_template("/bankreport.html", role=role, deposit=deposit,dates=dates,store=store)
      else:
        flash("Data Not Found")
        return redirect("/rdeposit",code=302)
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")


# Services
@app.route("/services", methods=["GET","POST"])
@login_required
def services():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    Userame = uinfo[0]['username']
    if request.method == "GET":
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      if not cdate:
        flash("Please select date first!")
        return redirect("/home",code=302)
      
      checkRate = db.execute("select * from rate where store_id = ? and rdate = ?",store_id,cdate)
      if checkRate:
        if checkRate[0]['disable'] == 1:
          return redirect("/servicesView",code=302)
      
      
      currentDate = cdate
      electricity = db.execute("select * from electricity where cdate = ? and store_id = ?", cdate, store_id)
      if electricity:
        electricity=electricity[0]
      palpay = db.execute("select * from palpay where store_id = ? and cdate = ?", store_id, cdate)
      if palpay:
        palpay=palpay[0]
      if electricity and palpay:
          return render_template("/services.html",role=role, electricity=electricity, cdate=cdate, Userame=Userame, currentDate=currentDate, palpay=palpay)
      elif electricity:
        return render_template("/services.html",role=role, electricity=electricity, cdate=cdate, Userame=Userame, currentDate=currentDate)
      elif palpay:
        return render_template("/services.html",role=role, palpay=palpay, cdate=cdate, Userame=Userame, currentDate=currentDate)
      
      return render_template("/services.html",role=role, Userame=Userame, currentDate=currentDate)
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")


# services view
@app.route("/servicesView")
@login_required
def servicesView():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    Userame = uinfo[0]['username']
    if request.method == "GET":
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      if not cdate:
        flash("Please select date first!")
        return redirect("/home",code=302)
      currentDate = cdate
      electricity = db.execute("select * from electricity where cdate = ? and store_id = ?", cdate, store_id)
      if electricity:
        electricity=electricity[0]
        
      palpay = db.execute("select * from palpay where store_id = ? and cdate = ?", store_id, cdate)
      if palpay:
        palpay=palpay[0]
        
      if electricity and palpay:
          return render_template("/servicesView.html",role=role, electricity=electricity, cdate=cdate, Userame=Userame, currentDate=currentDate, palpay=palpay)
      elif electricity:
        return render_template("/servicesView.html",role=role, electricity=electricity, cdate=cdate, Userame=Userame, currentDate=currentDate)
      elif palpay:
        return render_template("/servicesView.html",role=role, palpay=palpay, cdate=cdate, Userame=Userame, currentDate=currentDate)
      return render_template("/servicesView.html",role=role, Userame=Userame, currentDate=currentDate)
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")
  
  
# electricity
@app.route("/electricity",methods=["POST"])
@login_required
def electricity():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    if request.method == "POST":
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      if not cdate:
        flash("Please select date first!")
        return redirect("/home",code=302)
      currentDate = cdate
      holley1 = (request.form.get("holley1"))
      if not holley1:
        holley1 = 0
      else:
        holley1 = float(holley1)
      
      holley2 = (request.form.get("holley2"))
      if not holley2:
        holley2 = 0
      else:
        holley2 = float(holley2)
        
      invoices = (request.form.get("invoices"))
      if not invoices:
        invoices = 0
      else:
        invoices = float(invoices)
      
      actualSale = request.form.get("actualSale")
      if not actualSale:
        actualSale = 0
      else:
        actualSale = float(actualSale)
      if actualSale == 0:
        flash("Actual Sale must be more than 0")
        return redirect("/services",code=302)
      
      systemSale = holley1 + holley2 + invoices
      if not systemSale:
        systemSale = 0

      if systemSale <=0:
        flash("System Sale must be more than 0")
        return redirect("/services",code=302)
      
      difference = actualSale - systemSale
      if not difference:
        difference = 0

      
      balance = (request.form.get("balance"))
      if not balance:
        balance = 0
      else:
        balance = float(balance)
      
      notes = (request.form.get("notes"))
      if not notes:
        notes = ""
      electricity = db.execute("select * from electricity where cdate = ? and store_id = ?", cdate, store_id)
      if electricity:
        flash("Data already exisit for this day")
        return redirect("/services",code=302)
      
      db.execute("insert into electricity (user_id, store_id, holley1, holley2, invoices, actualSale, systemSale, diff, remainingBalance, notes, cdate) values (?,?,?,?,?,?,?,?,?,?,?)", session.get("user_id"), store_id, holley1, holley2, invoices, actualSale, systemSale, difference, balance, notes, cdate )
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (timestamp,user_id, store_id, movement_type, m_table, m_description,movement_date) values (?,?,?,?,?,?,?)",timestamp, session.get("user_id"), store_id,"Insert", "electricity", f"inserted values  holley1: {holley1}, holley2: {holley2}, invoices: {invoices}, actualSale: {actualSale}, systemSale: {systemSale}, difference: {difference}, balance: {balance}, notes: {notes}",cdate)
      return redirect("/services",code=302)
    else:
      return apology("METHOD NOT ALLOWED!!!")
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")


# edit electricity
@app.route("/editElectricity", methods=["GET","POST"])
@login_required
def editElectricity():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    Userame = uinfo[0]['username']
    if request.method =="POST":
      row_id = request.form.get("row_id")
      if not row_id:
        flash("Table not found!")
        return redirect("/services",code=302)
      cdate = db.execute("select cdate from c_date where store_id = ?", uinfo[0]['store_id'])[0]['cdate']
      if not cdate:
        flash("Please select date first!")
        return redirect("/home",code=302)
      currentDate = cdate
      electricity = db.execute("select * from electricity where id = ?", row_id)
      electricity = electricity[0]
      
      return render_template("/editElectricity.html",role=role, electricity=electricity, Userame=Userame, currentDate=currentDate)
    
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")    


# delete electricity
@app.route("/deleteElectricity", methods=["POST"])
@login_required
def deleteElectricity():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    if request.method =="POST":
      row_id = request.form.get("row_id")
      if not row_id:
        flash("Table not found!")
        return redirect("/services",code=302)
      cdate = db.execute("select cdate from electricity where id = ?", row_id)[0]['cdate']
      db.execute("delete from electricity where id = ?", row_id)
      
      store_id = db.execute("select store_id from users where id = ?",session.get("user_id"))[0]['store_id']
      
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description, movement_date, timestamp) values(?,?,?,?,?,?,?)",session.get("user_id"),store_id,"Delete","electricity",f"data has been deleted from store {store_id}",cdate,timestamp)
      
      
      flash("Table has been deleted successfully")
      return redirect("/services",code=302)
    
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")  
  


# update electricity
@app.route("/updateElectricity",methods=["POST"])
@login_required
def updateElectricity():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    if request.method =="POST":
      row_id = request.form.get("row_id")
      if not row_id:
        flash("Table not found!")
        return redirect("/services",code=302)

      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      if not cdate:
        flash("Please select date first!")
        return redirect("/home",code=302)
      holley1 = (request.form.get("holley1"))
      if not holley1:
        holley1 = 0
      else:
        holley1 = float(holley1)
      
      holley2 = (request.form.get("holley2"))
      if not holley2:
        holley2 = 0
      else:
        holley2 = float(holley2)
        
      invoices = (request.form.get("invoices"))
      if not invoices:
        invoices = 0
      else:
        invoices = float(invoices)
      
      actualSale = request.form.get("actualSale")
      if not actualSale:
        actualSale = 0
      else:
        actualSale = float(actualSale)
        
      if actualSale == 0:
        flash("Actual Sale must be more than 0")
        return redirect("/services",code=302)
      
      systemSale = holley1 + holley2 + invoices
      if not systemSale:
        systemSale = 0

      if systemSale <=0:
        flash("System Sale must be more than 0")
        return redirect("/services",code=302)
      
      difference = actualSale - systemSale
      if not difference:
        difference = 0

      
      balance = (request.form.get("balance"))
      if not balance:
        balance = 0
      else:
        balance = float(balance)
      
      notes = (request.form.get("notes"))
      if not notes:
        notes = ""
      
      db.execute("update electricity set user_id = ?, holley1 = ?, holley2 = ?, invoices = ?, actualSale = ?, systemSale = ?, diff = ?, remainingBalance = ?, notes = ? where id = ?", session.get("user_id"), holley1, holley2, invoices, actualSale, systemSale, difference, balance, notes, row_id)

      cdate = db.execute("select cdate from electricity where id = ?", row_id)[0]['cdate']
      store_id = db.execute("select store_id from users where id = ?",session.get("user_id"))[0]['store_id']
      
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description, movement_date, timestamp) values(?,?,?,?,?,?,?)",session.get("user_id"),store_id,"Update","electricity",f"data has been Updated from store {store_id}, values :\nholley1: {holley1}, holley2: {holley2}, invoices: {invoices}, actualSale: {actualSale}, systemSale: {systemSale}, diff: {difference}, remainingBalance: {balance}, notes: {notes}",cdate,timestamp)
      
      
      flash("Table has been Updated successfully")
      return redirect("/services",code=302)
    
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")  


# palpay
@app.route("/palpay",methods=["POST"])
@login_required
def palpay():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    if request.method == "POST":
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      if not cdate:
        flash("Please select date first!")
        return redirect("/home",code=302)
      currentDate = cdate
      
      sys_ils = request.form.get("sys_ils")
      if not sys_ils:
        sys_ils = 0
      else:
        sys_ils = float(sys_ils)
        
      cash_ils = request.form.get("cash_ils")
      if not cash_ils:
        cash_ils = 0
      else:
        cash_ils = float(cash_ils)
        
      visa_ils = request.form.get("visa_ils")
      if not visa_ils:
        visa_ils = 0
      else:
        visa_ils= float(visa_ils)
        
      ttl_ils = float(cash_ils + visa_ils)
        
      diff_ils = float(sys_ils - ttl_ils)
        
      note_ils = request.form.get("note_ils")
      if not note_ils:
        note_ils = ""

      sys_usd = request.form.get("sys_usd")
      if not sys_usd:
        sys_usd = 0
      else:
        sys_usd = float(sys_usd)
        
      cash_usd = request.form.get("cash_usd")
      if not cash_usd:
        cash_usd = 0
      else:
        cash_usd = float(cash_usd)
        
      visa_usd = request.form.get("visa_usd")
      if not visa_usd:
        visa_usd = 0
      else:
        visa_usd= float(visa_usd)
        
      ttl_usd = float(cash_usd + visa_usd)
        
      diff_usd = float(sys_usd - ttl_usd)
        
      note_usd = request.form.get("note_usd")
      if not note_usd:
        note_usd = ""
        
      sys_jod = request.form.get("sys_jod")
      if not sys_jod:
        sys_jod = 0
      else:
        sys_jod = float(sys_jod)
        
      cash_jod = request.form.get("cash_jod")
      if not cash_jod:
        cash_jod = 0
      else:
        cash_jod = float(cash_jod)
        
      visa_jod = request.form.get("visa_jod")
      if not visa_jod:
        visa_jod = 0
      else:
        visa_jod= float(visa_jod)
        
      ttl_jod = float(cash_jod + visa_jod)
        
      diff_jod = float(sys_jod - ttl_jod)
        
      note_jod = request.form.get("note_jod")
      if not note_jod:
        note_jod = ""  
      
      x = ttl_ils + ttl_usd + ttl_jod
      if x <= 0:
        flash("Total income must be more than 0")
        return redirect("/services",code=302)
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into palpay (store_id, user_id, sys_ils, cash_ils, visa_ils, ttl_ils, diff_ils, note_ils, sys_usd, cash_usd, visa_usd, ttl_usd, diff_usd, note_usd, sys_jod, cash_jod, visa_jod, ttl_jod, diff_jod, note_jod, cdate, timestamp) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",store_id, session.get("user_id"), sys_ils, cash_ils, visa_ils, ttl_ils, diff_ils, note_ils, sys_usd, cash_usd, visa_usd, ttl_usd, diff_usd, note_usd, sys_jod, cash_jod, visa_jod, ttl_jod, diff_jod, note_jod, cdate, timestamp)
      db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description, movement_date, timestamp) values(?,?,?,?,?,?,?)",session.get("user_id"),store_id,"Insert","palpay",f"values sys_ils: { sys_ils} cash_ils: {cash_ils} visa_ils: {visa_ils} ttl_ils: { ttl_ils} diff_ils: {diff_ils} note_ils: {note_ils} sys_usd: { sys_usd} cash_usd: {cash_usd} visa_usd: {visa_usd} ttl_usd: { ttl_usd} diff_usd: {diff_usd} note_usd: {note_usd} sys_jod: { sys_jod} cash_jod: {cash_jod} visa_jod: {visa_jod} ttl_jod: { ttl_jod} diff_jod: {diff_jod} note_jod: {note_jod} ", cdate, timestamp)
      return redirect("/services",code=302)
    else:
      return apology("GATCHYAA GET OUT :)")
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")



# edit palpay
@app.route("/editPalpay",methods=["POST"])
@login_required
def editPalpay():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    Userame = uinfo[0]['username']
    if request.method == "POST":
      row_id = request.form.get("row_id")
      if not row_id:
        flash("Data not found, Call Support!")
        return redirect("/services",code=302)
      palpay = db.execute("select * from palpay where id = ?", row_id)
      if not palpay:
        flash("Data not found, Call Support!")
        return redirect("/services",code=302)
      palpay = palpay[0]
      currentDate = palpay['cdate']
      return render_template("/editPalpay.html",role=role, palpay=palpay, cdate=currentDate, Userame=Userame, currentDate=currentDate)
    else:
      return apology("Method not allowed :)")
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")


# delete palpay
@app.route("/deletePalpay",methods=["POST"])
@login_required
def deletePalpay():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    Userame = uinfo[0]['username']
    if request.method == "POST":
      row_id = request.form.get("row_id")
      if not row_id:
        flash("Data not found, Call Support!")
        return redirect("/services",code=302)
      palpay = db.execute("select * from palpay where id = ?", row_id)
      if not palpay:
        flash("Data not found, Call Support!")
        return redirect("/services",code=302)
      palpay = palpay[0]
      
      cdate = db.execute("select cdate from palpay where id = ?", row_id)[0]['cdate']
      db.execute("delete from palpay where id = ?", row_id)
      
      store_id = db.execute("select store_id from users where id = ?",session.get("user_id"))[0]['store_id']
      
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description, movement_date, timestamp) values(?,?,?,?,?,?,?)",session.get("user_id"),store_id,"Delete","palpay",f"data has been deleted from store {store_id}, values:\n{palpay}",cdate,timestamp)
      flash("Table has been deleted successfully!")
      return redirect("/services",code=302)
    else:
      return apology("Method not allowed :)")
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")


# update palpay
@app.route("/updatePalpay",methods=["POST"])
@login_required
def updatePalpay():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    if request.method == "POST":
      store_id = db.execute("select store_id from users where id = ?", session.get("user_id"))[0]['store_id']
      cdate = db.execute("select cdate from c_date where store_id = ?", store_id)[0]['cdate']
      if not cdate:
        flash("Please select date first!")
        return redirect("/home",code=302)
      currentDate = cdate
      row_id = request.form.get("row_id")
      if not row_id:
        flash("Data not found, Call Support!")
        return redirect("/services",code=302)
      
      sys_ils = request.form.get("sys_ils")
      if not sys_ils:
        sys_ils = 0
      else:
        sys_ils = float(sys_ils)
        
      cash_ils = request.form.get("cash_ils")
      if not cash_ils:
        cash_ils = 0
      else:
        cash_ils = float(cash_ils)
        
      visa_ils = request.form.get("visa_ils")
      if not visa_ils:
        visa_ils = 0
      else:
        visa_ils= float(visa_ils)
        
      ttl_ils = float(cash_ils + visa_ils)
        
      diff_ils = float(sys_ils - ttl_ils)
        
      note_ils = request.form.get("note_ils")
      if not note_ils:
        note_ils = ""

      sys_usd = request.form.get("sys_usd")
      if not sys_usd:
        sys_usd = 0
      else:
        sys_usd = float(sys_usd)
        
      cash_usd = request.form.get("cash_usd")
      if not cash_usd:
        cash_usd = 0
      else:
        cash_usd = float(cash_usd)
        
      visa_usd = request.form.get("visa_usd")
      if not visa_usd:
        visa_usd = 0
      else:
        visa_usd= float(visa_usd)
        
      ttl_usd = float(cash_usd + visa_usd)
        
      diff_usd = float(sys_usd - ttl_usd)
        
      note_usd = request.form.get("note_usd")
      if not note_usd:
        note_usd = ""
        
      sys_jod = request.form.get("sys_jod")
      if not sys_jod:
        sys_jod = 0
      else:
        sys_jod = float(sys_jod)
        
      cash_jod = request.form.get("cash_jod")
      if not cash_jod:
        cash_jod = 0
      else:
        cash_jod = float(cash_jod)
        
      visa_jod = request.form.get("visa_jod")
      if not visa_jod:
        visa_jod = 0
      else:
        visa_jod= float(visa_jod)
        
      ttl_jod = float(cash_jod + visa_jod)
        
      diff_jod = float(sys_jod - ttl_jod)
        
      note_jod = request.form.get("note_jod")
      if not note_jod:
        note_jod = ""  
      
      x = ttl_ils + ttl_usd + ttl_jod
      if x <= 0:
        flash("Total income must be more than 0")
        return redirect("/services",code=302)
      timestamp = datetime.now()
      timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      db.execute("update palpay set user_id = ?, sys_ils = ?, cash_ils = ?, visa_ils = ?, ttl_ils = ?, diff_ils = ?, note_ils = ?, sys_usd = ?, cash_usd = ?, visa_usd = ?, ttl_usd = ?, diff_usd = ?, note_usd = ?, sys_jod = ?, cash_jod = ?, visa_jod = ?, ttl_jod = ?, diff_jod = ?, note_jod = ?, cdate = ?, timestamp = ? where id = ?", session.get("user_id"), sys_ils, cash_ils, visa_ils, ttl_ils, diff_ils, note_ils, sys_usd, cash_usd, visa_usd, ttl_usd, diff_usd, note_usd, sys_jod, cash_jod, visa_jod, ttl_jod, diff_jod, note_jod, cdate, timestamp, row_id)
      db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description, movement_date, timestamp) values(?,?,?,?,?,?,?)",session.get("user_id"),store_id,"Update","palpay",f"values sys_ils: { sys_ils} cash_ils: {cash_ils} visa_ils: {visa_ils} ttl_ils: { ttl_ils} diff_ils: {diff_ils} note_ils: {note_ils} sys_usd: { sys_usd} cash_usd: {cash_usd} visa_usd: {visa_usd} ttl_usd: { ttl_usd} diff_usd: {diff_usd} note_usd: {note_usd} sys_jod: { sys_jod} cash_jod: {cash_jod} visa_jod: {visa_jod} ttl_jod: { ttl_jod} diff_jod: {diff_jod} note_jod: {note_jod} ", cdate, timestamp)
      flash("Palpay table has beed updated successfully")
      return redirect("/services",code=302)
    else:
      return apology("GATCHYAA GET OUT :)")
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")



# palpay report
@app.route("/palpayReport",methods=["POST"])
@login_required
def palpayReport():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
    role = 'is_accounting'
    user = db.execute("select username from users where id = ?", session.get("user_id"))[0]
    if request.method =="POST":
      FromDate = request.form.get("FromDate")
      if not FromDate:
        flash("you must select From Date")
        return redirect("/acchome",code=302)
      
      ToDate = request.form.get("ToDate")
      if not ToDate:
        flash("you must select To Date")
        return redirect("/acchome",code=302)
      
      store = request.form.get("storeSelect")
      if not store:
        flash("you must select Store")
        return redirect("/acchome",code=302)
      
      fdate = datetime.strptime(FromDate ,"%Y-%m-%d")
      tdate = datetime.strptime(ToDate,"%Y-%m-%d")
      fdate -= timedelta(days=1)
      if fdate > tdate:
        flash("From Date Error: The start date must be before the end date(To Date)")
        return redirect("/acchome",code=302)
      
      store_id = db.execute("select id from stores where name = ?", store)
      if not store_id:
        flash("Error Selecting store CATCH YUAA")
        return redirect("/acchome",code=302)
      else:
        store_id = store_id[0]['id']
      
      palpay = db.execute("select * from palpay where store_id = ? and cdate >= ? and cdate <= ? order by cdate",store_id, fdate, tdate)
      if not palpay:
        flash("no data found!")
        return redirect("/acchome",code=302)
      total = {
        "sys_ils":0,
        "cash_ils":0,
        "visa_ils":0,
        "ttl_ils":0,
        "diff_ils":0,
        "sys_usd":0,
        "cash_usd":0,
        "visa_usd":0,
        "ttl_usd":0,
        "diff_usd":0,
        "sys_jod":0,
        "cash_jod":0,
        "visa_jod":0,
        "ttl_jod":0,
        "diff_jod":0,
        }
      for line in palpay:
        for x in total:
            total[x] = total[x] + line[x]
            
      return render_template("/palpayReport.html",role=role, palpay=palpay, total=total,user=user)
           
    else:
      return apology("GATCHYAA METHOD NOT ALLOWED")
  else:
    return apology("UR NOT ACCOUNTER GET OUT OF HERE!")
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

# JDECo Manager Report
@app.route("/JDECoMReport",methods=["POST"])
@login_required
def JDECoMReport():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    Userame = uinfo[0]['username']
    if request.method == "POST":
      FromDate = request.form.get("FromDate")
      if not FromDate:
        flash("you must select From Date")
        return redirect("/rdeposit",code=302)
      
      ToDate = request.form.get("ToDate")
      if not ToDate:
        flash("you must select To Date")
        return redirect("/rdeposit",code=302)
      
      store = db.execute("select name from stores where id = ?", uinfo[0]['store_id'])
      if not store:
        flash("Store not found, Call support")
        return redirect("/rdeposit",code=302)
      store = store[0]['name']
      fdate = datetime.strptime(FromDate ,"%Y-%m-%d")
      tdate = datetime.strptime(ToDate,"%Y-%m-%d")
      fdate -= timedelta(days=1) 
      if fdate > tdate:
        flash("Error: (From Date) must be before (To Date)")
        return redirect("/rdeposit",code=302)
      
      store_id = db.execute("select id from stores where name = ?", store)
      if not store_id:
        flash("Error Selecting store CATCH YUAA")
        return redirect("/rdeposit",code=302)
      else:
        store_id = store_id[0]['id']
        
      electricity = db.execute("select actualSale,cdate from electricity where store_id = ? and cdate >= ? and cdate <= ? order by cdate",store_id, fdate, tdate)
      if not electricity:
        flash("no data found!")
        return redirect("/rdeposit",code=302)
      dates = []
      actualSale = 0
      for x in electricity:
        dates.append(x['cdate'])
        actualSale = actualSale + x['actualSale']

      if actualSale == 0:
        flash("Actual sales is 0, no need for the report")
        return redirect("/rdeposit",code=302)
      #testing
      #timestamp = datetime.now()
      #timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
      #db.execute("insert into user_movements (user_id, store_id, movement_type, m_table, m_description, movement_date, timestamp) values(?,?,?,?,?,?,?)",session.get("user_id"),store_id,"Delete","palpay",f"data has been deleted from store {store_id}, values:\n{palpay}",cdate,timestamp)

      return render_template("/JDECoMReport.html",store=store, dates=dates, actualSale=actualSale)
    else:
      return apology("Method not allowed :)")
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")

#palpay Manager Report
@app.route("/palpayMReport",methods=["POST"])
@login_required
def palpayMReport():
  uinfo = db.execute("select username,store_id,is_manager from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_manager'] == 1:
    role = "manager"
    Userame = uinfo[0]['username']
    if request.method == "POST":
      FromDate = request.form.get("FromDate")
      if not FromDate:
        flash("you must select From Date")
        return redirect("/rdeposit",code=302)
      
      ToDate = request.form.get("ToDate")
      if not ToDate:
        flash("you must select To Date")
        return redirect("/rdeposit",code=302)
      
      store = db.execute("select name from stores where id = ?", uinfo[0]['store_id'])
      if not store:
        flash("Store not found, Call support")
        return redirect("/rdeposit",code=302)
      store = store[0]['name']
      fdate = datetime.strptime(FromDate ,"%Y-%m-%d")
      tdate = datetime.strptime(ToDate,"%Y-%m-%d")
      fdate -= timedelta(days=1) 
      if fdate > tdate:
        flash("Error: (From Date) must be before (To Date)")
        return redirect("/rdeposit",code=302)
      
      store_id = db.execute("select id from stores where name = ?", store)
      if not store_id:
        flash("Error Selecting store CATCH YUAA")
        return redirect("/rdeposit",code=302)
      else:
        store_id = store_id[0]['id']
        
      palpay = db.execute("select cash_ils, cash_usd, cash_jod, cdate from palpay where store_id = ? and cdate >= ? and cdate <= ? order by cdate",store_id, fdate, tdate)
      if not palpay:
        flash("no data found!")
        return redirect("/rdeposit",code=302)      
      dates = []
      cash_ils = 0
      cash_usd = 0
      cash_jod = 0
      for x in palpay:
        dates.append(x['cdate'])
        cash_ils = cash_ils + x['cash_ils']
        cash_usd = cash_usd + x['cash_usd']
        cash_jod = cash_jod + x['cash_jod']
        
      return render_template("/palpayMReport.html",store=store, dates=dates, cash_ils=cash_ils, cash_usd=cash_usd, cash_jod=cash_jod)
    else:
      return apology("Method not allowed :)")
  else:
    return apology("YOUR NOT MANAGER GET OUT OF HERE!")



# deposit report
@app.route("/depositReport",methods=["POST"])
@login_required
def depositReport():
  uinfo = db.execute("select username,store_id,is_accounting from users where id = ?", session.get("user_id"))
  if uinfo[0]['is_accounting'] == 1:
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
      
      sdate = datetime.strptime(sdate, '%Y-%m-%d')
      tdate = sdate.strftime('%Y-%m-%d 23:59:59')
      sdate = sdate.strftime('%Y-%m-%d %H:%M:%S')
      print(sdate,tdate)
      deposit_report =  db.execute("select * from deposit_report where timestamp >= ? and timestamp <= ? and store_id = ? order by timestamp", sdate, tdate, store_id)
      if not deposit_report:
        flash("No deposit for this day")
        return redirect("acchome",code=302)
      

      for x in deposit_report:
        username = db.execute("select username from users where id = ?",x['user_id'])[0]['username']
        x['username'] = username
        if x['deposit_json']:  
          x['deposit_json'] = json.loads(x['deposit_json'])
        else:
          x['deposit_json'] = None
          
        if x['bankAccount_json']:
          x['bankAccount_json'] = json.loads(x['bankAccount_json'])
        else:
          x['bankAccount_json'] = None
        
        if x['electricity_json']:
          x['electricity_json'] = json.loads(x['electricity_json'])
        else:
          x['electricity_json'] = None
          
        if x['palpay_json']:
          x['palpay_json'] = json.loads(x['palpay_json'])
        else:
          x['palpay_json'] = None
          
        if x['dates_json']:  
          x['dates_json'] = json.loads(x['dates_json'])
        else:
          x['dates_json'] = None
        
        
      timestamp_string = x['timestamp']
      timestamp_datetime = datetime.strptime(timestamp_string, '%Y-%m-%d %H:%M:%S')
      formatted_date = timestamp_datetime.strftime('%Y-%m-%d')
      x['timestamp'] = formatted_date
        

      return render_template("/depositReport.html",deposit_report=deposit_report)
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
      rate = db.execute("select * from rate where rdate = ? and store_id = ?",sdate, store_id)
      if rate:
        rate_user = db.execute("select username from users where id = ?", rate[0]['user_id'])

      if deposit:
        return render_template("/homeview.html",role=role,store=sstore,cashx=cashx,cashz=cashz,deposit=deposit,uname=uname,sdate=sdate,rate=rate,rate_user=rate_user,ttlzview=ttlzview,ttlview=ttlview,stores=stores)
      elif cashz:
        return render_template("/homeview.html",role=role,store=sstore,cashx=cashx,cashz=cashz,uname=uname,rate=rate,rate_user=rate_user,ttlzview=ttlzview,ttlview=ttlview,stores=stores)
      elif cashx:
        return render_template("/homeview.html",role=role,store=sstore,cashx=cashx,uname=uname,rate=rate,rate_user=rate_user,ttlview=ttlview,stores=stores)
      elif rate:
        return render_template("/homeview.html",role=role,store=sstore,rate=rate,rate_user=rate_user,uname=uname,stores=stores)
      elif stores:
        return render_template("/homeview.html",role=role,store=sstore,uname=uname,stores=stores)
      else:
        return render_template("/homeview.html",role=role,store=sstore,uname=uname)


