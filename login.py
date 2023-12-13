from requirements import *

app = Flask(__name__)

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
