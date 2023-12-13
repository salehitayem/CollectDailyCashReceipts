from requirements import *

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
