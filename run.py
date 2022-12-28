from flask import Flask, render_template, request, redirect, url_for, session, flash, json
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re, db
import bcrypt

from datetime import datetime, timedelta
import requests
import logging

log_format = ('%(asctime)s | %(levelname)s | %(message)s')
log_level = logging.INFO

#app logger
app_log_file = r"C:\Users\serap\OneDrive\Desktop\AppSecProject (fully integrated)\AppSecProject (fully integrated)\AppSecProject\AppSecProject\app.log"

app_logger = logging.getLogger('__init__.app')
app_logger.setLevel(log_level)
app_logger_file_handler = logging.FileHandler(app_log_file)
app_logger_file_handler.setLevel(log_level)
app_logger_file_handler.setFormatter(logging.Formatter(log_format, datefmt='%d-%b-%y %H:%M:%S'))
app_logger.addHandler(app_logger_file_handler)

app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'my-secret'
# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'limkaiwee1'
app.config['MYSQL_DB'] = 'pythonlogin'
# Intialize MySQL
mysql = MySQL(app)
# http://localhost:5000/MyWebApp/ - this will be the login page, we need to use both GET and POST #requests

def is_human(captcha_response):
    """ Validating recaptcha response from google server
        Returns True captcha test passed for submitted form else returns False.
    """
    seckey = "6LdXbCUhAAAAACXFTJIDiaRANYfdRB0gn9MV7Tj4"
    payload = {'response':captcha_response, 'secret':seckey}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text['success']

@app.route('/', methods=['GET', 'POST'])
def login():
    sitekey = "6LdXbCUhAAAAAIqMeygxFHcW7pr2UiBVBF9pWy-o"
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form: # Create variables for easy access
        username = request.form['username']
        password = bytes(request.form['password'], 'utf-8')
        captcha_response = request.form['g-recaptcha-response']
        text = open("username.txt", "r")
        newUser = text.read().strip()
        text.close()

        if username == newUser and password == bytes("1234567890", "utf-8"):
            session['loggedin'] = True
            session['admin'] = True
            app_logger.info(f'{username} | Admin logged in')
            logging.getLogger('werkzeug').disabled = True
            return redirect(url_for('admin'))
        elif username == newUser and password != "1234567890" and is_human(captcha_response):
            session['loggedin'] = False
            session['admin'] = True
            msg = 'Incorrect password!'
            app_logger.error(f'{username} | WRONG PASSWORD!')
            logging.getLogger('werkzeug').disabled = True
        else:
            if is_human(captcha_response):
                # Check if account exists using MySQL
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
                # Fetch one record and return result
                account = cursor.fetchone()
                if not re.match(r'[A-Za-z0-9]+', username):
                    msg = 'Username must contain only characters and numbers!'

            # If account exists in accounts table in out database
            try:
                if account['fail'] > 3:
                    session['loggedin'] = False
                    check_time = False
                    fail_time = account['time']
                    add_time = timedelta(minutes=5)
                    new_time = add_time + fail_time
                    print(new_time)
                    current_time = datetime.now()
                    if current_time >= new_time:
                        check_time = True
                        print("True")
                    else:
                        check_time = False
                        print("False")
                        msg = f'Please wait 5 mins until {new_time.strftime("%b %d %Y %H:%M:%S")}'
                else:
                    check_time = True

                if check_time == True:
                    if bcrypt.checkpw(password, bytes(account['password'],'utf-8')):
                        check_time = False
                    # Create session data, we can access this data in other routes
                        set_fail_to_zero = """UPDATE accounts SET fail = %s, time = %s WHERE username = %s"""
                        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        cursor.execute(set_fail_to_zero, (0, datetime.now(), username,))
                        mysql.connection.commit()
                        session['loggedin'] = True
                        session['admin'] = False
                        session['id'] = account['id']
                        session['username'] = account['username']
                        app_logger.info(f'{username} | User logged in')
                        logging.getLogger('werkzeug').disabled = True
                        # Redirect to home page
                        return redirect(url_for('home'))
                    elif not bcrypt.checkpw(password, bytes(account['password'],'utf-8')):
                        check_time = False
                        retrieve_fail = account['fail'] + 1
                        add_one_to_fail = """UPDATE accounts SET fail = %s, time = %s WHERE username = %s"""
                        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        cursor.execute(add_one_to_fail, (retrieve_fail, datetime.now(), username,))
                        mysql.connection.commit()
                        msg = 'Incorrect password!'
                        app_logger.error(f'{username} | WRONG PASSWORD!')
                        logging.getLogger('werkzeug').disabled = True
            except:
                # Account doesn’t exist or username/password incorrect
                msg = 'Account does not exist'
    # Show the login form with message (if any)
    return render_template('login.html', msg=msg, sitekey=sitekey)

@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        password = bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())
        email = request.form['email']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            insert_user_query = """INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s)"""
            cursor.execute(insert_user_query, (username, password, email, datetime.now(), 0,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
    elif request.method == 'POST':
    #   Form is empty... (no POST data)
        msg = 'Please fill out the form!'

    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)

@app.route('/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
    # User is loggedin show them the home page
        return render_template('home.html', username=session['username'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
    # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

from flask import make_response
@app.route('/formpage', methods=['GET', 'POST'])
def formpage():
    if request.method == 'POST':
        db.add_comment(request.form['comment'])
    search_query = request.args.get('q')
    comments = db.get_comments(search_query)

    # return render_template('formpage.html',
    #                        comments=comments,
    #                        search_query=search_query)

    r = make_response(render_template('formpage.html', comments=comments, search_query=search_query))
    r.headers.set('Content-Security-Policy', "script-src 'none'")
    return r

@app.route('/post')
def post():
    return render_template('post.html')


@app.route('/adminpage')
def admin():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts')
    account = cursor.fetchall()
    if session['admin'] == True and 'loggedin' in session:
        return render_template('admin.html', account=account)
    return redirect(url_for('login'))

@app.route('/robots.txt', methods=['GET','POST'])
def robots():
    return render_template('robots.txt')

if __name__== '__main__':
    session = {}
    app.run()
