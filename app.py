import functools
import os
from flask import Flask, request, redirect, url_for, render_template, session, flash, g, abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)








if __name__ == '__main__':
    app.run()

app.config.from_mapping(
    SECRET_KEY='MyNew$ecureP@ssw0rd', )


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mahmoud.reda45667@gmail.com'
app.config['MAIL_PASSWORD'] = 'wrxm ybds cgmp znjj'
app.config['MAIL_DEFAULT_SENDER'] = 'mahmoud.reda45667@gmail.com'

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)  # For generating secure tokens

if __name__ == '__main__':
    app.run()

############### DATA BASE CONECTION ###############
database = 'blog.db'
def get_db():
    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    return db




############## DECORATOR ######################3
def login_required(func):
    @functools.wraps(func)
    def wrapped_func(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return func(**kwargs)
    return wrapped_func






######################## HOME PAGE ##############################
@app.route('/')
def posts():
    db = get_db()
    posts = db.execute('SELECT * FROM posts').fetchall()
    db.close()
    return render_template('posts.html', posts=posts)





########################### SHOW ONE POST ########################
@app.route('/post/<int:id>')
def post(id):
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id=?', (id,)).fetchone()
    db.close()
    return  render_template('post.html', post=post)





######################### CREATE POST ############################
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        db = get_db()
        title = request.form['title']
        body = request.form['body']
        db.execute('INSERT INTO posts (title, body, author_id) VALUES (?, ?, ?)', (title, body, g.user['id']))
        db.commit()
        db.close()
        return redirect(url_for('posts'))
    return render_template('create.html')



def get_post(id):
    post = get_db().execute('SELECT * FROM posts WHERE id=?', (id,)).fetchone()
    if post is None:
        abort(404, 'Post not found')
    if post['author_id'] != g.user['id']:
        abort(403)
    return post

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    post = get_post(id)
    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        error = None
        if not title:
            error = 'Title is required.'
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute('UPDATE posts SET title = ?, body=? WHERE id = ?', (title,body, id))
            db.commit()
            db.close()
            return redirect(url_for('posts'))
    return render_template('create.html', post=post)



@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    db = get_db()
    db.execute('DELETE FROM posts WHERE id = ?', (id,))
    db.commit()
    db.close()
    return redirect(url_for('posts'))




# ############################# REGISTER #############################
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        error = None

        if not username:
            error = "Username is require !"
        if not password:
            error = "Password is require !"
        if not email:
            error = "email is require !"

        if error is None:
            db = get_db()
            try:
                db.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                           (username, generate_password_hash(password), email))
                db.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'this email is already used '
            finally:
                db.close()
        flash(error)
    return render_template('auth/register.html')



#################### LOG IN ############################
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        error = None

        if not email :
            error = 'Email is required.'
        elif not password :
            error = 'Password is required.'
        else:
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
            if not user :
                error = 'Incorrect email.'
            elif not check_password_hash(user['password'], password):
                error = 'Incorrect password.'

            if error is None:
                session.clear()
                session['user_id'] = user['id']
                return redirect(url_for('posts'))
        flash(error)

    # If already logged in → skip login page
    if g.user:
        return redirect(url_for('posts'))

    return render_template('auth/login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()

        if user:
            # Generate reset token
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send email
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_url}'
            mail.send(msg)

            flash('Check your email for the password reset link.')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email.')

    return render_template('auth/forgot_password.html')




@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour expiry
    except:
        flash('The reset link is invalid or has expired.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        db = get_db()
        db.execute(
            'UPDATE users SET password = ? WHERE email = ?',
            (generate_password_hash(new_password), email)
        )
        db.commit()

        flash('Your password has been reset! You can log in now.')
        return redirect(url_for('login'))

    return render_template('auth/reset_password.html')
































################ BEFORE REQUEST #######################
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id == None :
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()




################## LOG OUT ###################
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))