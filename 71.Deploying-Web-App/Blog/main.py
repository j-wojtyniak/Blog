from flask import Flask, abort, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, Comment
from datetime import datetime
from flask_gravatar import Gravatar
from dotenv import load_dotenv
import os

load_dotenv()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = db.session.query(User).filter_by(email="admin@admin.com").first()
        if not current_user.is_authenticated:
            abort(403)
        elif not current_user.email == admin.email or not current_user.password == admin.password:
            abort(403)
        else:
            return f(*args, **kwargs)

    return decorated_function


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)


class User(db.Model, UserMixin):
    def __init__(self, name, email, password):
        super().__init__()
        self.name = name
        self.email = email
        self.password = password

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)


class Comments(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    post: Mapped[str] = mapped_column(String, nullable=False)
    author: Mapped[str] = mapped_column(String, nullable=False)
    date: Mapped[str] = mapped_column(String, nullable=False)
    comment: Mapped[str] = mapped_column(String, nullable=False)


with app.app_context():
    db.create_all()


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        user_to_register = User(
            name=request.form.get("name"),
            email=request.form.get("email"),
            password=generate_password_hash(request.form.get("password"))
        )
        email_to_check = db.session.query(User).filter_by(email=user_to_register.email).first()
        print(email_to_check)
        if email_to_check is None:
            db.session.add(user_to_register)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            flash("This email is already registered!")
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        login_passed = request.form.get("login")
        password_passed = request.form.get("password")
        user_to_login = db.session.query(User).filter_by(email=login_passed).first()
        if user_to_login is None:
            flash("This user does not exist")
        elif user_to_login and check_password_hash(user_to_login.password, password_passed):
            session["is_logged_in"] = True
            login_user(user_to_login)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", is_logged_in=False, form=login_form)


@app.route('/logout')
def logout():
    session.pop("is_logged_in", None)
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = Comment()

    if comment_form.validate_on_submit():
        comment = Comments(
            post=requested_post.title,
            author=current_user.name,
            date=datetime.now().strftime("%d-%m-%Y"),
            comment=request.form.get("comment")
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    post_comments = db.session.execute(db.select(Comments)).scalars().all()
    admin = db.session.query(User).filter_by(email="admin@admin.com").first()
    is_admin = current_user.email == admin.email and current_user.password == admin.password
    return render_template("post.html",
                           post=requested_post, form=comment_form, comments=post_comments, is_admin=is_admin)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
