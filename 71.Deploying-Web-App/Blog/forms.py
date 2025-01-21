from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, URL, length
from flask_ckeditor import CKEditorField


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField(validators=[DataRequired()])
    email = EmailField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired(), length(min=3)])
    submit = SubmitField(label="Sign Up", render_kw={"class": "btn btn-success"})

class LoginForm(FlaskForm):
    login = EmailField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField(label="Login", render_kw={"class": "btn btn-dark"})


class Comment(FlaskForm):
    comment = CKEditorField(label="Comment content", validators=[DataRequired()])
    submit = SubmitField(label="Send", render_kw={"class": "btn btn-success"})