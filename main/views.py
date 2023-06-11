from django.shortcuts import render, HttpResponse, redirect, HttpResponseRedirect
from .forms import UserForm
from .models import *
from django.contrib.auth.hashers import make_password, check_password
from django.utils.encoding import smart_str
from django.utils.encoding import force_bytes

# urlsafe_base64_encode() and urlsafe_base64_decode() functions in Django are used to encode and decode data in a way that is safe
# to use in URLs. The urlsafe_base64_encode() function takes a string as input and returns a base64-encoded string that does not
# contain any characters that are not allowed in URLs. The urlsafe_base64_decode() function takes a base64-encoded string as input
# and returns the original string, decoded from base64.
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

# as i am not using django's default user so, i dont have last_login field so, can't generate tokens from PasswordResetTokenGenerator.
# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# for making tokens
# for creating tokens...
from .uuid_gen import uuid_genrator
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse

# Create your views here.


def home(request):
    try:
        val = getcookies(request)
        user = User.objects.get(session_id=val)
        if not user.is_expired:
            context = {"user_login": not (user.is_expired)}
            return render(request, "base.html", context=context)
        else:
            return render(request, "base.html")
    except Exception as e:
        return render(request, "base.html")


def login(request):
    return render(request, "login.html")


def activate(request, user_id, token):
    # uid = request.GET.get('user_id')
    uid = smart_str(urlsafe_base64_decode(user_id))
    user = User.objects.get(id=uid)
    if user:
        user.email_verification = 1
        user.save()
    return render(request, "login.html")


def login_logic(request):
    if request.method == "POST":
        email = request.POST["email"]
        raw_password = request.POST["password"]
        try:
            user_obj = User.objects.get(email=email)
            hashed_pasword = user_obj.password
            if user_obj:
                res = check_password(raw_password, hashed_pasword)

                if res and user_obj.email_verification == 1:
                    session_id = uuid_genrator()
                    user_obj.session_id = session_id
                    user_obj.save()
                    # val = getcookies(request)
                    user = 0

                    # response = render(request, "dashboard.html", {
                    #                   "message": "login sucessful"})
                    response = redirect("dashboard")
                    response.set_cookie("session_id", session_id)
                    return response
                else:
                    return render(
                        request,
                        "login.html",
                        {
                            "message": "incorrect email or password or verify ypur email first"
                        },
                    )

        except:
            return render(
                request,
                "login.html",
                {"message": "incorrect email or password or verify ypur email first"},
            )


def getcookies(request):
    value = request.COOKIES.get("session_id")
    return value


def signup(request):
    return render(request, "signup.html")


def signup_logic(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = make_password(request.POST["password"])
        email = request.POST["email"]
        if User.objects.filter(email=email).exists():
            return render(
                request,
                "signup.html",
                {"message": "This email already exits try with new email.."},
            )
        # save user into the database
        else:
            user = User(username=username, password=password, email=email)
            user.save()

            """urlsafe_base64_encode() and urlsafe_base64_decode( a bytes-like object is required, not 'str'or int) functions in Django are used to encode and decode 
            data in a way that is safe to use in URLs. The urlsafe_base64_encode() function takes a string as
            input and returns a base64-encoded string that does not contain any characters that are not allowed
            in URLs. The urlsafe_base64_decode() function takes a base64-encoded string as input and returns the
            original string, decoded from base64."""
            user_id = urlsafe_base64_encode(force_bytes(user.id))
            # token generator
            token = uuid_genrator()
            link = f"https://kantest.onrender.com/activate/{user_id}/{token}/"
            subject = "Registration"
            email_content = f"Hi {user.username},\n\nThank you for signing up for our service. To verify your email address, please click on the following link:\n\n{link}\n\nIf you do not click on the link within 24 hours, your account will be deleted.\n\nThanks,\nDjango Bloggers"
            email_from = settings.EMAIL_HOST_USER
            recepient_list = [
                email,
            ]
            send_mail(subject, email_content, email_from, recepient_list)
            user = User(email_verification=1)
    return render(request, "login.html", {"message": "User register sucessfully..."})


def forget_passcode(request):
    return render(request, "forgetpasscode.html")


def forgot_password_logic(request):
    if request.method == "POST":
        email = request.POST["email"]
        user = User.objects.get(email=email)
    if user:
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = uuid_genrator()
        reset_link = f"https://kantest.onrender.com/reset?uid={uid}&token={token}/"
        subject = "Password reset link"
        email_content = f"Hi {user.username},\n\nThank you for signing up for our service. To verify your email address, please click on the following link:\n\n{reset_link}\n\nIf you do not click on the link within 24 hours, your account will be deleted.\n\nThanks,\nDjango Bloggers"
        email_from = settings.EMAIL_HOST_USER
        recepient_list = [
            email,
        ]
        send_mail(subject, email_content, email_from, recepient_list)
    return render(
        request,
        "forgetpasscode.html",
        {"message": "Password reset link has been send successfully"},
    )


def reset(request):
    if request.method == "GET":
        return render(request, "reset_logic.html")
    if request.method == "POST":
        password = request.POST["psw1"]
        password2 = request.POST["psw2"]
        uid = request.POST["uid"]
        token = request.POST["token"]

        if password == password2 and uid is not None:
            decode_uid = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=decode_uid)
            if user:
                user.password = make_password(password)
                user.save()
            else:
                return render(
                    request, "reset_logic.html", {"message": "User does not exists"}
                )
        else:
            return render(
                request, "reset_logic.html", {"message": "Password do not match"}
            )
    return render(request, "login.html", {"message": "Password changed sucessfully.."})


def dashboard(request):
    try:
        val = getcookies(request)
        user = 0
        user = User.objects.get(session_id=val)
        user_blog = Blog.objects.filter(rel_user=user)
        # user_context = {"blogTitle": user_blog}
        if user:
            return render(
                request,
                "dashboard.html",
                {"blogTitle": user_blog, "username": user.username},
            )
        else:
            redirect_url_login = reverse("login")
            return redirect(redirect_url_login)
    except Exception as e:
        redirect_url_login = reverse("login")
        return redirect(redirect_url_login)
    # return render(request, "dashboard.html")


def tinymce(request):
    return render(request, "tinymce.html")


def tinymce(request):
    if request.method == "GET":
        return render(request, "tinymce.html")

    if request.method == "POST":
        val = getcookies(request)
        user = User.objects.get(session_id=val)
        blog_content = request.POST["textarea"]
        blog_title = request.POST["blogTitle"]
        tinymce_obj = Blog.objects.create(
            title=blog_title, content=blog_content, rel_user=user
        )
        tinymce_obj.save()
    return render(request, "tinymce.html")


def view_blog(request, id):
    val = getcookies(request)
    # user = User.objects.get(session_id=val)
    user_blog = Blog.objects.get(id=id)

    rel_pub_obj = (
        Published.objects.get(rel_blog=user_blog)
        if Published.objects.filter(rel_blog=user_blog).exists()
        else 0
    )

    uid = rel_pub_obj.uid if rel_pub_obj else 0

    if not uid:
        user_context = {
            "blogTitle": user_blog.title,
            "blogContent": user_blog.content,
            "blog": user_blog,
        }
    else:
        user_context = {
            "blogTitle": user_blog.title,
            "blogContent": user_blog.content,
            "blog": user_blog,
            "pub_uid": uid,
        }

    return render(request, "viewblog.html", context=user_context)


def edit_blog(request, id):
    val = getcookies(request)
    # user = User.objects.get(session_id=val)
    user_blog = Blog.objects.get(id=id)
    # start_body_tag_idx = user_blog.content.find("<body>")
    # end_body_tag_idx = user_blog.content.find("<body>")
    # tinyMCE_content = user_blog.content[42:176+len("</body>")]
    user_context = {
        "blogTitle": user_blog.title,
        "tinyMCE_content": user_blog.content,
        "blog_id": id,
    }
    return render(request, "edit_blog.html", context=user_context)


def update_blog(request, blogid):
    if request.method == "POST":
        val = getcookies(request)
        loggedin_user = User.objects.get(session_id=val)

        blog_to_edit = Blog.objects.get(id=blogid)

        # if blog_to_edit.rel_user == loggedin_user:
        #     pass

        blog_content = request.POST["textarea"]
        blog_title = request.POST["blogTitle"]

        blog_to_edit.title = blog_title
        blog_to_edit.content = blog_content

        # tinymce_obj = Blog.objects.create(title=blog_title, content=blog_content, rel_user=loggedin_user)
        blog_to_edit.save()
    # return render(request, "viewblog.html")
    return redirect(reverse("view_blog", kwargs={"id": blogid}))


def create_pub_url(request, blogid):
    id = uuid_genrator()
    val = getcookies(request)
    loggedin_user = User.objects.get(session_id=val)
    related_blog = Blog.objects.get(id=blogid)

    # constructing url
    hostname = request.META.get("HTTP_HOST")
    url = f"{hostname}/pub/{id}/"
    # new_pub_blog =
    related_blog.published_url = url
    related_blog.publish_active = True
    related_blog.save()

    if Published.objects.filter(rel_blog=related_blog).exists():
        rel_pub_obj = Published.objects.get(rel_blog=related_blog)
        rel_pub_obj.uid = id
        rel_pub_obj.save()
    else:
        rel_pub_obj = Published(uid=id, rel_blog=related_blog)
        rel_pub_obj.save()
    return redirect(reverse("pub", kwargs={"uid": id}))


def pub(request, uid):
    rel_pub_obj = Published.objects.get(uid=uid)
    rel_blog = rel_pub_obj.rel_blog

    user_context = {
        "blogTitle": rel_blog.title,
        "blogContent": rel_blog.content,
        "blog": rel_blog,
        "pub_uid": uid,
    }
    return render(request, "viewblog.html", context=user_context)
