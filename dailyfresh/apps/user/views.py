from django.shortcuts import render,redirect
from django.urls import reverse
from django.core.mail import send_mail
from django.views.generic import View
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from user.models import User
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer            # 加密解密、设置失效时间
from itsdangerous import SignatureExpired
from celery_tasks.tasks import send_register_active_email
import re,time
# Create your views here.

def register(request):
    '''注册'''
    if request.method == 'GET':
        # 显示注册页面
        return render(request, 'register.html')
    else:
        # 进行注册处理
        # 通用流程： 
        # 1、接收数据 
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        cpassword = request.POST.get('cpwd')
        allow = request.POST.get('allow')

        # 2、进行数据校验  
        if not all([username, password, email]):
            # 数据不完整
            return render(request, 'register.html', {'errmsg':'数据不完整'})
        # 校验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg':'邮箱格式不正确'})
        # 校验两次密码输入是否一致
        if password != cpassword:
            return render(request, 'register.html', {'errmsg':'两次输入的密码不一致'})
        if allow != 'on':
            return render(request, 'register.html', {'errmsg':'请同意协议'})
        # 校验用户名是否存在
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # 用户名不存在
            user = None
        if user:
            # 用户名已存在
            return render(request, 'register.html', {'errmsg': '用户名已存在'})
        # 3、进行业务处理: 进行用户注册  
        user = User.objects.create_user(username, email=email, password=password)
        user.is_active = 0 
        user.save()
        # 4、 返回应答,跳转到首页
        return redirect(reverse('goods:index'))

def register_handle(request):
    '''进行注册处理'''
    # 通用流程： 
    # 1、接收数据 
    username = request.POST.get('user_name')
    password = request.POST.get('pwd')
    email = request.POST.get('email')
    cpassword = request.POST.get('cpwd')
    allow = request.POST.get('allow')

    # 2、进行数据校验  
    if not all([username, password, email]):
        # 数据不完整
        return render(request, 'register.html', {'errmsg':'数据不完整'})
      # 校验邮箱
    if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
        return render(request, 'register.html', {'errmsg':'邮箱格式不正确'})
     # 校验两次密码输入是否一致
    if password != cpassword:
        return render(request, 'register.html', {'errmsg':'两次输入的密码不一致'})
    if allow != 'on':
        return render(request, 'register.html', {'errmsg':'请同意协议'})
    # 校验用户名是否存在
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        # 用户名不存在
        user = None
    if user:
        # 用户名已存在
        return render(request, 'register.html', {'errmsg': '用户名已存在'})
    # 3、进行业务处理: 进行用户注册  
    user = User.objects.create_user(username, email=email, password=password)
    user.is_active = 0 
    user.save()
    
    # 4、 返回应答,跳转到首页
    return redirect(reverse('goods:index'))


# /user/register
class RegisterView(View):
    '''注册'''
    def get(self, request):
        '''显示注册页面'''
        return render(request, 'register.html')
    
    def post(self, request):
        '''进行注册处理'''
        # 通用流程： 
        # 1、接收数据 
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        cpassword = request.POST.get('cpwd')
        allow = request.POST.get('allow')

        # 2、进行数据校验  
        if not all([username, password, email]):
            # 数据不完整
            return render(request, 'register.html', {'errmsg':'数据不完整'})
        # 校验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg':'邮箱格式不正确'})
        # 校验两次密码输入是否一致
        if password != cpassword:
            return render(request, 'register.html', {'errmsg':'两次输入的密码不一致'})
        if allow != 'on':
            return render(request, 'register.html', {'errmsg':'请同意协议'})
        # 校验用户名是否存在
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # 用户名不存在
            user = None
        if user:
            # 用户名已存在
            return render(request, 'register.html', {'errmsg': '用户名已存在'})
        # 3、进行业务处理: 进行用户注册  
        user = User.objects.create_user(username, email=email, password=password)
        user.is_active = 0 
        user.save()

        # 发送激活邮件，包含激活链接: http://127.0.0.1:8000/user/active/1
        # 激活链接中需要包含用户的身份信息，并且要把身份信息进行加密
        
        # 加密用户的身份信息，生成激活token
        serializer = Serializer(settings.SECRET_KEY, 3600)
        info = {'confirm': user.id}
        token = serializer.dumps(info)         # 加密后生成显示的是bytes
        token = token.decode()         # decode的编码格式默认是utf8，所以可写可不写

        # 发邮件
        # send_register_active_email.delay(email, username, token)    # 暂时先放着，学了Redis再改celery发邮件
        subject = '天天生鲜欢迎信息'       # 邮件的主题
        message = ''
        sender = settings.EMAIL_FROM
        receiver = [email]
        html_message = f'<h1>{username},欢迎您成为天天生鲜注册会员</h1>请点击下面链接激活您的账号<br/><a href="http://127.0.0.1:8000/user/active/{token}">http://127.0.0.1:8000/user/active/{token}</a>'
        send_mail(subject, message, sender, receiver, html_message=html_message)
        
    
        # 4、 返回应答,跳转到首页
        return redirect(reverse('goods:index'))

class ActiveView(View):
    '''用户激活'''
    def get(self, request, token):
        '''进行用户激活'''
        # 进行解密，获取要激活的用户信息
        serializer = Serializer(settings.SECRET_KEY, 3600)
        try:
            info = serializer.loads(token)
            # 获取待激活用户的id
            user_id = info['confirm']

            # 根据id获取用户信息
            user = User.objects.get(id=user_id)
            user.is_active = 1
            user.save()

            # 跳转到登录页面
            return redirect(reverse('user:login'))
        except SignatureExpired as e:
            # 激活链接已过期
            return HttpResponse('激活链接已过期')        # 实际项目中要提供一个链接让用户点击去重新激活，这边只是模拟。

# /user/login
class LoginView(View):
    '''登录'''
    def get(self, request):
        '''显示登录页面'''
        return render(request, 'login.html')

    def post(self, request):
        '''登录校验'''
        # 接收数据
        username = request.POST.get('username')
        password = request.POST.get('pwd')

        # 校验数据
        if not all([username, password]):
            return render(request, 'login.html', {'errmsg':'数据不完整'})

        # 业务处理：登录校验
        user = authenticate(username='username', password='password')
        if user is not None:
            # 用户名密码正确
            if user.is_active:
                # 用户已激活
                # 记录用户的登录状态
                login(request, user)

                # 跳转到首页
                return redirect(reverse('goods:index'))
            else:
                # 用户未激活
                return render(request, 'login.html', {'errmsg':'账户未激活'})
        else:
            # 用户名或密码错误
            return render(request, 'login.html', {'errmsg':'用户名或密码错误'})
