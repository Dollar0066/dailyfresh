from django.urls import path, re_path
from user.views import RegisterView,ActiveView,LoginView

urlpatterns = [
    # re_path(r'^register$', views.register, name='register'),   # 注册
    # re_path(r'^register_handle$', views.register_handle, name='register_handle'),   # 注册处理
    re_path(r'^register$', RegisterView.as_view(), name='register'),   # 注册
    re_path(r'^active/(?P<token>.*)$', ActiveView.as_view(), name='active'),   # 用户激活
    re_path(r'^login$', LoginView.as_view(), name='login'),    # 登录
]
