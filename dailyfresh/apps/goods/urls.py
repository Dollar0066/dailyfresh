from django.urls import path,re_path
from goods import views

urlpatterns = [
    re_path(r'^$', views.index, name='index'),    # 首页
]
