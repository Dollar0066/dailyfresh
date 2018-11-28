# 使用celery
from celery import Celery
from django.conf import settings
from django.core.mail import send_mail
import time

# 创建一个Celery类的实例对象
app = Celery('celery_tasks.tasks', broker='redis://127.0.0.1:6379/8')

# 定义任务函数
@app.task
def send_register_active_email(to_email, username, token):
    '''发送激活邮件'''
    # 组织邮件信息
    pass