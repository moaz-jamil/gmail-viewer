# gmail_app/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.google_login, name='login'),
    path('oauth2callback/', views.oauth2callback, name='oauth2callback'),
    path('inbox/', views.inbox, name='inbox'),
    path('logout/', views.logout_view, name='logout'), 
    path('view_email/<str:email_id>/', views.view_email, name='view_email'),
    path('compose/', views.compose_email, name='compose'),
    path('dashboard/',views.dashboard, name='dashboard'),
    path('reply/<str:email_id>/', views.reply_email, name='reply_email'),
    path('delete/<str:email_id>/', views.delete_email, name='delete_email'),
    path('get-usernames/', views.get_usernames, name='get_usernames'),
    path('send_message/', views.send_message, name='send_message'),
    path('fetch_messages/', views.fetch_messages, name='fetch_messages'),
    path('notifications/', views.notifications_view, name='notifications'),
    path('notifications/mark_read/', views.mark_notification_read, name='mark_notification_read'),
    path('get_unread_notifications/', views.get_unread_notifications, name='get_unread_notifications'),
    path('notifications/mark_read/', views.mark_notification_read, name='mark_notification_read'),
    path('clear_chat/', views.clear_chat, name='clear_chat'),


    

    





    ]
