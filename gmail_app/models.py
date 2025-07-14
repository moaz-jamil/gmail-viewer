from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class LoginActivity(models.Model):
    user_email = models.EmailField()
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    login_time = models.DateTimeField(auto_now_add=True)
  
    def __str__(self):
        return f"{self.user_email} - {self.login_time}"


class TagNotification(models.Model):
    tagged_user = models.ForeignKey(User, on_delete=models.CASCADE)
    sender = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    message = models.TextField()
    thread_id = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.tagged_user.username} tagged on {self.subject}"
    

class EmailThread(models.Model):
    gmail_id = models.CharField(max_length=200, unique=True)
    subject = models.CharField(max_length=255)
    sender = models.EmailField()
    body = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    received_at = models.DateTimeField(null=True, blank=True)  # ✅ Needed for notifications sorting
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)  # ✅ Needed for filtering by user
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return self.subject


class TaggedEmail(models.Model):
    sender_email = models.EmailField(default="no-reply@example.com")
    subject = models.CharField(max_length=300, default="untitled")
    body = models.TextField(default="")
    tagged_user_email = models.EmailField(default="unknown@example.com")
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Tagged to {self.tagged_user_email} by {self.sender_email}"


class EmailReply(models.Model):
    sender = models.CharField(max_length=255)
    body = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)
    email_id = models.CharField(max_length=255)
    thread = models.ForeignKey(EmailThread, on_delete=models.CASCADE, related_name='replies', null=True)

    def __str__(self):
        return f'Reply from {self.sender} at {self.sent_at}'



class ChatMessage(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_seen = models.BooleanField(default=False)
    cleared_by=models.ManyToManyField(User,related_name='cleared_chats', blank=True)
    thread = models.ForeignKey(EmailThread, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.sender.username} → {self.receiver.username}: {self.message[:20]}"



class ChatNotification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_notifications')
    message = models.TextField()
    thread = models.ForeignKey(EmailThread, on_delete=models.CASCADE,null=True)  # Must be NOT NULL now
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

