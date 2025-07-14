import os
import json
import base64
import html
import datetime
import re
from django.conf import settings
from django.shortcuts import redirect, render
from django.http import JsonResponse
from django.contrib.auth import login
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from django.contrib.auth.models import User
from googleapiclient.errors import HttpError
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.contrib import messages
from .models import ChatMessage,EmailReply,TaggedEmail,EmailThread,TagNotification,LoginActivity,ChatNotification
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
def home(request):
    return render(request, 'home.html')


def google_login(request):
    flow = Flow.from_client_secrets_file(
        settings.GOOGLE_CLIENT_SECRET_FILE,
        scopes=settings.GOOGLE_SCOPES,
        redirect_uri=settings.GOOGLE_REDIRECT_URI
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    return redirect(auth_url)

def oauth2callback(request):
    flow = Flow.from_client_secrets_file(
        settings.GOOGLE_CLIENT_SECRET_FILE,
        scopes=settings.GOOGLE_SCOPES,
        redirect_uri=request.build_absolute_uri('/oauth2callback/')
    )

    flow.fetch_token(authorization_response=request.build_absolute_uri())

    credentials = flow.credentials
    service = build('gmail', 'v1', credentials=credentials)
    profile = service.users().getProfile(userId='me').execute()

    user_email = profile.get('emailAddress')
    first_name = ""
    last_name = ""

    # Save user in session
    request.session['user_email'] = user_email

    request.session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    # Save or get Django User and log them in
    user, created = User.objects.get_or_create(email=user_email, defaults={'username': user_email.split('@')[0]})
    login(request, user)  # THIS LOGS IN THE USER TO DJANGO SESSION

    # Save login activity
    LoginActivity.objects.create(
        user_email=user_email,
        first_name=first_name,
        last_name=last_name
    )

    return redirect('dashboard')


def logout_view(request):
    request.session.flush()
    return redirect('home')

def inbox(request):
    if 'credentials' not in request.session:
        return redirect('login')

    creds_data = request.session['credentials']
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret']
    )

    service = build('gmail', 'v1', credentials=creds)
    query = request.GET.get('query', '').strip()
    label = request.GET.get('label')
    if request.GET.get('has_attachment'):
        query += ' has:attachment'

    # ✅ Force inbox-only query to ignore trash/spam
    if 'in:' not in query:
        query = f'in:inbox {query}'.strip()

    params = {
        'userId': 'me',
        'maxResults': 20,
        'q': query
    }
    if label:
        params['labelIds'] = [label]

    results = service.users().messages().list(**params).execute()
    messages = results.get('messages', [])

    threads_seen = set()
    emails = []

    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
        thread_id = msg_data.get('threadId')

        if thread_id in threads_seen:
            continue
        threads_seen.add(thread_id)

        headers = msg_data['payload']['headers']
        subject = from_email = ''
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            if header['name'] == 'From':
                from_email = header['value']

        body = ''
        if 'parts' in msg_data['payload']:
            for part in msg_data['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body'].get('data')
                    if data:
                        decoded_bytes = base64.urlsafe_b64decode(data.encode())
                        body = html.escape(decoded_bytes.decode())
                        break
        else:
            data = msg_data['payload']['body'].get('data')
            if data:
                decoded_bytes = base64.urlsafe_b64decode(data.encode())
                body = html.escape(decoded_bytes.decode())

        timestamp = int(msg_data['internalDate']) / 1000
        date_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')

        emails.append({
            'subject': subject,
            'sender': from_email,
            'snippet': body[:100] or '(No content)',
            'date': date_str,
            'id': msg['id'],
        })

    return render(request, 'inbox.html', {'messages': emails})




# ✅ Helper to clean emails from "Name <email@example.com>"
def extract_email(raw):
    match = re.search(r'[\w\.-]+@[\w\.-]+', raw)
    return match.group(0).lower() if match else None


def view_email(request, email_id):
    if 'credentials' not in request.session or not request.user.is_authenticated:
        return redirect('login')

    creds_data = request.session['credentials']
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret']
    )

    service = build('gmail', 'v1', credentials=creds)

    # Fetch message and thread
    try:
        message = service.users().messages().get(userId='me', id=email_id).execute()
    except Exception:
        messages.error(request, "Email not found or deleted.")
        return redirect('inbox')

    thread_id = message.get('threadId')
    thread = service.users().threads().get(userId='me', id=thread_id).execute()

    thread_messages = []
    participants = set()

    for msg in thread['messages']:
        headers = msg.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
        from_email = next((h['value'] for h in headers if h['name'] == 'From'), '')
        to_email = next((h['value'] for h in headers if h['name'] == 'To'), '')
        timestamp = int(msg['internalDate']) / 1000
        date = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')

        # ✅ Extract clean emails
        email_from = extract_email(from_email)
        if email_from:
            participants.add(email_from)

        if to_email:
            for addr in to_email.split(','):
                email_to = extract_email(addr)
                if email_to:
                    participants.add(email_to)

        body = ''
        payload = msg.get('payload', {})
        if 'parts' in payload:
            for part in payload['parts']:
                if part.get('mimeType') == 'text/plain':
                    data = part['body'].get('data')
                    if data:
                        body = html.unescape(base64.urlsafe_b64decode(data.encode()).decode())
                        break
        else:
            data = payload.get('body', {}).get('data')
            if data:
                body = html.unescape(base64.urlsafe_b64decode(data.encode()).decode())

        thread_messages.append({
            'subject': subject,
            'from': from_email,
            'to': to_email,
            'date': date,
            'body': body,
            'gmail_id': msg['id']
        })

    # Save thread to DB if not exists
    current_user = request.user
    db_thread, created = EmailThread.objects.get_or_create(
        gmail_id=thread_id,
        defaults={
            'subject': thread_messages[0]['subject'] if thread_messages else 'No Subject',
            'sender': thread_messages[0]['from'] if thread_messages else '',
            'body': thread_messages[0]['body'] if thread_messages else '',
            'user': current_user,
        }
    )

    replies = db_thread.replies.all().order_by('sent_at')

    # ✅ Get users based on email thread + tagged users
    all_users = User.objects.exclude(id=current_user.id)

    tagged_users = User.objects.filter(
        email__in=TaggedEmail.objects.filter(
            subject=db_thread.subject
        ).values_list('tagged_user_email', flat=True)
    )

    other_users = all_users.filter(
        Q(email__in=participants) | Q(id__in=tagged_users)
    ).distinct()

    # ✅ Handle selected user
    selected_user_id = request.GET.get('user')
    selected_user = None
    messages_qs = []

    if selected_user_id:
        try:
            selected_user = User.objects.get(id=int(selected_user_id))
        except User.DoesNotExist:
            selected_user = None

    if not selected_user and other_users.exists():
        selected_user = other_users.first()

    if selected_user:
        messages_qs = ChatMessage.objects.filter(
            thread=db_thread,
            sender__in=[current_user, selected_user],
            receiver__in=[current_user, selected_user]
        ).order_by('timestamp')

    return render(request, 'view_email.html', {
        'thread_messages': thread_messages,
        'email_id': email_id,
        'replies': replies,
        'selected_user': selected_user,
        'messages': messages_qs,
        'other_users': other_users,
        'db_thread': db_thread,
        'current_user': current_user,
    })


def compose_email(request):
    if 'credentials' not in request.session:
        return redirect('login')

    creds_data = request.session['credentials']
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret']
    )

    service = build('gmail', 'v1', credentials=creds)

    if request.method == 'POST':
        to = request.POST.get('to')
        subject = request.POST.get('subject')
        body = request.POST.get('body')

        try:
            # 🔄 Use MIMEMultipart for proper headers
            message = MIMEMultipart()
            message['to'] = to
            message['from'] = "me"
            message['subject'] = subject
            message.attach(MIMEText(body, 'plain'))

            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

            service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()

            return render(request, 'compose_success.html', {'to': to})
        except Exception as e:
            return render(request, 'compose_email.html', {'error': str(e)})

    return render(request, 'compose_email.html')


def dashboard(request):
    if 'credentials' not in request.session:
        return redirect('login')

    creds_data = request.session['credentials']
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret']
    )

    service = build('gmail', 'v1', credentials=creds)

    # Get unread messages
    result = service.users().messages().list(userId='me', labelIds=['INBOX'], q='is:unread', maxResults=10).execute()
    messages = result.get('messages', [])
    unread_emails = []

    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
        headers = msg_data['payload'].get('headers', [])
        subject = sender = ''
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            if header['name'] == 'From':
                sender = header['value']

        # Get email body snippet
        body = ''
        payload = msg_data.get('payload', {})
        if 'parts' in payload:
            for part in payload['parts']:
                if part.get('mimeType') == 'text/plain':
                    data = part['body'].get('data')
                    if data:
                        body = html.unescape(base64.urlsafe_b64decode(data.encode()).decode())
                        break
        else:
            data = payload.get('body', {}).get('data')
            if data:
                body = html.unescape(base64.urlsafe_b64decode(data.encode()).decode())

        date = datetime.datetime.fromtimestamp(int(msg_data['internalDate']) / 1000).strftime('%Y-%m-%d %H:%M')

        unread_emails.append({
            'from': sender,
            'subject': subject,
            'snippet': body.strip() or '(No Content)',
            'date': date,
            'id': msg['id'],
        })

    # Get recent login logs
    login_logs = LoginActivity.objects.order_by('-login_time')[:10]

    return render(request, 'dashboard.html', {
        'unread_count': len(unread_emails),
        'unread_emails': unread_emails,
        'login_logs': login_logs
    })



def handle_reply(request):
    if request.method == 'POST':
        content = request.POST['reply']
        subject = request.POST['subject']
        thread_id = request.POST.get('thread_id', '')
        sender = request.user.username  # ya full name/email

        # 🟡 Step: Detect all @username tags
        tags = re.findall(r'@(\w+)', content)

        for username in tags:
            try:
                user = User.objects.get(username=username)

                # 🔔 Create Notification
                TagNotification.objects.create(
                    tagged_user=user,
                    sender=sender,
                    subject=subject,
                    message=content,
                    thread_id=thread_id
                )

            except User.DoesNotExist:
                pass  # agar user nahi mila to ignore

        # Save the reply or redirect
        return redirect('dashboard')

# 👇 Utility to extract @username mentions
def extract_user_mentions(text):
    return re.findall(r'@(\w+)', text)

# 👇 Save tagged users in TaggedEmail model
def tag_users_in_email(email_obj, message_text):
    usernames = extract_user_mentions(message_text)
    for username in usernames:
        try:
            user = User.objects.get(username=username)
            TaggedEmail.objects.create(email=email_obj, tagged_user=user)
        except User.DoesNotExist:
            continue


def reply_email(request, email_id):
    if 'credentials' not in request.session:
        return redirect('login')

    creds_data = request.session['credentials']
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret']
    )

    if request.method == 'POST':
        body_text = request.POST.get('body')
        service = build('gmail', 'v1', credentials=creds)

        # ✅ Get original message details
        original_msg = service.users().messages().get(userId='me', id=email_id, format='full').execute()
        headers = original_msg.get('payload', {}).get('headers', [])
        subject = sender_email = ''
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            if header['name'] == 'From':
                sender_email = header['value']

        thread_id = original_msg.get('threadId')
        original_msg_id = original_msg.get('id')

        # ✅ Get or create EmailThread
        timestamp = int(original_msg['internalDate']) / 1000
        received_at = datetime.datetime.fromtimestamp(timestamp)

        thread, created = EmailThread.objects.get_or_create(
            gmail_id=thread_id,
            defaults={
                'subject': subject,
                'sender': sender_email,
                'body': '',
                'received_at': received_at,
                'user': request.user if request.user.is_authenticated else None,  # ✅ Add the logged-in user
                'is_read': True
            }
        )

        # ✅ Create reply message
        message = MIMEText(body_text)
        message['to'] = sender_email
        message['subject'] = f"Re: {subject}"
        message['In-Reply-To'] = original_msg_id
        message['References'] = original_msg_id
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        try:
            # ✅ Reply and attach to thread using threadId
            service.users().messages().send(
                userId='me',
                body={
                    'raw': raw_message,
                    'threadId': thread_id  # 🔁 Attach to correct Gmail thread
                }
            ).execute()

            # ✅ Save reply to local DB
            EmailReply.objects.create(
                thread=thread,
                email_id=email_id,
                sender=sender_email,
                body=body_text
            )

        except HttpError as error:
            return HttpResponse(f'An error occurred: {error}')

        return redirect('dashboard')

@csrf_exempt
def delete_email(request, email_id):
    if 'credentials' not in request.session:
        return redirect('login')

    creds_data = request.session['credentials']
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret']
    )

    service = build('gmail', 'v1', credentials=creds)

    if request.method == 'POST':
        try:
            # 💥 Debug print
            print("Trying to delete:", email_id)

            # 🔥 Try deleting
            service.users().messages().delete(userId='me', id=email_id).execute()
            return redirect('inbox')
        except Exception as e:
            print("❌ Error while deleting email:", e)
            return HttpResponse(f"Error deleting email: {e}")

    return redirect('inbox')

def get_usernames(request):
    usernames = list(User.objects.values_list('username', flat=True))
    return JsonResponse({'usernames': usernames})


def send_message(request):
    if request.method == 'POST':
        if not request.user.is_authenticated:
            messages.error(request, "Login session expired.")
            return redirect('login')

        sender_user = request.user
        to_id = request.POST.get('to_id')
        message = request.POST.get('message')
        thread_id = request.POST.get('thread_id')

        if not to_id or not message or not thread_id:
            messages.error(request, "Missing data.")
            return redirect(request.META.get('HTTP_REFERER', 'inbox'))

        try:
            receiver = User.objects.get(id=to_id)
        except User.DoesNotExist:
            messages.error(request, "Receiver not found.")
            return redirect(request.META.get('HTTP_REFERER', 'inbox'))

        thread = EmailThread.objects.filter(gmail_id=thread_id).first()
        if not thread:
            messages.error(request, "Thread not found.")
            return redirect('inbox')

        ChatMessage.objects.create(
            sender=sender_user,
            receiver=receiver,
            message=message,
            thread=thread
        )

        # 🔔 Create Chat Notification
        ChatNotification.objects.create(
            user=receiver,
            sender=sender_user,
            message=message,
            thread=thread
        )

        referer = request.META.get('HTTP_REFERER', '')

        if 'notifications' in referer:
    # Redirect back to notifications and select the correct user/thread
            return redirect(f'/notifications/?notif_from_reply=1&user={receiver.id}&thread={thread.gmail_id}')
        else:
    # Fallback to normal behavior
            return redirect(f'/view_email/{thread.gmail_id}?user={receiver.id}')
    return redirect('inbox')




def notifications_view(request):
    if not request.user.is_authenticated:
        return redirect('login')

    notifications = ChatNotification.objects.filter(user=request.user).order_by('-created_at')
    
# ✅ Only one notification per sender per thread
    unique_notifs = {}
    for n in notifications:
        key = (n.sender_id, n.thread_id)
        if key not in unique_notifs:
            unique_notifs[key] = n

    notif_id = request.GET.get('notif')
    notif_from_reply = request.GET.get('notif_from_reply')
    selected_user_id = request.GET.get('user')
    thread_gmail_id = request.GET.get('thread')

    selected_notif = None
    selected_user = None
    thread = None
    thread_messages = []
    chat_messages = []
    replies = []

    # If redirected from message reply
    if notif_from_reply and selected_user_id and thread_gmail_id:
        try:
            selected_user = User.objects.get(id=int(selected_user_id))
            thread = EmailThread.objects.get(gmail_id=thread_gmail_id)

            thread_messages = [{
                'subject': thread.subject,
                'from': thread.sender,
                'to': request.user.email,
                'date': thread.received_at,
                'body': thread.body
            }]
            replies = thread.replies.all()
            chat_messages = ChatMessage.objects.filter(
                thread=thread,
                sender__in=[request.user, selected_user],
                receiver__in=[request.user, selected_user]
            ).order_by('timestamp')
        except:
            pass  # ignore errors

    # If a notification is selected from dropdown
    elif notif_id:
        try:
            selected_notif = ChatNotification.objects.get(id=notif_id, user=request.user)
            selected_user = selected_notif.sender
            thread = selected_notif.thread

            thread_messages = [{
                'subject': thread.subject,
                'from': thread.sender,
                'to': request.user.email,
                'date': thread.received_at,
                'body': thread.body
            }]
            replies = thread.replies.all()
            chat_messages = ChatMessage.objects.filter(
                thread=thread,
                sender__in=[request.user, selected_user],
                receiver__in=[request.user, selected_user]
            ).order_by('timestamp')
        except ChatNotification.DoesNotExist:
            selected_notif = None

    return render(request, 'notifications.html', {
        'notifications': notifications,
        'selected_notif': selected_notif,
        'thread_messages': thread_messages,
        'selected_user': selected_user,
        'messages': chat_messages,
        'replies': replies,
        'other_users': User.objects.exclude(id=request.user.id),
        'db_thread': thread,
        'unique_notifs': unique_notifs.values(),  # pass only once-per-sender
    })


def mark_notification_read(request):
    if request.method == 'POST':
        import json
        data = json.loads(request.body)
        notif_id = data.get('id')

        try:
            from .models import ChatNotification
            notif = ChatNotification.objects.get(id=notif_id, user=request.user)
            notif.is_read = True
            notif.save()
            return JsonResponse({'status': 'success'})
        except ChatNotification.DoesNotExist:
            return JsonResponse({'status': 'not_found'}, status=404)

    return JsonResponse({'status': 'invalid'}, status=400)

def fetch_messages(request):
    user_email = request.session.get('user_email')
    selected_user_id = request.GET.get('user_id')

    if not user_email or not selected_user_id:
        return JsonResponse({'error': 'Invalid user'}, status=400)

    try:
        current_user = User.objects.get(email=user_email)
        selected_user = User.objects.get(id=selected_user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # ✅ Mark received messages as seen
    ChatMessage.objects.filter(
        sender=selected_user,
        receiver=current_user,
        is_seen=False
    ).update(is_seen=True)

    messages = ChatMessage.objects.filter(
        sender__in=[current_user, selected_user],
        receiver__in=[current_user, selected_user]
    ).order_by('timestamp')

    message_data = [{
        'sender': msg.sender.username,
        'message': msg.message,
        'timestamp': msg.timestamp.strftime('%H:%M'),
        'is_sender': msg.sender == current_user
    } for msg in messages]

    return JsonResponse({'messages': message_data})


def get_unread_notifications(request):
    if not request.user.is_authenticated:
        return JsonResponse({'notifications': []})

    unread = ChatNotification.objects.filter(user=request.user, is_read=False).order_by('-created_at')[:5]
    notif_data = []

    for n in unread:
        notif_data.append({
            'id': n.id,
            'sender': n.sender.username,
            'message': n.message[:50],  # short preview
            'thread_id': n.thread.gmail_id,
        })

    return JsonResponse({'notifications': notif_data})

def mark_notification_read(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        notif_id = data.get('id')
        try:
            notif = ChatNotification.objects.get(id=notif_id, user=request.user)
            notif.is_read = True
            notif.save()
            return JsonResponse({'status': 'success'})
        except ChatNotification.DoesNotExist:
            return JsonResponse({'status': 'fail'}, status=404)
    return JsonResponse({'status': 'fail'}, status=400)

def clear_chat(request):
    if request.method == 'POST':
        thread_id = request.POST.get('thread_id')
        user_id = request.user.id

        # All messages in this thread where this user is sender or receiver
        ChatMessage.objects.filter(thread__gmail_id=thread_id, 
                                   sender=request.user).update()
        
        # Add current user to 'cleared_by' list
        messages = ChatMessage.objects.filter(thread__gmail_id=thread_id,
                                              sender__in=[request.user],
                                              receiver__in=[request.user])
        for msg in messages:
            msg.cleared_by.add(request.user)

        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'fail'}, status=400)