"""

The MIT License (MIT)

Copyright (c) 2016, Mark Rogaski

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""
from __future__ import unicode_literals

from datetime import datetime

from django.http import HttpResponseRedirect, Http404, HttpResponseForbidden
from django.utils.timezone import make_aware
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import login
from django.views.generic.edit import FormView
from django.contrib.sites.shortcuts import get_current_site
from discord_bind.compat import is_authenticated, reverse
from discord_bind.forms import EmailVerifyForm
import requests
from requests_oauthlib import OAuth2Session

from account.models import (
    Account,
    EmailAddress,
)
from discord_bind.models import DiscordUser, DiscordInvite
from discord_bind.conf import settings
import json
import logging
logger = logging.getLogger(__name__)


def oauth_session(request, scope=None, state=None, token=None):
    """ Constructs the OAuth2 session object. """
    if settings.DISCORD_REDIRECT_URI is not None:
        redirect_uri = settings.DISCORD_REDIRECT_URI
    else:
        redirect_uri = request.build_absolute_uri(
            reverse('discord_bind_callback'))
    return OAuth2Session(settings.DISCORD_CLIENT_ID,
                         redirect_uri=redirect_uri,
                         scope=scope,
                         token=token,
                         state=state)


def log_user_in(request, data):
    uid = data.pop('uid')
    discord_user_exist = DiscordUser.objects.filter(uid=uid).exists()
    if discord_user_exist:
        user = User.objects.get(username=uid)
        DiscordUser.objects.filter(uid=uid).update(**data)
    else:
        if data.get('email_verified'):
            user = User.objects.create_user(uid)
            DiscordUser.objects.create(uid=uid, user=user, **data)
            Account.objects.filter(user=user).update(
                nickname=data.get('username'))
        else:
            # TODO: need to be optimized
            user = User.objects.create_user(uid, is_active=False)
            DiscordUser.objects.create(uid=uid, user=user, **data)
            Account.objects.filter(user=user).update(
                nickname=data.get('username'))
            redir_uri = reverse('account_verify_email')
            request.session['discord_bind_return_uri'] = redir_uri
            request.session['unverified_email'] = data.get('email')
            request.session['uid'] = uid
            return
    login(request, user)


def bind_user(request, data):
        """ Create or update a DiscordUser instance """
        uid = data.pop('uid')
        count = DiscordUser.objects.filter(uid=uid).update(user=request.user,
                                                           **data)
        if count == 0:
            DiscordUser.objects.create(uid=uid,
                                       user=request.user,
                                       **data)


def index(request):
    # Record the final redirect alternatives
    if 'invite_uri' in request.GET:
        request.session['discord_bind_invite_uri'] = request.GET['invite_uri']
    else:
        request.session['discord_bind_invite_uri'] = (
                settings.DISCORD_INVITE_URI)

    if 'return_uri' in request.GET:
        request.session['discord_bind_return_uri'] = request.GET['return_uri']
    else:
        request.session['discord_bind_return_uri'] = (
                settings.DISCORD_RETURN_URI)

    # Compute the authorization URI
    scope = settings.DISCORD_AUTH_SCOPE
    oauth = oauth_session(request, scope=scope)
    url, state = oauth.authorization_url(settings.DISCORD_BASE_URI +
                                         settings.DISCORD_AUTHZ_PATH)
    request.session['discord_bind_oauth_state'] = state
    return HttpResponseRedirect(url)


def callback(request):
    def decompose_data(user, token):
        """ Extract the important details """
        data = {
            'uid': user['id'],
            'username': user['username'],
            'discriminator': user['discriminator'],
            'email': user.get('email', ''),
            'email_verified': user.get('verified', False),
            'avatar': user.get('avatar', ''),
            'access_token': token['access_token'],
            'refresh_token': token.get('refresh_token', ''),
            'scope': ' '.join(token.get('scope', '')),
        }
        for k in data:
            if data[k] is None:
                data[k] = ''
        try:
            expiry = datetime.utcfromtimestamp(float(token['expires_at']))
            if settings.USE_TZ:
                expiry = make_aware(expiry)
            data['expiry'] = expiry
        except KeyError:
            pass
        return data

    response = request.build_absolute_uri()
    state = request.session['discord_bind_oauth_state']
    if 'state' not in request.GET or request.GET['state'] != state:
        return HttpResponseForbidden()
    oauth = oauth_session(request, state=state)
    token = oauth.fetch_token(settings.DISCORD_BASE_URI +
                              settings.DISCORD_TOKEN_PATH,
                              client_secret=settings.DISCORD_CLIENT_SECRET,
                              authorization_response=response)

    # Get Discord user data
    user = oauth.get(settings.DISCORD_BASE_URI + '/users/@me').json()
    data = decompose_data(user, token)
    if request.user.is_authenticated:
        bind_user(request, data)
    else:
        log_user_in(request, data)

    # Accept Discord invites
    groups = request.user.groups.all()
    invites = DiscordInvite.objects.filter(active=True).filter(
                                        Q(groups__in=groups) | Q(groups=None))
    count = 0
    for invite in invites:
        r = requests.put(
            (settings.DISCORD_BASE_URI + '/guilds/' + invite.guild_id +
             "/members/" + user.get('id')),
            data=json.dumps(dict(access_token=token.get("access_token"))),
            headers={'Content-Type': 'application/json',
                     'Authorization': settings.BOT_TOKEN})

        if r.status_code == 201 or 204:
            # code=204 no_content, if user already invited to the guild
            # code=201 created, successfully get invited
            count += 1
            logger.info(('accepted Discord '
                         'invite for %s/%s') % (invite.guild_name,
                                                invite.channel_name))
        else:
            logger.warning(('failed to accept Discord '
                            'invite for %s/%s: %d %s') % (invite.guild_name,
                                                          invite.channel_name,
                                                          r.status_code,
                                                          r.reason))

    # Select return target
    if count > 0:
        messages.success(request, '%d Discord invite(s) accepted.' % count)
        url = request.session.get('discord_bind_return_uri')
    else:
        url = request.session.get('discord_bind_return_uri')

    # Clean up
    del request.session['discord_bind_oauth_state']
    del request.session['discord_bind_invite_uri']
    del request.session['discord_bind_return_uri']

    return HttpResponseRedirect(url)


class EmailVerifyView(FormView):

    template_name = "account/email_verify.html"
    template_name_email_sent = "account/email_confirmation_sent.html"
    form_class = EmailVerifyForm
    email = str()
    success_url = "/"
    uid = str()

    def get(self, request, *args, **kwargs):
        "get the email from the session"
        unverified_email = request.session.get('unverified_email')
        if not unverified_email:
            return HttpResponseForbidden()
        self.email = unverified_email
        del request.session['unverified_email']
        return self.render_to_response(self.get_context_data())

    def get_initial(self):
        initial = super().get_initial()
        if self.email:
            initial["email"] = self.email
        return initial

    def create_email_address(self, user, email, **kwargs):
        kwargs.setdefault("primary", True)
        kwargs.setdefault("verified", False)
        return EmailAddress.objects.add_email(user, email, **kwargs)

    def send_email_confirmation(self, email_address):
        email_address.send_confirmation(site=get_current_site(self.request))

    def form_valid(self, form):

        discord_user = DiscordUser.objects.get(uid=self.uid)
        user = discord_user.user
        email = form.cleaned_data["email"]
        email_address = self.create_email_address(user, email)
        self.send_email_confirmation(email_address)
        response_kwargs = {
            "request": self.request,
            "template": self.template_name_email_sent,
            "context": {
                "email": email,
                "success_url": self.get_success_url(),
            }
        }
        return self.response_class(**response_kwargs)

    def post(self, request, *args, **kwargs):
        self.uid = request.session.get('uid')
        del request.session['uid']
        if is_authenticated(self.request.user):
            raise Http404()
        return super().post(request, *args, **kwargs)
