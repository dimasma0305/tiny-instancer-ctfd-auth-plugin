import os
import jwt
import time
from flask import Blueprint, redirect, request, abort, url_for, session, current_app
from CTFd.utils.decorators import authed_only
from CTFd.utils.user import get_current_user, get_current_team
from CTFd.plugins import register_plugin_assets_directory

def load(app):
    plugin_bp = Blueprint('tiny_instancer', __name__, url_prefix='/plugins/tiny-instancer')

    @plugin_bp.route('/auth', methods=['GET'])
    @authed_only
    def auth():
        secret = os.environ.get('TI_AUTH_SECRET') or app.config.get('TI_AUTH_SECRET')
        if not secret:
            return "TI_AUTH_SECRET not configured", 500

        user = get_current_user()
        team = get_current_team()

        # Decide identity: uses team.id if available (Team Mode), else user.id (User Mode)
        identity_id = user.id
        if team:
            identity_id = team.id

        payload = {
            "team_id": str(identity_id),
            "user_id": user.id,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600 * 24 # 24 hours
        }

        token = jwt.encode(payload, secret, algorithm='HS256')

        redirect_uri = request.args.get('redirect_uri')
        state = request.args.get('state')

        if not redirect_uri:
            return "Missing redirect_uri", 400

        # Append token and state
        if '?' in redirect_uri:
            target = f"{redirect_uri}&token={token}&state={state}"
        else:
            target = f"{redirect_uri}?token={token}&state={state}"
        
        return redirect(target)

    app.register_blueprint(plugin_bp)
