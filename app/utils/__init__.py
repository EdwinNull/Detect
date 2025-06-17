from functools import wraps
from flask import session, redirect, url_for, flash

# 权限控制中间件
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'error')
            return redirect(url_for('auth.login'))
        return view(*args, **kwargs)
    return wrapped_view

def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'error')
            return redirect(url_for('auth.login'))
        if session.get('role') != 'admin':
            flash('需要管理员权限', 'error')
            return redirect(url_for('user.index'))
        return view(*args, **kwargs)
    return wrapped_view
