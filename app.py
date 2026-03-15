"""
نظام إدارة المخزن - الخادم الرئيسي
Flask Backend + Excel Database + Auth System
الإصدار: 2.0 - مع إصلاح ترتيب Routes
"""

from flask import Flask, request, jsonify, send_file, send_from_directory, session
from flask_cors import CORS
import os
import json
import datetime
import io
import traceback
import excel_db as db
import auth
from pdf_generator import generate_operation_pdf

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'wms_secret_key_2026_secure_v2'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)
CORS(app, supports_credentials=True, origins='*')

# تهيئة قاعدة البيانات عند بدء التشغيل
db.init_db()
auth.init_auth()


# ==================== ERROR HANDLER ====================
@app.errorhandler(Exception)
def handle_error(e):
    tb = traceback.format_exc()
    print(f"[ERROR] {e}\n{tb}")
    return jsonify({'error': str(e), 'success': False}), 500


# ==================== AUTH API (يجب أن تكون أولاً) ====================
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    ip = request.remote_addr or ''

    if not username or not password:
        return jsonify({'success': False, 'message': 'يرجى إدخال اسم المستخدم وكلمة المرور'})

    user, error = auth.authenticate(username, password)
    if user:
        session['user'] = user
        session.permanent = True
        auth.log_activity(user['id'], user['username'], 'تسجيل دخول', 'دخول ناجح', ip)
        return jsonify({'success': True, 'user': user})
    else:
        auth.log_activity(0, username, 'محاولة دخول فاشلة', error or '', ip)
        return jsonify({'success': False, 'message': error or 'خطأ في تسجيل الدخول'})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    user = session.get('user')
    if user:
        auth.log_activity(user['id'], user['username'], 'تسجيل خروج', '', request.remote_addr or '')
    session.clear()
    return jsonify({'success': True})


@app.route('/api/auth/me', methods=['GET'])
def get_me():
    user = session.get('user')
    if user:
        return jsonify({'logged_in': True, 'user': user})
    return jsonify({'logged_in': False})


@app.route('/api/auth/change-password', methods=['POST'])
def change_password():
    user = session.get('user')
    if not user:
        return jsonify({'success': False, 'message': 'غير مسجل دخول'})
    data = request.json or {}
    old_pass = data.get('old_password', '')
    new_pass = data.get('new_password', '')
    if not old_pass or not new_pass:
        return jsonify({'success': False, 'message': 'يرجى إدخال كلمة المرور القديمة والجديدة'})
    verified, err = auth.authenticate(user['username'], old_pass)
    if not verified:
        return jsonify({'success': False, 'message': 'كلمة المرور القديمة غير صحيحة'})
    if len(new_pass) < 6:
        return jsonify({'success': False, 'message': 'كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل'})
    auth.reset_user_password(user['id'], new_pass)
    auth.log_activity(user['id'], user['username'], 'تغيير كلمة المرور', '', request.remote_addr or '')
    return jsonify({'success': True, 'message': 'تم تغيير كلمة المرور بنجاح'})


# ==================== USERS MANAGEMENT ====================
@app.route('/api/users', methods=['GET'])
def get_users():
    user = session.get('user')
    if not user or user.get('role') not in ['admin', 'manager']:
        return jsonify({'error': 'غير مصرح'}), 403
    return jsonify(auth.get_all_users())


@app.route('/api/users', methods=['POST'])
def add_user():
    user = session.get('user')
    if not user or user.get('role') != 'admin':
        return jsonify({'error': 'غير مصرح - للمدير فقط'}), 403
    data = request.json or {}
    new_id, error = auth.add_user(data)
    if new_id:
        auth.log_activity(user['id'], user['username'], 'إضافة مستخدم', f"اسم المستخدم: {data.get('username')}", request.remote_addr or '')
        return jsonify({'success': True, 'id': new_id})
    return jsonify({'success': False, 'message': error})


@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    user = session.get('user')
    if not user or user.get('role') != 'admin':
        return jsonify({'error': 'غير مصرح'}), 403
    data = request.json or {}
    success, error = auth.update_user(user_id, data)
    if success:
        auth.log_activity(user['id'], user['username'], 'تعديل مستخدم', f"ID: {user_id}", request.remote_addr or '')
    return jsonify({'success': success, 'message': error or ''})


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = session.get('user')
    if not user or user.get('role') != 'admin':
        return jsonify({'error': 'غير مصرح'}), 403
    if user_id == user.get('id'):
        return jsonify({'success': False, 'message': 'لا يمكنك حذف حسابك الخاص'})
    success = auth.delete_user(user_id)
    if success:
        auth.log_activity(user['id'], user['username'], 'حذف مستخدم', f"ID: {user_id}", request.remote_addr or '')
    return jsonify({'success': success})


@app.route('/api/users/<int:user_id>/reset-password', methods=['POST'])
def reset_password(user_id):
    user = session.get('user')
    if not user or user.get('role') != 'admin':
        return jsonify({'error': 'غير مصرح'}), 403
    data = request.json or {}
    new_pass = data.get('password', '')
    if len(new_pass) < 6:
        return jsonify({'success': False, 'message': 'كلمة المرور يجب أن تكون 6 أحرف على الأقل'})
    success = auth.reset_user_password(user_id, new_pass)
    if success:
        auth.log_activity(user['id'], user['username'], 'إعادة تعيين كلمة مرور', f"ID: {user_id}", request.remote_addr or '')
    return jsonify({'success': success})


@app.route('/api/roles', methods=['GET'])
def get_roles():
    return jsonify(auth.get_roles())


@app.route('/api/activity-log', methods=['GET'])
def get_activity_log():
    user = session.get('user')
    if not user or user.get('role') not in ['admin', 'manager']:
        return jsonify({'error': 'غير مصرح'}), 403
    user_id = request.args.get('user_id')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    limit = int(request.args.get('limit', 200))
    logs = auth.get_activity_log(user_id, date_from, date_to, limit)
    return jsonify(logs)


# ==================== SETTINGS ====================
@app.route('/api/settings', methods=['GET'])
def get_settings():
    try:
        return jsonify(db.get_settings())
    except Exception as e:
        return jsonify({}), 200


@app.route('/api/settings', methods=['POST'])
def update_settings():
    data = request.json or {}
    db.update_settings(data)
    user = session.get('user')
    if user:
        auth.log_activity(user['id'], user['username'], 'تعديل الإعدادات', '', request.remote_addr or '')
    return jsonify({'success': True})


# ==================== UNITS ====================
@app.route('/api/units', methods=['GET'])
def get_units():
    try:
        return jsonify(db.get_units())
    except Exception as e:
        return jsonify([]), 200

@app.route('/api/units', methods=['POST'])
def add_unit():
    data = request.json or {}
    result = db.add_unit(data.get('اسم_الوحدة', ''))
    user = session.get('user')
    if user:
        auth.log_activity(user['id'], user['username'], 'إضافة وحدة', data.get('اسم_الوحدة', ''), request.remote_addr or '')
    return jsonify(result)

@app.route('/api/units/<int:unit_id>', methods=['PUT'])
def update_unit(unit_id):
    data = request.json or {}
    success = db.update_unit(unit_id, data.get('اسم_الوحدة', ''))
    return jsonify({'success': success})

@app.route('/api/units/<int:unit_id>', methods=['DELETE'])
def delete_unit(unit_id):
    success = db.delete_unit(unit_id)
    return jsonify({'success': success})


# ==================== GROUPS ====================
@app.route('/api/groups', methods=['GET'])
def get_groups():
    try:
        return jsonify(db.get_groups())
    except Exception as e:
        return jsonify([]), 200

@app.route('/api/groups', methods=['POST'])
def add_group():
    data = request.json or {}
    result = db.add_group(data.get('اسم_المجموعة', ''))
    return jsonify(result)

@app.route('/api/groups/<int:group_id>', methods=['PUT'])
def update_group(group_id):
    data = request.json or {}
    success = db.update_group(group_id, data.get('اسم_المجموعة', ''))
    return jsonify({'success': success})

@app.route('/api/groups/<int:group_id>', methods=['DELETE'])
def delete_group(group_id):
    success = db.delete_group(group_id)
    return jsonify({'success': success})


# ==================== ITEMS ====================
@app.route('/api/items', methods=['GET'])
def get_items():
    try:
        return jsonify(db.get_items())
    except Exception as e:
        return jsonify([]), 200

@app.route('/api/items', methods=['POST'])
def add_item():
    data = request.json or {}
    new_id = db.add_item(data)
    user = session.get('user')
    if user:
        auth.log_activity(user['id'], user['username'], 'إضافة صنف', data.get('اسم_الصنف', ''), request.remote_addr or '')
    return jsonify({'success': True, 'رقم_الصنف': new_id})

@app.route('/api/items/<int:item_id>', methods=['PUT'])
def update_item(item_id):
    data = request.json or {}
    success = db.update_item(item_id, data)
    return jsonify({'success': success})

@app.route('/api/items/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    success = db.delete_item(item_id)
    return jsonify({'success': success})


# ==================== CUSTOMERS ====================
@app.route('/api/customers', methods=['GET'])
def get_customers():
    try:
        return jsonify(db.get_customers())
    except Exception as e:
        return jsonify([]), 200

@app.route('/api/customers', methods=['POST'])
def add_customer():
    data = request.json or {}
    new_id = db.add_customer(data)
    return jsonify({'success': True, 'رقم_العميل': new_id})

@app.route('/api/customers/<int:cust_id>', methods=['PUT'])
def update_customer(cust_id):
    data = request.json or {}
    success = db.update_customer(cust_id, data)
    return jsonify({'success': success})

@app.route('/api/customers/<int:cust_id>', methods=['DELETE'])
def delete_customer(cust_id):
    success = db.delete_customer(cust_id)
    return jsonify({'success': success})


# ==================== SUPPLIERS ====================
@app.route('/api/suppliers', methods=['GET'])
def get_suppliers():
    try:
        return jsonify(db.get_suppliers())
    except Exception as e:
        return jsonify([]), 200

@app.route('/api/suppliers', methods=['POST'])
def add_supplier():
    data = request.json or {}
    new_id = db.add_supplier(data)
    return jsonify({'success': True, 'رقم_المورد': new_id})

@app.route('/api/suppliers/<int:sup_id>', methods=['PUT'])
def update_supplier(sup_id):
    data = request.json or {}
    success = db.update_supplier(sup_id, data)
    return jsonify({'success': success})

@app.route('/api/suppliers/<int:sup_id>', methods=['DELETE'])
def delete_supplier(sup_id):
    success = db.delete_supplier(sup_id)
    return jsonify({'success': success})


# ==================== WAREHOUSES ====================
@app.route('/api/warehouses', methods=['GET'])
def get_warehouses():
    try:
        return jsonify(db.get_warehouses())
    except Exception as e:
        return jsonify([]), 200

@app.route('/api/warehouses', methods=['POST'])
def add_warehouse():
    data = request.json or {}
    new_id = db.add_warehouse(data)
    return jsonify({'success': True, 'رقم_المخزن': new_id})

@app.route('/api/warehouses/<int:wh_id>', methods=['PUT'])
def update_warehouse(wh_id):
    data = request.json or {}
    success = db.update_warehouse(wh_id, data)
    return jsonify({'success': success})

@app.route('/api/warehouses/<int:wh_id>', methods=['DELETE'])
def delete_warehouse(wh_id):
    success = db.delete_warehouse(wh_id)
    return jsonify({'success': success})


# ==================== OPERATIONS ====================
@app.route('/api/operations', methods=['GET'])
def get_operations():
    try:
        op_type = request.args.get('type')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        supplier_id = request.args.get('supplier_id')
        warehouse_id = request.args.get('warehouse_id')
        ops = db.get_operations(op_type, date_from, date_to, supplier_id, warehouse_id)
        return jsonify(ops)
    except Exception as e:
        return jsonify([]), 200

@app.route('/api/operations/<int:op_id>', methods=['GET'])
def get_operation(op_id):
    op = db.get_operation_by_id(op_id)
    if op:
        return jsonify(op)
    return jsonify({'error': 'not found'}), 404

@app.route('/api/operations', methods=['POST'])
def save_operation():
    data = request.json or {}
    user = session.get('user')
    if user:
        data['اسم_المستخدم'] = user.get('username', '')
        data['رقم_المستخدم'] = user.get('id', '')
    op_id, op_ref = db.save_operation(data)
    if user:
        auth.log_activity(user['id'], user['username'], f"حفظ عملية {data.get('نوع_العملية', '')}",
                          f"رقم: {op_id} - مرجع: {op_ref}", request.remote_addr or '')
    return jsonify({'success': True, 'رقم_العملية': op_id, 'المرجع': op_ref})

@app.route('/api/operations/<int:op_id>', methods=['DELETE'])
def delete_operation(op_id):
    user = session.get('user')
    success = db.delete_operation(op_id)
    if success and user:
        auth.log_activity(user['id'], user['username'], 'حذف عملية', f"ID: {op_id}", request.remote_addr or '')
    return jsonify({'success': success})


# ==================== REPORTS ====================
@app.route('/api/reports/stock', methods=['GET'])
def stock_report():
    try:
        group_id = request.args.get('group_id')
        item_id = request.args.get('item_id')
        low_stock = request.args.get('low_stock') == 'true'
        return jsonify(db.get_stock_report(group_id, item_id, low_stock))
    except Exception as e:
        return jsonify([]), 200


@app.route('/api/reports/stock-by-warehouse', methods=['GET'])
def stock_by_warehouse_report():
    """تقرير المخزون التفصيلي مع كل مخزن"""
    try:
        group_id = request.args.get('group_id')
        item_id = request.args.get('item_id')
        warehouse_id = request.args.get('warehouse_id')
        return jsonify(db.get_stock_by_warehouse(group_id, item_id, warehouse_id))
    except Exception as e:
        print(f'[ERROR] stock_by_warehouse: {e}')
        import traceback; traceback.print_exc()
        return jsonify({'items': [], 'warehouses': []}), 200


@app.route('/api/reports/stock-by-warehouse/excel', methods=['GET'])
def stock_by_warehouse_excel():
    """تصدير تقرير المخزون التفصيلي كملف Excel"""
    try:
        group_id = request.args.get('group_id')
        item_id = request.args.get('item_id')
        warehouse_id = request.args.get('warehouse_id')
        settings = db.get_settings()
        company_name = settings.get('company_name', 'نظام إدارة المخزن')
        report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        excel_output = db.export_stock_excel(group_id, item_id, warehouse_id, company_name, report_date)
        return send_file(
            excel_output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'stock_report_{datetime.datetime.now().strftime("%Y%m%d_%H%M")}.xlsx'
        )
    except Exception as e:
        print(f'[ERROR] stock_excel: {e}')
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/stock-by-warehouse/pdf', methods=['GET'])
def stock_by_warehouse_pdf():
    """تصدير تقرير المخزون التفصيلي كملف PDF"""
    try:
        group_id = request.args.get('group_id')
        item_id = request.args.get('item_id')
        warehouse_id = request.args.get('warehouse_id')
        settings = db.get_settings()
        data = db.get_stock_by_warehouse(group_id, item_id, warehouse_id)
        from pdf_generator import generate_stock_report_pdf
        pdf_bytes = generate_stock_report_pdf(data, settings)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=False,
            download_name=f'stock_report_{datetime.datetime.now().strftime("%Y%m%d_%H%M")}.pdf'
        )
    except Exception as e:
        print(f'[ERROR] stock_pdf: {e}')
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/movements', methods=['GET'])
def movements_report():
    try:
        item_id = request.args.get('item_id')
        op_type = request.args.get('type')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        return jsonify(db.get_movements_report(item_id, op_type, date_from, date_to))
    except Exception as e:
        return jsonify([]), 200


# ==================== PDF ====================
@app.route('/api/operations/<int:op_id>/pdf', methods=['GET'])
def print_operation(op_id):
    op = db.get_operation_by_id(op_id)
    if not op:
        return jsonify({'error': 'not found'}), 404
    settings = db.get_settings()
    pdf_bytes = generate_operation_pdf(op, settings)
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=False,
        download_name=f"operation_{op_id}.pdf"
    )


# ==================== BACKUP ====================
@app.route('/api/backup/create', methods=['POST'])
def create_backup():
    backup_path = db.create_backup()
    filename = os.path.basename(backup_path)
    user = session.get('user')
    if user:
        auth.log_activity(user['id'], user['username'], 'إنشاء نسخة احتياطية', filename, request.remote_addr or '')
    return send_file(backup_path, as_attachment=True, download_name=filename)

@app.route('/api/backup/list', methods=['GET'])
def list_backups():
    try:
        backups = db.list_backups()
        return jsonify(backups)
    except Exception as e:
        return jsonify([]), 200

@app.route('/api/backup/restore', methods=['POST'])
def restore_backup():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if not file.filename.endswith('.xlsx'):
        return jsonify({'error': 'Invalid file type'}), 400
    backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    save_path = os.path.join(backup_dir, file.filename)
    file.save(save_path)
    success = db.restore_backup(save_path)
    if success:
        auth.init_auth()
        user = session.get('user')
        if user:
            auth.log_activity(user['id'], user['username'], 'استعادة نسخة احتياطية', file.filename, request.remote_addr or '')
    return jsonify({'success': success})

@app.route('/api/backup/download-db', methods=['GET'])
def download_db():
    return send_file(db.DB_PATH, as_attachment=True, download_name='warehouse.xlsx')


# ==================== STATIC PAGES (يجب أن تكون آخراً) ====================
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/login')
def login_page():
    return send_from_directory('static', 'login.html')

@app.route('/css/<path:filename>')
def serve_css(filename):
    return send_from_directory('static/css', filename)

@app.route('/js/<path:filename>')
def serve_js(filename):
    return send_from_directory('static/js', filename)

@app.route('/fonts/<path:filename>')
def serve_fonts(filename):
    return send_from_directory('static/fonts', filename)

@app.route('/images/<path:filename>')
def serve_images(filename):
    return send_from_directory('static/images', filename)

# هذا يجب أن يكون آخر route - يلتقط فقط الصفحات غير الموجودة
@app.route('/<path:path>')
def catch_all(path):
    # لا تلتقط مسارات API
    if path.startswith('api/'):
        return jsonify({'error': 'Not found'}), 404
    full_path = os.path.join(app.static_folder, path)
    if os.path.exists(full_path) and os.path.isfile(full_path):
        return send_from_directory('static', path)
    return send_from_directory('static', 'index.html')


if __name__ == '__main__':
    print("=" * 60)
    print("🏪 نظام إدارة المخزن - الإصدار 2.0")
    print("=" * 60)
    print("🌐 الرابط المحلي: http://localhost:5000")
    print("👤 المستخدم الافتراضي: admin")
    print("🔑 كلمة المرور الافتراضية: admin123")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
