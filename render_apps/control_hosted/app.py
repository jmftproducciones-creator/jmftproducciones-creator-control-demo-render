import json, os
from copy import deepcopy
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'control-hosted-json-secret')
app.config['JSON_AS_ASCII'] = False

def _path(name): return DATA_DIR / name

def load_json(name, default=None):
    p = _path(name)
    if not p.exists(): return deepcopy(default if default is not None else [])
    with p.open('r', encoding='utf-8') as f: return json.load(f)

def save_json(name, data):
    p = _path(name); p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', encoding='utf-8') as f: json.dump(data, f, ensure_ascii=False, indent=2)

def now_iso(): return datetime.now().isoformat(timespec='seconds')
def to_int(v, d=None):
    try:
        return d if v in (None, '', 'null') else int(v)
    except: return d

def to_bool(v):
    if isinstance(v, bool): return 1 if v else 0
    return 1 if str(v).strip().lower() in {'1','si','sí','true','on','yes'} else 0

def parse_json(raw, default):
    if not raw: return deepcopy(default)
    if isinstance(raw, (list, dict)): return raw
    try: return json.loads(raw)
    except: return deepcopy(default)

def next_id(rows): return max((to_int(r.get('id'), 0) or 0 for r in rows), default=0) + 1
def safe_date(v):
    if not v: return None
    for fmt in ('%Y-%m-%d', '%Y-%m-%dT%H:%M:%S'):
        try: return datetime.strptime(v[:19], fmt)
        except: pass
    return None

def full_name(u): return ' '.join(filter(None, [u.get('nombre'), u.get('apellido')])).strip() or u.get('usuario') or u.get('email') or 'Usuario'
def users_data():
    rows = load_json('usuarios.json', [])
    out = []
    for u in rows:
        x = dict(u); x['rol'] = x.get('rol_control') or x.get('rol') or 'visor'; x['activo'] = bool(x.get('activo', 1)); out.append(x)
    return out

def plantas_data(): return load_json('plantas.json', [])
def sectores_data(): return load_json('sectores.json', [])
def controles_data(): return load_json('controles.json', [])
def personal_data(): return load_json('personal_control.json', [])
def documentos_data(): return load_json('documentos_control.json', [])
def quimicos_data(): return load_json('productos_quimicos.json', [])
def hallazgos_data(): return load_json('hallazgos_auditoria.json', [])
def acciones_data(): return load_json('acciones_correctivas.json', [])
def cronograma_data(): return load_json('cronograma_semanal.json', [])
def idx(rows): return {r.get('id'): r for r in rows}

def current_user():
    uid = session.get('control_user_id')
    if not uid: return None
    user = idx(users_data()).get(uid)
    if not user or not user.get('activo'):
        session.pop('control_user_id', None); return None
    return user

@app.before_request
def load_user():
    u = current_user(); g.user = SimpleNamespace(**u) if u else None

def login_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not g.user: return redirect(url_for('login'))
        return fn(*a, **k)
    return w

def role_required(*roles):
    def dec(fn):
        @wraps(fn)
        def w(*a, **k):
            if not g.user: return redirect(url_for('login'))
            if g.user.rol not in roles:
                flash('No tienes permisos para acceder a esa sección.', 'warning'); return redirect(url_for('dashboard'))
            return fn(*a, **k)
        return w
    return dec

def enrich_control(c, users_idx=None, sectores_idx=None, plantas_idx=None):
    r = dict(c); users_idx = users_idx or idx(users_data()); sectores_idx = sectores_idx or idx(sectores_data()); plantas_idx = plantas_idx or idx(plantas_data())
    sec = sectores_idx.get(r.get('sector_id')) or {}; pla = plantas_idx.get(r.get('planta_id')) or {}
    ctrl = users_idx.get(r.get('controlador_id')) or {}; cdo = users_idx.get(r.get('controlado_id')) or {}; resp = users_idx.get(r.get('responsable_id')) or cdo
    r['sector'] = sec.get('nombre', '-'); r['sector_nombre'] = r['sector']; r['planta'] = pla.get('nombre', '-'); r['planta_nombre'] = r['planta']
    r['controlador_nombre'] = full_name(ctrl) if ctrl else '-'; r['controlado_nombre'] = full_name(cdo) if cdo else '-'; r['responsable'] = full_name(resp) if resp else ''
    r['auditor_jefe'] = r.get('auditor_jefe_nombre'); r['auditor_acompanante'] = r.get('auditor_acompanante_nombre'); r['auditor_formacion'] = r.get('auditor_formacion_nombre')
    r['agenda_auditoria'] = r.get('agenda_auditoria') or '[]'
    return r

def control_for_user(c, user):
    if user['rol'] in {'superadmin','admin','visor'}: return True
    if user['rol'] == 'plant_manager': return user.get('planta_id') in (None, c.get('planta_id')) or user.get('sector_id') == c.get('sector_id')
    if user['rol'] == 'auditor_jefe':
        actor = full_name(user).lower(); hay = ' '.join(filter(None, [c.get('auditor_jefe_nombre'), c.get('auditor_acompanante_nombre'), c.get('auditor_formacion_nombre')])).lower()
        return actor in hay or user.get('sector_id') == c.get('sector_id')
    return user.get('sector_id') == c.get('sector_id')

def visible_controles(user=None):
    rows = controles_data(); return rows if not user else [c for c in rows if control_for_user(c, user)]

def can_manage_audit_plan(control, user):
    if user['rol'] in {'superadmin','admin'}: return True
    actor = full_name(user).lower(); hay = ' '.join(filter(None, [control.get('auditor_jefe_nombre'), control.get('auditor_acompanante_nombre'), control.get('auditor_formacion_nombre')])).lower()
    return actor in hay

def control_payload(control_id, user=None):
    controls = controles_data(); uidx = idx(users_data()); sidx = idx(sectores_data()); pidx = idx(plantas_data())
    c = next((x for x in controls if x.get('id') == control_id), None)
    if not c: return None
    if user and not control_for_user(c, user): return None
    c = enrich_control(c, uidx, sidx, pidx)
    hall = hallazgos_data(); accs = acciones_data(); acc_by_h = {a.get('hallazgo_id'): a for a in accs if a.get('control_id') == control_id}
    hall_list = []
    for h in hall:
        if h.get('control_id') != control_id: continue
        x = dict(h); ac = acc_by_h.get(h.get('id')); x['accion_correctiva_id'] = ac.get('id') if ac else None; x['ac_estado'] = ac.get('estado_flujo') if ac else None; hall_list.append(x)
    return {'control': c, 'agenda_auditoria': parse_json(c.get('agenda_auditoria'), []), 'hallazgos': hall_list, 'personal': [p for p in personal_data() if p.get('control_id') == control_id], 'documentos': [d for d in documentos_data() if d.get('control_id') == control_id], 'quimicos': [q for q in quimicos_data() if q.get('control_id') == control_id]}

def pending_payload(user):
    controls = [enrich_control(c) for c in visible_controles(user)]; accs = acciones_data(); actor = full_name(user).lower(); audits = []; capas = []
    for c in controls:
        if c.get('tipo_control') == 'A' and c.get('estado_flujo') == 'A Confirmar' and user['rol'] == 'superadmin': audits.append(c)
    for a in accs:
        ia = actor in (a.get('auditor_lider') or '').lower() or user['rol'] in {'superadmin','admin'}
        ir = actor in (a.get('responsable_area') or '').lower() or user['rol'] in {'superadmin','admin'}
        if a.get('estado_flujo') == 'PASO_1' and ia: capas.append(a)
        elif a.get('estado_flujo') in {'PASO_2','PASO_4'} and ir: capas.append(a)
        elif a.get('estado_flujo') in {'PASO_3','PASO_5'} and ia: capas.append(a)
    return audits, capas

@app.context_processor
def pending_ctx():
    if not g.user: return {'sidebar_pending_count': 0, 'sidebar_pending_has_items': False}
    u = current_user(); audits, capas = pending_payload(u); c = len(audits) + len(capas)
    return {'sidebar_pending_count': c, 'sidebar_pending_has_items': c > 0}

@app.route('/')
def index(): return redirect(url_for('dashboard' if g.user else 'login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower(); password = request.form.get('password') or ''
        for u in users_data():
            if not u.get('activo'): continue
            if email in {(u.get('email') or '').lower(), (u.get('usuario') or '').lower()} and check_password_hash(u.get('password_hash') or generate_password_hash('invalid'), password):
                session['control_user_id'] = u['id']; return redirect(url_for('dashboard'))
        flash('Credenciales inválidas.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.pop('control_user_id', None); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user(); controls = [enrich_control(c) for c in visible_controles(user)]; p_rows = personal_data(); d_rows = documentos_data(); q_rows = quimicos_data(); ids = {c['id'] for c in controls}
    p_rows = [p for p in p_rows if p.get('control_id') in ids]; d_rows = [d for d in d_rows if d.get('control_id') in ids]; q_rows = [q for q in q_rows if q.get('control_id') in ids]
    stats = {'documentos_correctos': sum(1 for d in d_rows if (d.get('estado') or '').lower() == 'correcto'), 'documentos_incorrectos': sum(1 for d in d_rows if (d.get('estado') or '').lower() != 'correcto'), 'personas_total': len(p_rows), 'personas_requieren': sum(1 for p in p_rows if to_bool(p.get('requiere_capacitacion'))), 'quimicos_total': len(q_rows), 'quimicos_incorrectos': sum(1 for q in q_rows if not (to_bool(q.get('bajo_llave')) and to_bool(q.get('envase_original')) and to_bool(q.get('etiquetado_correcto')) and to_bool(q.get('hoja_seguridad'))))}
    docs_pp, pers_pp, quims_pp, monthly = [], [], [], {}
    for c in controls:
        cid = c['id']; docs = [d for d in d_rows if d.get('control_id') == cid]; pers = [p for p in p_rows if p.get('control_id') == cid]; quims = [q for q in q_rows if q.get('control_id') == cid]
        docs_pp.append({'sector': c['sector'], 'correcto': sum(1 for d in docs if (d.get('estado') or '').lower() == 'correcto'), 'incorrecto': sum(1 for d in docs if (d.get('estado') or '').lower() != 'correcto')})
        pers_pp.append({'sector': c['sector'], 'relevadas': len(pers), 'requieren': sum(1 for p in pers if to_bool(p.get('requiere_capacitacion')))})
        quims_pp.append({'sector': c['sector'], 'total': len(quims), 'incorrecto': sum(1 for q in quims if not (to_bool(q.get('bajo_llave')) and to_bool(q.get('envase_original')) and to_bool(q.get('etiquetado_correcto')) and to_bool(q.get('hoja_seguridad'))))})
        dt = safe_date(c.get('fecha_control'))
        if dt:
            key = dt.strftime('%Y-%m'); bucket = monthly.setdefault(key, {'mes': dt.strftime('%m/%Y'), 'total_controles': 0, 'docs_total': 0, 'docs_ok': 0}); bucket['total_controles'] += 1; bucket['docs_total'] += len(docs); bucket['docs_ok'] += sum(1 for d in docs if (d.get('estado') or '').lower() == 'correcto')
    tendencias = [monthly[k] for k in sorted(monthly.keys())][-6:]
    return render_template('dashboard.html', stats=stats, documentos_por_planta=docs_pp, personal_por_planta=pers_pp, quimicos_por_planta=quims_pp, tendencias=tendencias, ultimos_controles=sorted(controls, key=lambda x: x.get('fecha_control') or '', reverse=True)[:10])

@app.route('/dashboard_auditorias')
@login_required
def dashboard_auditorias():
    user = current_user(); planta_id = to_int(request.args.get('planta_id')); sector_id = to_int(request.args.get('sector_id')); tipo = request.args.get('tipo_hallazgo') or ''; meses = to_int(request.args.get('meses'), 6) or 6
    controls = [enrich_control(c) for c in visible_controles(user) if c.get('tipo_control') == 'A']; limit = datetime.now() - timedelta(days=30 * meses)
    controls = [c for c in controls if not safe_date(c.get('fecha_control')) or safe_date(c.get('fecha_control')) >= limit]
    if planta_id: controls = [c for c in controls if c.get('planta_id') == planta_id]
    if sector_id: controls = [c for c in controls if c.get('sector_id') == sector_id]
    ids = {c['id'] for c in controls}; hall = [h for h in hallazgos_data() if h.get('control_id') in ids];
    if tipo: hall = [h for h in hall if h.get('tipo_hallazgo') == tipo]
    hid = {h['id'] for h in hall}; accs = [a for a in acciones_data() if a.get('hallazgo_id') in hid or a.get('control_id') in ids]
    stats = {'auditorias_total': len(controls), 'hallazgos_total': len(hall), 'acciones_abiertas': sum(1 for a in accs if a.get('estado_flujo') != 'CERRADO'), 'acciones_cerradas': sum(1 for a in accs if a.get('estado_flujo') == 'CERRADO')}
    hallazgos_por_sector, workflow_sector, acciones_tipos_sector, tendencias, recurrentes = [], [], [], {}, {}
    wf = {}
    for h in hall:
        c = next((x for x in controls if x['id'] == h.get('control_id')), None)
        if not c: continue
        sector = c['sector']; hallazgos_por_sector.append({'sector': sector, 'tipo_hallazgo': h.get('tipo_hallazgo') or 'Sin tipo', 'cantidad': 1}); m = (safe_date(c.get('fecha_control')) or datetime.now()).strftime('%m/%Y'); t = tendencias.setdefault(m, {'mes': m, 'hallazgos_total': 0, 'capas_total': 0, 'capas_cerradas': 0}); t['hallazgos_total'] += 1
        if 'No Conformidad' in (h.get('tipo_hallazgo') or ''): recurrentes.setdefault(sector, {'sector': sector, 'no_conformidades': 0, 'prorrogas': 0}); recurrentes[sector]['no_conformidades'] += 1
    for a in accs:
        sector = (a.get('area_auditada') or 'Sin sector').split(' - ')[-1]; r = wf.setdefault(sector, {'sector': sector, 'cerradas': 0, 'en_revision_sector': 0, 'en_revision_auditor': 0, 'bloqueadas_prorroga': 0, 'vencidas': 0})
        st = a.get('estado_flujo')
        if st == 'CERRADO': r['cerradas'] += 1
        elif st in {'PASO_2', 'PASO_4'}: r['en_revision_sector'] += 1
        else: r['en_revision_auditor'] += 1
        if to_bool(a.get('prorroga_requiere')): r['bloqueadas_prorroga'] += 1; recurrentes.setdefault(sector, {'sector': sector, 'no_conformidades': 0, 'prorrogas': 0}); recurrentes[sector]['prorrogas'] += 1
        acciones_tipos_sector.append({'sector': sector, 'plan_tipo_accion': a.get('plan_tipo_accion') or 'Sin definir', 'cantidad': 1})
        mc = safe_date(a.get('capa_creada_at') or a.get('created_at'))
        if mc: tendencias.setdefault(mc.strftime('%m/%Y'), {'mes': mc.strftime('%m/%Y'), 'hallazgos_total': 0, 'capas_total': 0, 'capas_cerradas': 0})['capas_total'] += 1
        mf = safe_date(a.get('capa_closed_at'))
        if mf: tendencias.setdefault(mf.strftime('%m/%Y'), {'mes': mf.strftime('%m/%Y'), 'hallazgos_total': 0, 'capas_total': 0, 'capas_cerradas': 0})['capas_cerradas'] += 1
    workflow_sector = list(wf.values())
    vals_plan, vals_info, vals_capa, vals_close = [], [], [], []
    for c in controls:
        ini = safe_date(c.get('fecha_control'))
        if not ini: continue
        if safe_date(c.get('plan_completado_at')): vals_plan.append((safe_date(c.get('plan_completado_at')) - ini).days)
        if safe_date(c.get('informe_emitido_at')): vals_info.append((safe_date(c.get('informe_emitido_at')) - ini).days)
    for a in accs:
        fa, ca, cc = safe_date(a.get('fecha_auditoria')), safe_date(a.get('capa_creada_at') or a.get('created_at')), safe_date(a.get('capa_closed_at'))
        if fa and ca: vals_capa.append((ca - fa).days)
        if ca and cc: vals_close.append((cc - ca).days)
    tiempos_ciclo = {'dias_a_plan': round(sum(vals_plan)/len(vals_plan)) if vals_plan else None, 'dias_a_informe': round(sum(vals_info)/len(vals_info)) if vals_info else None, 'dias_a_capa': round(sum(vals_capa)/len(vals_capa)) if vals_capa else None, 'dias_cierre_capa': round(sum(vals_close)/len(vals_close)) if vals_close else None}
    ultimas_acciones = sorted(accs, key=lambda x: x.get('updated_at') or x.get('created_at') or '', reverse=True)[:8]
    for a in ultimas_acciones: a['workflow_estado_visual'] = 'CERRADO' if a.get('estado_flujo') == 'CERRADO' else ('Prorroga' if to_bool(a.get('prorroga_requiere')) else (a.get('estado_flujo') or 'Pendiente'))
    return render_template('dashboard_auditorias.html', plantas=plantas_data(), sectores=sectores_data(), planta_id=planta_id, s_id=sector_id, tipo_hallazgo=tipo, meses=meses, stats_auditoria=stats, hallazgos_por_sector=hallazgos_por_sector, workflow_sector=workflow_sector, acciones_tipos_sector=acciones_tipos_sector, tendencias_mensuales=[tendencias[k] for k in sorted(tendencias.keys())], tiempos_ciclo=tiempos_ciclo, sectores_recurrentes=sorted(recurrentes.values(), key=lambda x: (x['no_conformidades'], x['prorrogas']), reverse=True), ultimas_acciones=ultimas_acciones, hallazgos_disponibles=[{'tipo_hallazgo': t} for t in sorted({h.get('tipo_hallazgo') for h in hallazgos_data() if h.get('tipo_hallazgo')})])

@app.route('/pendientes')
@login_required
def pendientes():
    a, c = pending_payload(current_user()); return render_template('pendientes.html', pending_auditorias=a, pending_capas=c, pending_count=len(a) + len(c))

@app.route('/usuarios')
@login_required
@role_required('superadmin')
def usuarios():
    pidx, sidx = idx(plantas_data()), idx(sectores_data()); rows = []
    for u in users_data():
        x = dict(u); x['planta_nombre'] = (pidx.get(x.get('planta_id')) or {}).get('nombre'); x['sector_nombre'] = (sidx.get(x.get('sector_id')) or {}).get('nombre'); rows.append(x)
    return render_template('usuarios.html', usuarios=rows, plantas=plantas_data(), sectores=sectores_data())

@app.route('/usuarios/nuevo', methods=['POST'])
@login_required
@role_required('superadmin')
def nuevo_usuario():
    rows = load_json('usuarios.json', [])
    rows.append({'id': next_id(rows), 'nombre': request.form.get('nombre','').strip(), 'apellido': request.form.get('apellido','').strip(), 'usuario': request.form.get('usuario','').strip(), 'email': request.form.get('email','').strip(), 'password_hash': generate_password_hash(request.form.get('password','demo123')), 'rol': request.form.get('rol','visor'), 'rol_control': request.form.get('rol','visor'), 'activo': 1, 'created_at': now_iso(), 'updated_at': now_iso(), 'planta_id': to_int(request.form.get('planta_id')), 'sector_id': to_int(request.form.get('sector_id'))})
    save_json('usuarios.json', rows); flash('Usuario creado en JSON.', 'success'); return redirect(url_for('usuarios'))

@app.route('/usuarios/toggle/<int:user_id>', methods=['POST'])
@login_required
@role_required('superadmin')
def toggle_usuario(user_id):
    rows = load_json('usuarios.json', [])
    for u in rows:
        if u.get('id') == user_id: u['activo'] = 0 if to_bool(u.get('activo')) else 1; u['updated_at'] = now_iso(); break
    save_json('usuarios.json', rows); return redirect(url_for('usuarios'))

@app.route('/usuarios/cambiar_rol/<int:user_id>', methods=['POST'])
@login_required
@role_required('superadmin')
def cambiar_rol_usuario(user_id):
    rows = load_json('usuarios.json', [])
    for u in rows:
        if u.get('id') == user_id: u['rol'] = request.form.get('rol','visor'); u['rol_control'] = u['rol']; u['updated_at'] = now_iso(); break
    save_json('usuarios.json', rows); return redirect(url_for('usuarios'))

@app.route('/usuarios/editar/<int:user_id>', methods=['POST'])
@login_required
@role_required('superadmin')
def editar_usuario(user_id):
    rows = load_json('usuarios.json', [])
    for u in rows:
        if u.get('id') == user_id:
            for f in ['nombre','apellido','usuario','email']: u[f] = request.form.get(f,'').strip()
            u['rol'] = request.form.get('rol', u.get('rol','visor')); u['rol_control'] = u['rol']; u['planta_id'] = to_int(request.form.get('planta_id')); u['sector_id'] = to_int(request.form.get('sector_id')); u['updated_at'] = now_iso()
            if request.form.get('password'): u['password_hash'] = generate_password_hash(request.form['password'])
            break
    save_json('usuarios.json', rows); flash('Usuario actualizado.', 'success'); return redirect(url_for('usuarios'))

@app.route('/historial')
@login_required
def historial(): return render_template('historial.html', controles=[enrich_control(c) for c in visible_controles(current_user())], usuarios_activos=[u for u in users_data() if u.get('activo')], sectores=sectores_data(), es_mi_cronograma=False)

@app.route('/mi-cronograma')
@login_required
def mi_cronograma(): return render_template('historial.html', controles=[enrich_control(c) for c in visible_controles(current_user())], usuarios_activos=[u for u in users_data() if u.get('activo')], sectores=sectores_data(), es_mi_cronograma=True)

def cal_status(item, control=None):
    if item.get('item_kind') == 'capa':
        state = item.get('estado_flujo') or 'PASO_1'
        return {'CERRADO': ('Cerrado', 'event-capa-cerrado'), 'PASO_1': ('Clasificación', 'event-capa-auditor'), 'PASO_2': ('Revisión sector', 'event-capa-sector'), 'PASO_3': ('Revisión auditor', 'event-capa-auditor'), 'PASO_4': ('Ejecución', 'event-capa-sector'), 'PASO_5': ('Verificación', 'event-capa-auditor')}.get(state, (state, 'event-capa'))
    if item.get('tipo_control') == 'R':
        if control and control.get('tipo_control') == 'A':
            st = control.get('estado_flujo') or 'Realizada'
            return {'A Confirmar': ('A confirmar', 'event-audit-confirm'), 'Confirmada': ('Confirmada', 'event-audit-confirmed'), 'Reprogramada': ('Reprogramada', 'event-audit-rescheduled')}.get(st, ('Realizada', 'event-realized'))
        return ('Realizada', 'event-realized')
    if item.get('tipo_control') == 'A': return ('Programada', 'event-audit-confirm')
    return ('Programada', 'event-programmed')

@app.route('/api/cronograma/eventos')
@login_required
def get_eventos():
    user = current_user(); controls = {c['id']: enrich_control(c) for c in visible_controles(user)}; uidx, sidx = idx(users_data()), idx(sectores_data()); events = []
    for item in cronograma_data():
        control = controls.get(item.get('control_id')) if item.get('control_id') else None
        if item.get('control_id') and not control: continue
        sec = sidx.get(item.get('sector_id')) or {}; ctrl = uidx.get(item.get('controlador_id')) or {}; cdo = uidx.get(item.get('controlado_id')) or {}; tipo = item.get('tipo_control') or (control.get('tipo_control') if control else 'P'); lab, css = cal_status(item, control)
        events.append({'id': str(item.get('id')), 'title': item.get('titulo') or ('Auditoría' if ((control and control.get('tipo_control') == 'A') or tipo == 'A') else 'Control documental'), 'start': item.get('fecha_inicio'), 'end': item.get('fecha_fin'), 'allDay': True, 'extendedProps': {'original_id': item.get('id'), 'sector_id': item.get('sector_id'), 'sector_nombre': sec.get('nombre','-'), 'controlador_id': item.get('controlador_id'), 'controlado_id': item.get('controlado_id'), 'controlador_nombre': full_name(ctrl) if ctrl else '-', 'controlado_nombre': full_name(cdo) if cdo else '-', 'tipo_control': tipo, 'control_id': item.get('control_id'), 'is_audit': (control and control.get('tipo_control') == 'A') or tipo == 'A', 'plan_auditoria': item.get('plan_auditoria'), 'recurrencia': item.get('recurrencia'), 'recurrencia_fin': item.get('recurrencia_fin'), 'auditor_jefe_nombre': item.get('auditor_jefe_nombre'), 'auditor_acompanante_nombre': item.get('auditor_acompanante_nombre'), 'auditor_formacion_nombre': item.get('auditor_formacion_nombre'), 'jefe_nombre': item.get('auditor_jefe_nombre'), 'acompanante_nombre': item.get('auditor_acompanante_nombre'), 'formacion_nombre': item.get('auditor_formacion_nombre'), 'status_class': css, 'calendar_status': lab}})
    if request.args.get('mi_cronograma') == 'true':
        actor = full_name(user).lower(); events = [e for e in events if e['extendedProps'].get('controlador_id') == user['id'] or e['extendedProps'].get('controlado_id') == user['id'] or actor in (e['extendedProps'].get('auditor_jefe_nombre') or '').lower() or actor in (e['extendedProps'].get('auditor_acompanante_nombre') or '').lower() or actor in (e['extendedProps'].get('auditor_formacion_nombre') or '').lower()]
    for a in acciones_data():
        control = controls.get(a.get('control_id'))
        if not control: continue
        lab, css = cal_status({'item_kind': 'capa', 'estado_flujo': a.get('estado_flujo')})
        events.append({'id': f"capa-{a.get('id')}", 'title': f"CAPA #{a.get('id')}", 'start': a.get('fecha_cierre_programado') or control.get('fecha_control'), 'allDay': True, 'extendedProps': {'item_kind': 'capa', 'ac_id': a.get('id'), 'tipo_hallazgo': a.get('tipo_hallazgo'), 'sector_nombre': control.get('sector'), 'controlador_nombre': a.get('auditor_lider'), 'controlado_nombre': a.get('responsable_area'), 'status_class': css, 'calendar_status': lab}})
    return jsonify(events)
@app.route('/api/cronograma/toggle', methods=['POST'])
@app.route('/api/cronograma/toggle_estado', methods=['POST'])
@login_required
def toggle_cronograma():
    rows = load_json('cronograma_semanal.json', []); data = request.get_json(force=True) or {}; event_id = to_int(data.get('event_id')); state = data.get('new_state')
    if state == 'E' and event_id:
        rows = [r for r in rows if r.get('id') != event_id]; save_json('cronograma_semanal.json', rows); return jsonify({'status': 'success'})
    if state == 'R' and event_id:
        item = next((r for r in rows if r.get('id') == event_id), None)
        if item: item['tipo_control'] = 'R'; item['control_id'] = to_int(data.get('control_id')) or item.get('control_id')
        save_json('cronograma_semanal.json', rows); return jsonify({'status': 'success'})
    item = next((r for r in rows if r.get('id') == event_id), None) if event_id else None
    if not item: item = {'id': next_id(rows)}; rows.append(item)
    item.update({'sector_id': to_int(data.get('sector_id')), 'tipo_control': state or data.get('tipo_control') or item.get('tipo_control') or 'P', 'controlador_id': to_int(data.get('controlador_id')), 'controlado_id': to_int(data.get('controlado_id')), 'fecha_inicio': data.get('fecha_inicio'), 'fecha_fin': data.get('fecha_fin') or data.get('fecha_inicio'), 'hora_inicio': data.get('hora_inicio'), 'hora_fin': data.get('hora_fin'), 'titulo': data.get('titulo') or '', 'recurrencia': data.get('recurrencia'), 'recurrencia_fin': data.get('recurrencia_fin'), 'plan_auditoria': data.get('plan_auditoria'), 'auditor_jefe_nombre': data.get('auditor_jefe_nombre'), 'auditor_acompanante_nombre': data.get('auditor_acompanante_nombre'), 'auditor_formacion_nombre': data.get('auditor_formacion_nombre')})
    save_json('cronograma_semanal.json', rows); return jsonify({'status': 'success', 'id': item['id']})

@app.route('/api/cronograma/bulk_create', methods=['POST'])
@login_required
def bulk_create():
    rows = load_json('cronograma_semanal.json', []); data = request.get_json(force=True) or {}; assignments = data.get('assignments') or []
    for a in assignments:
        rows.append({'id': next_id(rows), 'sector_id': to_int(a.get('sector_id')), 'tipo_control': data.get('tipo_control') or 'A', 'controlador_id': to_int(data.get('controlador_id')), 'controlado_id': to_int(data.get('controlado_id')), 'control_id': None, 'fecha_inicio': a.get('fecha'), 'fecha_fin': a.get('fecha'), 'hora_inicio': None, 'hora_fin': None, 'titulo': data.get('titulo') or '', 'recurrencia': None, 'recurrencia_fin': None, 'parent_id': None, 'plan_auditoria': data.get('plan_auditoria'), 'auditor_jefe_id': None, 'auditor_acompanante_id': None, 'auditor_formacion_id': None, 'auditor_jefe_nombre': data.get('auditor_jefe_nombre'), 'auditor_acompanante_nombre': data.get('auditor_acompanante_nombre'), 'auditor_formacion_nombre': data.get('auditor_formacion_nombre')})
    save_json('cronograma_semanal.json', rows); return jsonify({'status': 'success', 'count': len(assignments)})

def save_related(control_id):
    prs, dcs, qms = load_json('personal_control.json', []), load_json('documentos_control.json', []), load_json('productos_quimicos.json', [])
    prs = [p for p in prs if p.get('control_id') != control_id]; dcs = [d for d in dcs if d.get('control_id') != control_id]; qms = [q for q in qms if q.get('control_id') != control_id]
    for i, n in enumerate(request.form.getlist('personal_nombre[]')):
        if not n.strip(): continue
        prs.append({'id': next_id(prs), 'control_id': control_id, 'nombre_apellido': n.strip(), 'conoce_gestion_documental': to_bool((request.form.getlist('personal_conoce[]') + [''])[i]), 'realizo_capacitacion': to_bool((request.form.getlist('personal_capacitacion[]') + [''])[i]), 'requiere_capacitacion': to_bool((request.form.getlist('personal_requiere[]') + [''])[i]), 'observaciones': (request.form.getlist('personal_observacion[]') + [''])[i].strip()})
    for i, codigo in enumerate(request.form.getlist('documento_codigo[]')):
        obs = (request.form.getlist('documento_observacion[]') + [''])[i] if i < len(request.form.getlist('documento_observacion[]')) else ''
        if not (codigo or obs.strip()): continue
        dcs.append({'id': next_id(dcs), 'control_id': control_id, 'codigo_documento': codigo.strip(), 'revision': (request.form.getlist('documento_revision[]') + [''])[i].strip(), 'estado': (request.form.getlist('documento_estado[]') + ['otro'])[i], 'observaciones': obs.strip(), 'copia_controlada': 1, 'no_cargado_portal': 0, 'imagen_path': None})
    for i, prod in enumerate(request.form.getlist('quimico_producto[]')):
        if not prod.strip(): continue
        qms.append({'id': next_id(qms), 'control_id': control_id, 'nombre_producto': prod.strip(), 'bajo_llave': to_bool((request.form.getlist('quimico_bajo_llave[]') + [''])[i]), 'envase_original': to_bool((request.form.getlist('quimico_envase[]') + [''])[i]), 'etiquetado_correcto': to_bool((request.form.getlist('quimico_etiqueta[]') + [''])[i]), 'hoja_seguridad': to_bool((request.form.getlist('quimico_hoja[]') + [''])[i]), 'observaciones': (request.form.getlist('quimico_observacion[]') + [''])[i].strip(), 'medida': (request.form.getlist('quimico_medida[]') + [''])[i].strip()})
    save_json('personal_control.json', prs); save_json('documentos_control.json', dcs); save_json('productos_quimicos.json', qms)

def refresh_totals(c):
    cid = c['id']; prs = [p for p in personal_data() if p.get('control_id') == cid]; dcs = [d for d in documentos_data() if d.get('control_id') == cid]; qms = [q for q in quimicos_data() if q.get('control_id') == cid]
    c['total_personas_entrevistadas'] = len(prs); c['total_requieren_capacitacion'] = sum(1 for p in prs if to_bool(p.get('requiere_capacitacion'))); c['total_documentos_controlados'] = len(dcs); c['total_documentos_correctos'] = sum(1 for d in dcs if (d.get('estado') or '').lower() == 'correcto'); c['total_documentos_incorrectos'] = sum(1 for d in dcs if (d.get('estado') or '').lower() != 'correcto'); c['sector_tiene_quimicos'] = 1 if qms else to_bool(c.get('sector_tiene_quimicos'))

@app.route('/nuevo-control', methods=['GET', 'POST'])
@login_required
def nuevo_control():
    if request.method == 'POST':
        rows = load_json('controles.json', [])
        c = {'id': next_id(rows), 'cronograma_id': to_int(request.form.get('event_id')), 'planta_id': to_int(request.form.get('planta_id'), 1), 'sector_id': to_int(request.form.get('sector_id')), 'fecha_control': request.form.get('fecha_control'), 'fecha_fin_control': request.form.get('fecha_control'), 'responsable_id': to_int(request.form.get('responsable_id')) or to_int(request.form.get('controlado_id')), 'controlador_id': to_int(request.form.get('controlador_id')), 'controlado_id': to_int(request.form.get('controlado_id')), 'sector_tiene_quimicos': to_bool(request.form.get('sector_tiene_quimicos')), 'observaciones_generales': request.form.get('observaciones_generales', '').strip(), 'created_at': now_iso(), 'updated_at': now_iso(), 'tipo_control': 'P', 'estado_flujo': 'Realizada', 'auditor_jefe_id': to_int(request.form.get('auditor_jefe_id')), 'auditor_acompanante_id': to_int(request.form.get('auditor_acompanante_id')), 'auditor_formacion_id': to_int(request.form.get('auditor_formacion_id')), 'auditor_jefe_nombre': None, 'auditor_acompanante_nombre': None, 'auditor_formacion_nombre': None, 'riesgos_pdf_path': None, 'agenda_auditoria': '[]'}
        rows.append(c); save_json('controles.json', rows); save_related(c['id'])
        rows = load_json('controles.json', [])
        for r in rows:
            if r['id'] == c['id']: refresh_totals(r); r['updated_at'] = now_iso(); break
        save_json('controles.json', rows)
        cr = load_json('cronograma_semanal.json', [])
        for i in cr:
            if i.get('id') == c['cronograma_id']: i['tipo_control'] = 'R'; i['control_id'] = c['id']; break
        save_json('cronograma_semanal.json', cr); flash('Control guardado en JSON.', 'success'); return redirect(url_for('detalle_control', control_id=c['id']))
    return render_template('nuevo_control.html', sectores=sectores_data(), usuarios=[u for u in users_data() if u.get('activo')])

@app.route('/nueva-auditoria', methods=['GET', 'POST'])
@login_required
def nueva_auditoria():
    if request.method == 'POST':
        rows = load_json('controles.json', [])
        c = {'id': next_id(rows), 'cronograma_id': to_int(request.form.get('event_id')), 'planta_id': to_int(request.form.get('planta_id'), 1), 'sector_id': to_int(request.form.get('sector_id')), 'fecha_control': request.form.get('fecha_control'), 'fecha_fin_control': request.form.get('fecha_fin_control') or request.form.get('fecha_control'), 'responsable_id': to_int(request.form.get('controlado_id')), 'controlador_id': to_int(request.form.get('controlador_id')) or getattr(g.user, 'id', None), 'controlado_id': to_int(request.form.get('controlado_id')), 'sector_tiene_quimicos': 0, 'observaciones_generales': request.form.get('observaciones_generales', '').strip(), 'created_at': now_iso(), 'updated_at': now_iso(), 'tipo_control': 'A', 'estado_flujo': 'A Confirmar', 'auditor_jefe_id': None, 'auditor_acompanante_id': None, 'auditor_formacion_id': None, 'auditor_jefe_nombre': request.form.get('auditor_jefe_nombre', '').strip(), 'auditor_acompanante_nombre': request.form.get('auditor_acompanante_nombre', '').strip(), 'auditor_formacion_nombre': request.form.get('auditor_formacion_nombre', '').strip(), 'riesgos_pdf_path': None, 'sistema_gestion_auditoria': '', 'objetivo_auditoria': '', 'criterios_auditoria': '', 'descripcion_actividades_auditoria': '', 'recursos_auditoria': '', 'agenda_auditoria_path': None, 'agenda_auditoria': '[]', 'fortalezas_auditoria': None, 'conclusiones_auditoria': None, 'plan_completado_at': None, 'informe_emitido_at': None}
        rows.append(c); save_json('controles.json', rows)
        cr = load_json('cronograma_semanal.json', [])
        for i in cr:
            if i.get('id') == c['cronograma_id']:
                i['tipo_control'] = 'R'; i['control_id'] = c['id']; i['auditor_jefe_nombre'] = c['auditor_jefe_nombre']; i['auditor_acompanante_nombre'] = c['auditor_acompanante_nombre']; i['auditor_formacion_nombre'] = c['auditor_formacion_nombre']; break
        save_json('cronograma_semanal.json', cr); flash('Auditoría guardada y enviada a confirmar.', 'success'); return redirect(url_for('detalle_control', control_id=c['id']))
    return render_template('nueva_auditoria.html', sectores=sectores_data(), usuarios=[u for u in users_data() if u.get('activo')])

@app.route('/control/<int:control_id>')
@login_required
def detalle_control(control_id):
    p = control_payload(control_id, current_user())
    if not p: abort(404)
    user = current_user()
    return render_template('detalle_control.html', **p, can_manage_audit_plan=can_manage_audit_plan(p['control'], user), can_create_capa=user['rol'] in {'superadmin','admin','auditor_jefe'})

@app.route('/control/publico/<int:control_id>')
def detalle_control_publico(control_id):
    p = control_payload(control_id)
    if not p: abort(404)
    return render_template('detalle_control_publico.html', **p)
@app.route('/auditoria/<int:control_id>/confirmar', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def confirmar_auditoria(control_id):
    rows = load_json('controles.json', [])
    for r in rows:
        if r.get('id') == control_id: r['estado_flujo'] = 'Confirmada'; r['updated_at'] = now_iso(); break
    save_json('controles.json', rows); flash('Auditoría confirmada.', 'success'); return redirect(url_for('detalle_control', control_id=control_id))

@app.route('/auditoria/<int:control_id>/reprogramar', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def reprogramar_auditoria(control_id):
    rows = load_json('controles.json', [])
    for r in rows:
        if r.get('id') == control_id:
            r['fecha_control'] = request.form.get('nueva_fecha_inicio') or r.get('fecha_control'); r['fecha_fin_control'] = request.form.get('nueva_fecha_fin') or r.get('fecha_fin_control'); r['estado_flujo'] = 'Reprogramada'; r['updated_at'] = now_iso(); break
    save_json('controles.json', rows); flash('Auditoría reprogramada en JSON.', 'success'); return redirect(url_for('detalle_control', control_id=control_id))

@app.route('/auditoria/<int:control_id>/plan', methods=['GET', 'POST'])
@login_required
def plan_auditoria(control_id):
    p = control_payload(control_id, current_user())
    if not p: abort(404)
    if request.method == 'POST':
        rows = load_json('controles.json', [])
        for r in rows:
            if r.get('id') == control_id:
                for f in ['sistema_gestion_auditoria','objetivo_auditoria','criterios_auditoria','descripcion_actividades_auditoria','recursos_auditoria']: r[f] = request.form.get(f, '').strip()
                agenda = []
                for dia, hora, act, lugar, aud in zip(request.form.getlist('agenda_dia[]'), request.form.getlist('agenda_hora[]'), request.form.getlist('agenda_actividad[]'), request.form.getlist('agenda_lugar[]'), request.form.getlist('agenda_auditor[]')):
                    if any([dia, hora, act, lugar, aud]): agenda.append({'dia': dia, 'hora': hora, 'actividad': act, 'lugar': lugar, 'auditor': aud})
                r['agenda_auditoria'] = json.dumps(agenda, ensure_ascii=False); r['plan_completado_at'] = now_iso(); r['estado_flujo'] = 'Confirmada' if r.get('estado_flujo') == 'A Confirmar' else r.get('estado_flujo'); r['updated_at'] = now_iso(); break
        save_json('controles.json', rows); flash('Plan de auditoría guardado en JSON.', 'success'); return redirect(url_for('detalle_control', control_id=control_id))
    return render_template('plan_auditoria.html', control=p['control'], agenda_existente=p['agenda_auditoria'])

@app.route('/auditoria/<int:control_id>/informe', methods=['GET', 'POST'])
@login_required
def informe_auditoria(control_id):
    p = control_payload(control_id, current_user())
    if not p: abort(404)
    if request.method == 'POST':
        rows = load_json('controles.json', []); hall = load_json('hallazgos_auditoria.json', []); hall = [h for h in hall if h.get('control_id') != control_id]
        for r in rows:
            if r.get('id') == control_id: r['fortalezas_auditoria'] = request.form.get('fortalezas_auditoria', '').strip(); r['conclusiones_auditoria'] = request.form.get('conclusiones_auditoria', '').strip(); r['informe_emitido_at'] = now_iso(); r['updated_at'] = now_iso(); break
        for req, tipo, desc in zip(request.form.getlist('hallazgo_requisito[]'), request.form.getlist('hallazgo_tipo[]'), request.form.getlist('hallazgo_descripcion[]')):
            if not any([req, tipo, desc]): continue
            hall.append({'id': next_id(hall), 'control_id': control_id, 'requisito': req.strip(), 'tipo_hallazgo': tipo.strip(), 'descripcion': desc.strip(), 'created_at': now_iso(), 'updated_at': now_iso()})
        save_json('controles.json', rows); save_json('hallazgos_auditoria.json', hall); flash('Informe de auditoría guardado en JSON.', 'success'); return redirect(url_for('detalle_control', control_id=control_id))
    return render_template('informe_auditoria.html', control=p['control'], hallazgos=p['hallazgos'])

@app.route('/auditoria/hallazgo/<int:hallazgo_id>/nueva_accion')
@login_required
def nueva_accion_correctiva(hallazgo_id):
    hallazgo = next((h for h in hallazgos_data() if h.get('id') == hallazgo_id), None)
    if not hallazgo: abort(404)
    control = enrich_control(next(c for c in controles_data() if c.get('id') == hallazgo.get('control_id')))
    rows = load_json('acciones_correctivas.json', []); ex = next((a for a in rows if a.get('hallazgo_id') == hallazgo_id), None)
    if ex: return redirect(url_for('accion_correctiva', ac_id=ex['id']))
    new = {'id': next_id(rows), 'hallazgo_id': hallazgo_id, 'estado_flujo': 'PASO_1', 'control_id': control['id'], 'tipo_auditoria': 'Interna', 'fecha_auditoria': control.get('fecha_control'), 'tipo_hallazgo': hallazgo.get('tipo_hallazgo'), 'requisito_normativo': hallazgo.get('requisito'), 'auditor_lider': control.get('auditor_jefe_nombre'), 'auditor_acompanante': control.get('auditor_acompanante_nombre'), 'auditor_formacion': control.get('auditor_formacion_nombre'), 'area_auditada': f"{control.get('planta')} - {control.get('sector')}", 'responsable_area': control.get('controlado_nombre'), 'responsable_verificacion': control.get('auditor_jefe_nombre'), 'evidencia_descripcion': hallazgo.get('descripcion'), 'accion_inmediata_requiere': 0, 'prorroga_requiere': 0, 'aprueba_causas': 0, 'aprueba_plan': 0, 'created_at': now_iso(), 'updated_at': now_iso(), 'capa_creada_at': now_iso(), 'capa_closed_at': None}
    rows.append(new); save_json('acciones_correctivas.json', rows); flash('Acción correctiva creada en JSON.', 'success'); return redirect(url_for('accion_correctiva', ac_id=new['id']))

def advance_capa(ac):
    st = ac.get('estado_flujo') or 'PASO_1'
    if st == 'PASO_1': ac['estado_flujo'] = 'PASO_2'
    elif st == 'PASO_2': ac['estado_flujo'] = 'PASO_3'
    elif st == 'PASO_3': ac['estado_flujo'] = 'PASO_4' if to_bool(ac.get('aprueba_causas')) and to_bool(ac.get('aprueba_plan')) else 'PASO_2'
    elif st == 'PASO_4': ac['estado_flujo'] = 'PASO_5'
    elif st == 'PASO_5': ac['estado_flujo'] = 'CERRADO'; ac['capa_closed_at'] = now_iso()

@app.route('/acciones_correctivas/<int:ac_id>', methods=['GET', 'POST'])
@login_required
def accion_correctiva(ac_id):
    rows = load_json('acciones_correctivas.json', []); ac = next((a for a in rows if a.get('id') == ac_id), None)
    if not ac: abort(404)
    user = current_user(); name = full_name(user)
    if request.method == 'POST':
        for k, v in request.form.items():
            if k == 'paso_guardado': continue
            ac[k] = to_bool(v) if k in {'accion_inmediata_requiere','prorroga_requiere','aprueba_causas','aprueba_plan'} else (v.strip() if isinstance(v, str) else v)
        advance_capa(ac); ac['updated_at'] = now_iso(); save_json('acciones_correctivas.json', rows); flash('CAPA actualizada en JSON.', 'success'); return redirect(url_for('accion_correctiva', ac_id=ac_id))
    is_auditor = name.lower() in (ac.get('auditor_lider') or '').lower() or user['rol'] in {'superadmin','admin'}
    is_resp = name.lower() in (ac.get('responsable_area') or '').lower() or user['rol'] in {'superadmin','admin'}
    return render_template('acciones_correctivas.html', ac=ac, control_id=ac.get('control_id'), is_capa_auditor=is_auditor, is_capa_responsable=is_resp, full_name=name)

@app.route('/editar-control/<int:control_id>', methods=['GET', 'POST'])
@login_required
def editar_control(control_id):
    p = control_payload(control_id, current_user())
    if not p: abort(404)
    rows = load_json('controles.json', [])
    if request.method == 'POST':
        for r in rows:
            if r.get('id') == control_id: r['sector_id'] = to_int(request.form.get('sector_id')); r['fecha_control'] = request.form.get('fecha_control'); r['controlado_id'] = to_int(request.form.get('controlado_id')); r['controlador_id'] = to_int(request.form.get('controlador_id')); r['observaciones_generales'] = request.form.get('observaciones_generales', '').strip(); r['sector_tiene_quimicos'] = to_bool(request.form.get('sector_tiene_quimicos')); r['updated_at'] = now_iso(); break
        save_json('controles.json', rows); save_related(control_id); rows = load_json('controles.json', [])
        for r in rows:
            if r['id'] == control_id: refresh_totals(r); break
        save_json('controles.json', rows); flash('Control actualizado en JSON.', 'success'); return redirect(url_for('detalle_control', control_id=control_id))
    return render_template('editar_control.html', control=p['control'], personal=p['personal'], documentos=p['documentos'], quimicos=p['quimicos'], sectores=sectores_data(), usuarios=[u for u in users_data() if u.get('activo')])

@app.route('/editar-auditoria/<int:control_id>', methods=['GET', 'POST'])
@login_required
def editar_auditoria(control_id):
    p = control_payload(control_id, current_user())
    if not p: abort(404)
    rows = load_json('controles.json', [])
    if request.method == 'POST':
        for r in rows:
            if r.get('id') == control_id:
                for f in ['sector_id','controlado_id']: r[f] = to_int(request.form.get(f))
                for f in ['fecha_control','fecha_fin_control','auditor_jefe_nombre','auditor_acompanante_nombre','auditor_formacion_nombre','observaciones_generales']: r[f] = request.form.get(f, '').strip()
                r['updated_at'] = now_iso(); break
        save_json('controles.json', rows); flash('Auditoría actualizada en JSON.', 'success'); return redirect(url_for('detalle_control', control_id=control_id))
    return render_template('editar_auditoria.html', control=p['control'], sectores=sectores_data(), usuarios=[u for u in users_data() if u.get('activo')])

@app.route('/eliminar-control/<int:control_id>', methods=['POST'])
@login_required
@role_required('superadmin')
def eliminar_control(control_id):
    save_json('controles.json', [c for c in load_json('controles.json', []) if c.get('id') != control_id])
    save_json('personal_control.json', [p for p in personal_data() if p.get('control_id') != control_id])
    save_json('documentos_control.json', [d for d in documentos_data() if d.get('control_id') != control_id])
    save_json('productos_quimicos.json', [q for q in quimicos_data() if q.get('control_id') != control_id])
    save_json('hallazgos_auditoria.json', [h for h in hallazgos_data() if h.get('control_id') != control_id])
    save_json('acciones_correctivas.json', [a for a in acciones_data() if a.get('control_id') != control_id])
    flash('Control eliminado de la versión JSON.', 'success'); return redirect(url_for('historial'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5051')), debug=True)
