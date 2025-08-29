import sys, csv, json, ast, re, os

def parse_obj(s):
    if isinstance(s, dict): return s
    if s is None: return {}
    t = s.strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    try:
        return ast.literal_eval(t)
    except Exception:
        pass
    u = t
    if u.endswith('"') and u.count('"') % 2 == 1: u = u[:-1]
    if "'" in u and '"' not in u:
        u = u.replace("'", '"')
    u = re.sub(r'(:\s*)(\d{4}-\d{2}-\d{2})(\s*[},])', r'\1"\2"\3', u)
    u = re.sub(r'(:\s*)([A-Za-z_]+)(\s*[},])', r'\1"\2"\3', u)
    try:
        return json.loads(u)
    except Exception:
        try:
            return ast.literal_eval(u)
        except Exception:
            return {}

def keep2_mask_rest(s):
    if not s: return s
    if len(s) <= 2: return s[0] + 'X'*(len(s)-1) if len(s)==2 else 'X'
    return s[:2] + 'X'*(len(s)-2)

def mask_phone(x):
    if x is None: return x
    d = re.sub(r'\D','', str(x))
    if len(d)==10:
        return d[:2] + 'XXXXXX' + d[-2:]
    return re.sub(r'\d','X', str(x))

def mask_aadhar(x):
    if x is None: return x
    d = re.sub(r'\D','', str(x))
    if len(d)==12:
        m = d[:2] + 'XXXXXXXX' + d[-2:]
        return m
    return re.sub(r'\d','X', str(x))

def mask_passport(x):
    s = str(x)
    m = re.match(r'([A-Za-z])(\d{5})(\d{2})$', s) or re.match(r'([A-Za-z])(\d{4})(\d{3})$', s) or re.match(r'([A-Za-z])(\d{3,5})(\d{2})', s)
    if m:
        g = m.groups()
        return g[0].upper() + 'X'*len(g[1]) + g[-1]
    if re.match(r'^[A-Za-z]\d{7}$', s):
        return s[0].upper() + 'XXXXX' + s[-2:]
    return re.sub(r'[A-Za-z0-9]', 'X', s)

def mask_email(x):
    s = str(x)
    p = s.split('@')
    if len(p)!=2: return s
    local, dom = p[0], p[1]
    if len(local)<=2: ml = 'X'*len(local)
    else: ml = local[:2] + 'X'*(len(local)-2)
    return ml + '@' + dom

def mask_upi(x):
    s = str(x)
    p = s.split('@')
    if len(p)!=2: return s
    user, handle = p[0], p[1]
    if len(user)<=2: mu = 'X'*len(user)
    else: mu = user[:2] + 'X'*(len(user)-2)
    return mu + '@' + handle

def mask_name(n):
    toks = str(n).split()
    out = []
    for w in toks:
        if len(w)==0: out.append(w)
        else:
            out.append(w[0].upper() + ('X'*(len(w)-1)))
    return ' '.join(out)

def mask_address(a):
    s = str(a)
    return ''.join(('X' if c.isdigit() or c.isalpha() else c) for c in s)

def mask_ip(ip):
    s = str(ip)
    m = re.match(r'^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*$', s)
    if not m: return s
    first = m.group(1)
    return first + '.XXX.XXX.XXX'

def mask_device(d):
    s = str(d)
    if len(s)<=3: return 'X'*len(s)
    return 'X'*(len(s)-3) + s[-3:]

def is_phone(v):
    d = re.sub(r'\D','', str(v))
    return True if re.fullmatch(r'\d{10}', d or '') else False

def is_aadhar(v):
    d = re.sub(r'\D','', str(v))
    return True if re.fullmatch(r'\d{12}', d or '') else False

def is_passport(v):
    s = str(v).strip()
    return True if re.fullmatch(r'[A-Za-z]\d{7}', s) else False

def is_upi(v):
    s = str(v)
    return True if re.fullmatch(r'[A-Za-z0-9._\-]{2,}@[A-Za-z]{2,}', s) else False

def is_email(v):
    return True if re.search(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', str(v) or '') else False

def is_full_name(v):
    s = str(v).strip()
    toks = [t for t in re.split(r'\s+', s) if t]
    return len(toks)>=2 and all(re.search(r'[A-Za-z]', t) for t in toks[:2])

def looks_address(v):
    s = str(v)
    return (len(s)>=12 and (re.search(r'\d', s) and (',' in s or re.search(r'\broad\b|\bstreet\b|\blane\b|\bsector\b', s.lower())))) or (len(s)>=18 and ' ' in s)

def is_ip(v):
    s = str(v).strip()
    m = re.match(r'^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*$', s)
    if not m: return False
    try:
        parts = [int(x) for x in m.groups()]
        return all(0<=p<=255 for p in parts)
    except:
        return False

def nonempty(x): return x is not None and str(x).strip()!=''

def main():
    if len(sys.argv)<2:
        print("usage: python3 detector_full_candidate_name.py <input_csv>")
        sys.exit(2)
    fin = sys.argv[1]
    fout = 'redacted_output_candidate_full_name.csv'
    rows = []
    with open(fin, 'r', newline='', encoding='utf-8') as f:
        rd = csv.DictReader(f)
        cols = [c.strip() for c in rd.fieldnames]
        json_col = 'Data_json' if 'Data_json' in cols else ('data_json' if 'data_json' in cols else None)
        if not json_col or 'record_id' not in cols:
            print('bad columns')
            sys.exit(3)
        for r in rd:
            rid = r.get('record_id')
            raw = r.get(json_col, '')
            obj = parse_obj(raw)
            if not isinstance(obj, dict): obj = {}
            val_phone = obj.get('phone') if 'phone' in obj else obj.get('contact')
            val_aadhar = obj.get('aadhar')
            val_passport = obj.get('passport')
            val_upi = obj.get('upi_id')
            val_email = obj.get('email')
            full_name = obj.get('name')
            fname, lname = obj.get('first_name'), obj.get('last_name')
            addr = obj.get('address')
            ip = obj.get('ip_address')
            device = obj.get('device_id')

            has_A = False
            if nonempty(val_phone) and is_phone(val_phone): has_A = True
            if nonempty(val_aadhar) and is_aadhar(val_aadhar): has_A = True or has_A
            if nonempty(val_passport) and is_passport(val_passport): has_A = True or has_A
            if nonempty(val_upi) and is_upi(val_upi): has_A = True or has_A

            name_is_full = (nonempty(full_name) and is_full_name(full_name)) or (nonempty(fname) and nonempty(lname))
            email_ok = nonempty(val_email) and is_email(val_email)
            address_ok = nonempty(addr) and looks_address(addr)
            dev_or_ip = (nonempty(ip) and is_ip(ip)) or nonempty(device)

            comb_types = set()
            if name_is_full: comb_types.add('name')
            if email_ok: comb_types.add('email')
            if address_ok: comb_types.add('address')
            if dev_or_ip: comb_types.add('devip')

            ispii = has_A or (len(comb_types)>=2)

            red = dict(obj)
            if nonempty(val_phone) and (has_A or ispii): red['phone'] = mask_phone(val_phone)
            if nonempty(val_aadhar) and (has_A or ispii): red['aadhar'] = mask_aadhar(val_aadhar)
            if nonempty(val_passport) and (has_A or ispii): red['passport'] = mask_passport(val_passport)
            if nonempty(val_upi) and (has_A or ispii): red['upi_id'] = mask_upi(val_upi)

            if ispii:
                if name_is_full:
                    if nonempty(full_name): red['name'] = mask_name(full_name)
                    if nonempty(fname): red['first_name'] = mask_name(fname)
                    if nonempty(lname): red['last_name'] = mask_name(lname)
                if email_ok: red['email'] = mask_email(val_email)
                if address_ok: red['address'] = mask_address(addr)
                if nonempty(ip) and is_ip(ip): red['ip_address'] = mask_ip(ip)
                if nonempty(device): red['device_id'] = mask_device(device)

            rows.append({'record_id': rid, 'redacted_data_json': json.dumps(red, ensure_ascii=False), 'is_pii': str(bool(ispii))})

    with open(fout, 'w', newline='', encoding='utf-8') as w:
        ww = csv.DictWriter(w, fieldnames=['record_id','redacted_data_json','is_pii'])
        ww.writeheader()
        for r in rows: ww.writerow(r)

if __name__ == '__main__':
    main()
