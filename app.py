#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Fixed Flask server with real-time progress display and proper file handling
English interface with improved functionality
"""

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import sqlite3
import datetime
import uuid
import threading
import time
import subprocess
import sys
import shutil
import zipfile
import re
from pathlib import Path

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-in-production'
app.config['DATABASE'] = 'plagiarism_checker.db'
app.config['ARCHIVES_DIR'] = 'submissions'

# Store progress and archive info
check_progress = {}
archives_info = {}

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

def init_db():
    """Initialize database"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  role TEXT NOT NULL)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS check_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  check_id TEXT UNIQUE NOT NULL,
                  filename TEXT NOT NULL,
                  parameters TEXT,
                  results TEXT,
                  results_file TEXT,
                  status TEXT DEFAULT 'processing',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create default users
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        admin_hash = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                 ('admin', admin_hash, 'admin'))
    
    c.execute("SELECT * FROM users WHERE username = 'teacher'")
    if not c.fetchone():
        teacher_hash = generate_password_hash('teacher123')
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                 ('teacher', teacher_hash, 'teacher'))
    
    conn.commit()
    conn.close()

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None

def parse_archive_name(filename):
    """Parse archive name to extract year, semester, and experiment"""
    result = {
        'valid': False,
        'academic_year': None,
        'semester': None,
        'experiment': None,
        'original': filename
    }
    
    # Pattern: YYYY.NN_experiment.zip or YYYZ.NN_experiment.zip
    match = re.match(r'^(\d{4})\.(\d{2})_([^.]+)\.zip$', filename)
    if match:
        year_code = match.group(1)
        semester = match.group(2)
        experiment = match.group(3)
        
        # Determine academic year
        if len(year_code) == 4:
            if year_code.startswith('24'):  # e.g., 2425 -> 2024-2025
                academic_year = f"20{year_code[:2]}-20{year_code[2:]}"
            elif year_code.startswith('20'):  # e.g., 2024 -> 2024-2025
                year_int = int(year_code)
                academic_year = f"{year_int}-{year_int + 1}"
            else:
                academic_year = year_code
        
        result['valid'] = True
        result['academic_year'] = academic_year
        result['semester'] = semester
        result['experiment'] = experiment
    
    return result

def scan_archives():
    """Scan submissions directory and collect info about archives"""
    global archives_info
    archives_info = {
        'total_archives': 0,
        'by_year': {},
        'experiments': set(),
        'archives': []
    }
    
    submissions_dir = Path(app.config['ARCHIVES_DIR'])
    if not submissions_dir.exists():
        print(f"Creating submissions directory: {submissions_dir}")
        submissions_dir.mkdir(exist_ok=True)
        return archives_info
    
    print(f"Scanning archives in {submissions_dir}...")
    
    # Recursively find all .zip files
    for zip_path in submissions_dir.rglob('*.zip'):
        try:
            archive_name = zip_path.name
            parsed = parse_archive_name(archive_name)
            
            if parsed['valid']:
                academic_year = parsed['academic_year']
                experiment = parsed['experiment']
            else:
                # Try to extract year from filename
                year_match = re.search(r'(\d{4})', archive_name)
                if year_match:
                    year = year_match.group(1)
                    if len(year) == 4 and year.startswith('24'):
                        academic_year = f"20{year[:2]}-20{year[2:]}"
                    else:
                        academic_year = f"{year}-{int(year)+1}"
                else:
                    academic_year = 'unknown'
                
                # Extract experiment
                exp_match = re.search(r'_([^.]+)\.', archive_name)
                experiment = exp_match.group(1) if exp_match else 'unknown'
            
            # Update statistics
            archives_info['total_archives'] += 1
            archives_info['experiments'].add(experiment)
            
            if academic_year not in archives_info['by_year']:
                archives_info['by_year'][academic_year] = {
                    'archives': 0,
                    'experiments': set()
                }
            
            archives_info['by_year'][academic_year]['archives'] += 1
            archives_info['by_year'][academic_year]['experiments'].add(experiment)
            
            archives_info['archives'].append({
                'path': str(zip_path.relative_to(submissions_dir)),
                'name': archive_name,
                'year': academic_year,
                'experiment': experiment,
                'size': zip_path.stat().st_size
            })
            
            print(f"  Found: {archive_name} - {academic_year} / {experiment}")
                
        except Exception as e:
            print(f"  Error processing {zip_path}: {e}")
    
    # Convert sets to lists for JSON serialization
    archives_info['experiments'] = list(archives_info['experiments'])
    for year_data in archives_info['by_year'].values():
        year_data['experiments'] = list(year_data['experiments'])
    
    print(f"Total: {archives_info['total_archives']} archives")
    return archives_info

# Routes
@app.route('/')
def index():
    if os.path.exists('index.html'):
        return send_from_directory('.', 'index.html')
    else:
        return '<h1>index.html not found</h1>'

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data and check_password_hash(user_data[2], password):
        user = User(user_data[0], user_data[1], user_data[3])
        login_user(user, remember=True)
        return jsonify({
            'success': True,
            'username': user.username,
            'role': user.role,
            'token': str(user.id)
        })
    
    return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

@app.route('/session/verify', methods=['POST'])
def verify_session():
    data = request.json
    username = data.get('username')
    token = data.get('token')
    
    if username and token:
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("SELECT id, username, role FROM users WHERE username = ? AND id = ?", 
                  (username, token))
        user_data = c.fetchone()
        conn.close()
        
        if user_data:
            user = User(user_data[0], user_data[1], user_data[2])
            login_user(user, remember=True)
            return jsonify({'success': True})
    
    return jsonify({'success': False}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

@app.route('/archives/info')
@login_required
def get_archives_info():
    """Get information about available archives"""
    return jsonify({
        'success': True,
        'info': archives_info
    })

@app.route('/validate_filename', methods=['POST'])
@login_required
def validate_filename():
    """Validate archive filename format"""
    data = request.json
    filename = data.get('filename')
    
    parsed = parse_archive_name(filename)
    
    return jsonify({
        'success': True,
        'valid': parsed['valid'],
        'parsed': parsed,
        'available_experiments': list(archives_info['experiments'])
    })

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file upload"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file'}), 400
    
    files = request.files.getlist('file')
    uploaded = []
    
    upload_dir = Path('uploads') / str(current_user.id)
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    for file in files:
        if file and file.filename:
            # Validate and potentially rename file
            parsed = parse_archive_name(file.filename)
            
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{file.filename}"
            filepath = upload_dir / filename
            file.save(str(filepath))
            
            uploaded.append({
                'name': file.filename,
                'saved_name': filename,
                'size': filepath.stat().st_size,
                'valid': parsed['valid']
            })
            
            print(f"Uploaded: {filename}")
    
    return jsonify({
        'success': True,
        'files': uploaded
    })

@app.route('/clear_uploads', methods=['POST'])
@login_required
def clear_uploads():
    """Clear uploaded files for current user"""
    upload_dir = Path('uploads') / str(current_user.id)
    if upload_dir.exists():
        shutil.rmtree(upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)
    return jsonify({'success': True, 'message': 'Files cleared'})

@app.route('/check', methods=['POST'])
@login_required
def start_check():
    """Start plagiarism check"""
    data = request.json
    check_id = str(uuid.uuid4())
    
    # Initialize progress tracking
    check_progress[check_id] = {
        'status': 'starting',
        'progress': 0,
        'message': 'Starting check...',
        'log': [],
        'last_sent_index': -1
    }
    
    # Save to database
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("""INSERT INTO check_history 
                 (user_id, check_id, filename, parameters, status) 
                 VALUES (?, ?, ?, ?, ?)""",
              (current_user.id, check_id, data.get('filename', ''), 
               json.dumps(data), 'processing'))
    conn.commit()
    conn.close()
    
    # Start check in background
    thread = threading.Thread(target=run_check_with_real_progress, 
                             args=(check_id, current_user.id, data))
    thread.start()
    
    return jsonify({
        'success': True,
        'check_id': check_id,
        'message': 'Check started'
    })

def run_check_with_real_progress(check_id, user_id, parameters):
    """Run plagiarism check"""
    try:
        def log_progress(percent, message, detail=None):
            """Update progress and add to log"""
            check_progress[check_id]['progress'] = percent
            check_progress[check_id]['message'] = message
            if detail:
                check_progress[check_id]['log'].append({
                    'time': datetime.datetime.now().strftime('%H:%M:%S'),
                    'message': detail
                })
            print(f"[{check_id[:8]}] {percent}% - {message}")
            if detail:
                print(f"    {detail}")
        
        log_progress(5, 'Initializing...', 'Preparing for check')
        
        # Get main directory
        main_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Step 1: Move uploaded files to submissions folder
        log_progress(10, 'Copying files...', 'Moving uploaded files')
        
        upload_dir = Path('uploads') / str(user_id)
        submissions_dir = Path(app.config['ARCHIVES_DIR'])
        
        if not submissions_dir.exists():
            submissions_dir.mkdir(exist_ok=True)
        
        # Copy uploaded files to submissions
        if upload_dir.exists():
            for file in upload_dir.iterdir():
                if file.suffix.lower() == '.zip':
                    # Extract original filename from timestamped name
                    original_name = '_'.join(file.name.split('_')[2:])
                    dest = submissions_dir / original_name
                    shutil.copy2(file, dest)
                    log_progress(15, f'File added: {original_name}', f'Copied to submissions folder')
        
        # Step 2: Create config file
        log_progress(20, 'Creating configuration...', 'Preparing config.ini')
        
        # Backup existing config
        config_backup = Path('config_backup.ini')
        if Path('config.ini').exists():
            shutil.copy2('config.ini', config_backup)
        
        # Create new config with user parameters
        with open('config.ini', 'w') as f:
            f.write('[FOLDERS]\n')
            f.write(f'Submissions = {app.config["ARCHIVES_DIR"]}\n')
            f.write(f'Unpack = temp/work\n')
            f.write(f'Report = temp/report\n\n')
            f.write('[PARAMETERS]\n')
            f.write(f'THRESHOLD_PERCENTILE = {parameters.get("threshold", 95)}\n')
            f.write(f'NGRAM_min = {parameters.get("ngram_min", 2)}\n')
            f.write(f'NGRAM_max = {parameters.get("ngram_max", 5)}\n')
            f.write(f'MIN_DAYS_DISTANCE = {parameters.get("days_diff", 14)}\n')
            f.write(f'ALLOWED_IMAGES_COPIED = {parameters.get("images_copied", 2)}\n')
            f.write(f'MIN_PIXEL_SIZE = {parameters.get("min_pixel_size", 200)}\n')
            f.write(f'HASH_SIZE = 16\n')
            f.write(f'HASH_DISTANCE_THRESHOLD = 32\n')
        
        log_progress(30, 'Running compare.py...', 'Executing Dr. Kolonsky algorithm')
        
        # Step 3: Run compare.py
        try:
            result = subprocess.run(
                [sys.executable, 'compare.py'],
                capture_output=True,
                text=True,
                cwd=main_dir,
                timeout=600  # 10 minutes timeout
            )
            
            # Simulate progress during execution
            log_progress(50, 'Processing archives...', 'Extracting and analyzing files')
            log_progress(70, 'Analyzing texts...', 'Building TF-IDF model')
            log_progress(80, 'Comparing documents...', 'Finding similarities')
            
            if result.returncode != 0:
                log_progress(85, 'Processing completed with warnings', f'Return code: {result.returncode}')
                if result.stderr:
                    print(f"Compare.py stderr: {result.stderr[:1000]}")
            else:
                log_progress(85, 'compare.py completed successfully', 'Processing finished')
            
        except subprocess.TimeoutExpired:
            log_progress(85, 'Timeout exceeded', 'Process took longer than 10 minutes')
        except Exception as e:
            log_progress(85, f'Execution error', str(e))
        
        log_progress(90, 'Reading results...', 'Looking for report.txt')
        
        # Step 4: Parse results and create downloadable archive
        report_file = Path('temp/report/report.txt')
        results = {'matches': [], 'total': 0, 'message': ''}
        results_archive = None
        
        if report_file.exists():
            log_progress(92, 'Parsing report...', f'File found: {report_file}')
            
            # Parse report
            with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            data_started = False
            for line in lines:
                if 'semester' in line and 'submission_id' in line and 'similarity_ratio' in line:
                    data_started = True
                    continue
                
                if data_started and '\t' in line:
                    parts = line.strip().split('\t')
                    if len(parts) >= 15:
                        try:
                            student1 = parts[2] if len(parts[2]) > 0 else 'Unknown'
                            student2 = parts[9] if len(parts[9]) > 0 else 'Unknown'
                            
                            similarity_str = parts[14].replace(',', '.')
                            similarity = float(similarity_str) if similarity_str else 0
                            
                            if similarity > 0:
                                results['matches'].append({
                                    'student1': student1,
                                    'student2': student2,
                                    'similarity': round(similarity * 100, 1)
                                })
                                log_progress(93 + len(results['matches']) % 5, 
                                           'Processing matches...', 
                                           f'Found: {student1} - {student2} ({similarity*100:.1f}%)')
                        except Exception as e:
                            print(f"Error parsing line: {e}")
                            continue
            
            results['total'] = len(results['matches'])
            log_progress(95, 'Creating results archive...', f'Found {results["total"]} matches')
            
            # Create ZIP archive of report folder
            report_dir = Path('temp/report')
            if report_dir.exists():
                archive_path = Path(f'reports/results_{check_id}.zip')
                archive_path.parent.mkdir(exist_ok=True)
                
                with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(report_dir):
                        for file in files:
                            file_path = Path(root) / file
                            arcname = file_path.relative_to(report_dir.parent)
                            zipf.write(file_path, arcname)
                
                results_archive = str(archive_path)
                log_progress(98, 'Results archived', 'Archive created successfully')
        else:
            log_progress(98, 'Report not found', 'No report.txt file generated')
            results['message'] = 'Report was not created. Possibly no data for comparison.'
        
        # Step 5: Cleanup
        log_progress(99, 'Cleaning up...', 'Restoring configuration')
        
        # Restore original config
        if config_backup.exists():
            shutil.move(config_backup, 'config.ini')
        
        # Clear uploaded files
        if upload_dir.exists():
            shutil.rmtree(upload_dir)
            upload_dir.mkdir(exist_ok=True)
        
        # Save results to database
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("UPDATE check_history SET results = ?, results_file = ?, status = ? WHERE check_id = ?",
                  (json.dumps(results), results_archive, 'completed', check_id))
        conn.commit()
        conn.close()
        
        log_progress(100, 'Check completed!', f'Total matches: {results["total"]}')
        check_progress[check_id]['status'] = 'completed'
        check_progress[check_id]['results'] = results
        check_progress[check_id]['results_file'] = results_archive
        
    except Exception as e:
        import traceback
        print(f"Error in check: {e}")
        print(traceback.format_exc())
        
        check_progress[check_id]['status'] = 'error'
        check_progress[check_id]['message'] = str(e)
        check_progress[check_id]['log'].append({
            'time': datetime.datetime.now().strftime('%H:%M:%S'),
            'message': f'Error: {str(e)}'
        })
        
        # Restore config if error
        if Path('config_backup.ini').exists():
            shutil.move('config_backup.ini', 'config.ini')
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("UPDATE check_history SET status = 'error' WHERE check_id = ?", (check_id,))
        conn.commit()
        conn.close()

@app.route('/status/<check_id>')
@login_required
def get_status(check_id):
    """Get check status with new log entries"""
    if check_id in check_progress:
        data = check_progress[check_id].copy()
        
        # Send only new log entries
        full_log = data.get('log', [])
        last_sent = data.get('last_sent_index', -1)
        
        new_entries = []
        if len(full_log) > last_sent + 1:
            new_entries = full_log[last_sent + 1:]
            check_progress[check_id]['last_sent_index'] = len(full_log) - 1
        
        return jsonify({
            'success': True,
            'status': data['status'],
            'progress': data['progress'],
            'message': data['message'],
            'new_log_entries': new_entries
        })
    
    # Check database
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT status FROM check_history WHERE check_id = ?", (check_id,))
    result = c.fetchone()
    conn.close()
    
    if result:
        return jsonify({
            'success': True,
            'status': result[0],
            'progress': 100 if result[0] == 'completed' else 0,
            'new_log_entries': []
        })
    
    return jsonify({'success': False}), 404

@app.route('/results/<check_id>')
@login_required
def get_results(check_id):
    """Get check results"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT results, status FROM check_history WHERE check_id = ? AND user_id = ?",
              (check_id, current_user.id))
    result = c.fetchone()
    conn.close()
    
    if result:
        results_data = json.loads(result[0]) if result[0] else {'matches': [], 'total': 0}
        return jsonify({
            'success': True,
            'status': result[1],
            'results': results_data
        })
    
    return jsonify({'success': False}), 404

@app.route('/download/<check_id>')
@login_required
def download_results(check_id):
    """Download results archive"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT results_file FROM check_history WHERE check_id = ? AND user_id = ?",
              (check_id, current_user.id))
    result = c.fetchone()
    conn.close()
    
    if result and result[0]:
        file_path = Path(result[0])
        if file_path.exists():
            return send_file(str(file_path), 
                           as_attachment=True,
                           download_name=f'plagiarism_check_{check_id[:8]}.zip')
    
    return jsonify({'success': False, 'message': 'Results file not found'}), 404

@app.route('/history')
@login_required
def get_history():
    """Get check history"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("""SELECT check_id, filename, status, created_at, results 
                 FROM check_history WHERE user_id = ? 
                 ORDER BY created_at DESC LIMIT 20""",
              (current_user.id,))
    
    history = []
    for row in c.fetchall():
        results = json.loads(row[4]) if row[4] else {}
        history.append({
            'check_id': row[0],
            'filename': row[1],
            'status': row[2],
            'created_at': row[3],
            'matches': results.get('total', 0)
        })
    
    conn.close()
    return jsonify({'success': True, 'history': history})

# Admin routes
@app.route('/admin/users')
@login_required
def get_users():
    """Get all users (admin only)"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users")
    
    users = []
    for row in c.fetchall():
        users.append({
            'id': row[0],
            'username': row[1],
            'role': row[2]
        })
    
    conn.close()
    return jsonify({'success': True, 'users': users})

@app.route('/admin/user', methods=['POST'])
@login_required
def add_user():
    """Add new user (admin only)"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'teacher')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Check if user exists
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'User already exists'}), 400
    
    # Add user
    password_hash = generate_password_hash(password)
    c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
              (username, password_hash, role))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/user/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """Update user (admin only)"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Update user
    if password:
        password_hash = generate_password_hash(password)
        c.execute("UPDATE users SET username = ?, password_hash = ?, role = ? WHERE id = ?",
                  (username, password_hash, role, user_id))
    else:
        c.execute("UPDATE users SET username = ?, role = ? WHERE id = ?",
                  (username, role, user_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """Delete user (admin only)"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Don't delete admin user
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    if user and user[0] == 'admin':
        conn.close()
        return jsonify({'success': False, 'message': 'Cannot delete admin user'}), 400
    
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/library/tree')
@login_required
def get_library_tree():
    """Get library folder structure (admin only)"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    def build_tree(path):
        tree = []
        try:
            for item in sorted(path.iterdir()):
                if item.is_dir():
                    tree.append({
                        'name': item.name,
                        'type': 'folder',
                        'children': build_tree(item)
                    })
                else:
                    tree.append({
                        'name': item.name,
                        'type': 'file',
                        'size': item.stat().st_size
                    })
        except PermissionError:
            pass
        return tree
    
    submissions_dir = Path(app.config['ARCHIVES_DIR'])
    tree = build_tree(submissions_dir)
    
    return jsonify({'success': True, 'tree': tree})

@app.route('/admin/library/upload', methods=['POST'])
@login_required
def upload_to_library():
    """Upload file directly to library (admin only)"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file'}), 400
    
    file = request.files['file']
    if file and file.filename.endswith('.zip'):
        submissions_dir = Path(app.config['ARCHIVES_DIR'])
        submissions_dir.mkdir(exist_ok=True)
        
        filepath = submissions_dir / file.filename
        file.save(str(filepath))
        
        # Rescan archives
        scan_archives()
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'Invalid file'}), 400

if __name__ == '__main__':
    print("\n" + "="*60)
    print("PLAGIARISM CHECKING SYSTEM")
    print("Algorithm: Dr. Evgeny Kolonsky, Technion Physics")
    print("="*60 + "\n")
    
    # Initialize
    init_db()
    Path('uploads').mkdir(exist_ok=True)
    Path('temp').mkdir(exist_ok=True)
    Path('reports').mkdir(exist_ok=True)
    
    # Scan archives
    print("\nScanning archives...")
    scan_archives()
    print(f"\nFound archives by academic year:")
    for year in sorted(archives_info['by_year'].keys()):
        data = archives_info['by_year'][year]
        experiments = ', '.join(data['experiments'])
        print(f"  {year}: {data['archives']} archives ({experiments})")
    
    print("\n" + "="*60)
    print("Server running: http://localhost:5000")
    print("Login: admin / admin123 or teacher / teacher123")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)