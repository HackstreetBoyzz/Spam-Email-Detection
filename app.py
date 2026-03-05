from flask import Flask, render_template, request, jsonify
from main import EmailSpamFilter
import secrets
import atexit  # Import the atexit module

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)


# Initialize spam filter system
print("="*70)
print("INITIALIZING HYBRID SPAM FILTER (for Web App)...")
print("="*70)
spam_filter = EmailSpamFilter(expected_keywords=5000, fp_rate=0.01)

# 1. Load Spam Keywords (for Bloom Filter)
spam_filter.load_spam_keywords()

# 2. Load Domain Reputations (Persistence)
print("\n--- Loading Domain Reputations ---")
import_success = spam_filter.analytics.import_reputation_data("domain_reputation.json")

# 3. If import failed (first run), populate with default domains.
if not import_success:
    print("No saved data found. Populating with default domains...")
    known_domains = [
        ("gmail.com", 95), ("yahoo.com", 90), ("outlook.com", 92),
        ("spam-domain.net", 10), ("phishing-site.org", 5),
        ("malware-host.ru", 8), ("suspicious-sender.info", 25),
        ("legitimate-bank.com", 98), ("trusted-service.edu", 100),
        ("hotmail.com", 88), ("protonmail.com", 93),
        ("casino-spam.biz", 12), ("lottery-scam.net", 8)
    ]
    spam_filter.add_known_domains(known_domains)

print("\n✓ System ready for web requests.")
print("="*70)

# --- Function to save data on exit ---
def save_data_on_exit():
    """Saves the reputation data when the server is shut down."""
    print("\n" + "=" * 70)
    print("SERVER SHUTTING DOWN. Saving domain reputations...")
    print("=" * 70)
    spam_filter.analytics.export_reputation_data("domain_reputation.json")
    spam_filter.analytics.export_blacklist("spam_blacklist.txt", threshold=30)

# Register the save function to run when the app exits
atexit.register(save_data_on_exit)


@app.route('/')
def index():
    # No need to initialize here anymore, it's done once at the start
    return render_template('index.html')

@app.route('/check_email', methods=['POST'])
def check_email():
    data = request.json
    sender = data.get('sender', '')
    subject = data.get('subject', '')
    body = data.get('body', '')
    
    if not sender or not subject:
        return jsonify({'error': 'Sender and subject are required'}), 400
    
    result = spam_filter.check_email(sender, subject, body)
    
    # Remove the 'scan_time_ms' key if it exists, as it's not in the new hybrid result
    result.pop('scan_time_ms', None) 
    
    return jsonify({
        'success': True,
        'result': result
    })


@app.route('/report_spam', methods=['POST'])
def report_spam():
    data = request.json
    email = data.get('email', '')
    severity = data.get('severity', 3)
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    spam_filter.report_spam_email(email, severity)
    
    return jsonify({'success': True, 'message': f'Reported {email} as spam'})

@app.route('/whitelist', methods=['POST'])
def whitelist():
    data = request.json
    email = data.get('email', '')
    boost = data.get('boost', 20)
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    spam_filter.whitelist_email(email, boost)
    
    return jsonify({'success': True, 'message': f'Whitelisted {email}'})

@app.route('/statistics')
def statistics():
    keyword_stats = spam_filter.keyword_manager.get_statistics()
    bf_stats = spam_filter.bloom_filter.get_stats()
    
    # Get top domains
    top_spammers = spam_filter.analytics.get_top_spammers(5)
    top_trusted = spam_filter.analytics.get_top_trusted(5)
    
    return jsonify({
        'keyword_stats': {
            'total_keywords': keyword_stats['total_keywords_loaded'],
            'total_scans': keyword_stats['total_scans'],
            'spam_detected': keyword_stats['spam_detected'],
            'ham_detected': keyword_stats['ham_detected']
        },
        'bloom_filter': {
            'capacity_usage': round(bf_stats['capacity_usage_percent'], 2),
            'false_positive_rate': bf_stats['actual_fp_rate'],
            'size_bits': bf_stats['size_bits'],
            'num_hash_functions': bf_stats['num_hash_functions'],
            'items_added': bf_stats['items_added']
        },
        'top_spammers': [{'domain': d[0], 'score': d[1], 'reports': d[2]} for d in top_spammers],
        'top_trusted': [{'domain': d[0], 'score': d[1], 'reports': d[3]} for d in top_trusted]
    })

@app.route('/full_report')
def full_report():
    # Generate comprehensive report
    report = spam_filter.analytics.generate_reputation_report()
    
    return jsonify({
        'success': True,
        'report': report
    })

@app.route('/tree_structure')
def tree_structure():
    # Get all domains in tree order
    all_domains = []
    spam_filter.analytics._collect_domain_info(spam_filter.domain_tree.root, all_domains)
    
    return jsonify({
        'success': True,
        'domains': [{'domain': d[0], 'score': d[1], 'spam_reports': d[2], 'legit_reports': d[3]} 
                   for d in all_domains],
        'tree_height': spam_filter.domain_tree.get_height(),
        'is_balanced': spam_filter.domain_tree.verify_rb_properties()[0]
    })

@app.route('/benchmark', methods=['POST'])
def benchmark():
    data = request.json
    num_messages = data.get('num_messages', 1000)
    
    # Run benchmark
    results = spam_filter.keyword_manager.benchmark_performance(num_messages)
    
    return jsonify({
        'success': True,
        'benchmark': results
    })

if __name__ == '__main__':
    print("\n" + "="*70)
    print("EMAIL SPAM FILTER WEB INTERFACE")
    print("="*70)
    print("Starting Flask server...")
    print("Open http://127.0.0.1:5000 in your browser")
    print("="*70 + "\n")
    app.run(debug=True, port=5000)