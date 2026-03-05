from bloom_filter import BloomFilter
from bloom_application import SpamKeywordManager
from rbtree_core import RedBlackTree
from analytics_final import DomainAnalytics
import re
import os
import json
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv('GEMINI_API_KEY')

if API_KEY:
    try:
        gemini_client = genai.Client(api_key=API_KEY)
        print("✓ Gemini API Key loaded successfully.")
    except Exception as e:
        gemini_client = None
        print(f"✗✗✗ Error: Failed to initialize Gemini client. {e}")
else:
    gemini_client = None
    print("✗✗✗ Error: GEMINI_API_KEY not found. Please check your .env file.")

class EmailSpamFilter:     #Complete email spam filtering system combining:- Bloom Filter for keyword detection-Red-Black Tree for domain reputation management
    
    def __init__(self, expected_keywords=10000, fp_rate=0.01):  #Initialize the complete spam filter system.
        
        # --- 1. Bloom Filter (for fast pre-check) ---
        self.bloom_filter = BloomFilter(expected_keywords, fp_rate)
        self.keyword_manager = SpamKeywordManager(self.bloom_filter)
        
        # --- 2. Red-Black Tree (for domain reputation) ---
        self.domain_tree = RedBlackTree()
        self.analytics = DomainAnalytics(self.domain_tree)

        # --- 3. Gemini Model (for smart analysis) ---
        self.gemini_client = gemini_client
        self.model_name = 'gemini-2.5-flash'
        
        print("=" * 70)
        print("HYBRID SPAM FILTER SYSTEM INITIALIZED")
        print("=" * 70)
        print(f"✓ Bloom Filter ready (size: {self.bloom_filter.size} bits)")
        print(f"✓ Red-Black Tree ready")
        if self.gemini_client:
            print("✓ Gemini Model ready")
        else:
            print("✗ Gemini Model FAILED")
        print("=" * 70 + "\n")

    def load_spam_keywords(self, filepath="spam_keywords.txt"):
        """Loads keywords from a file, creating the file if it doesn't exist."""
        from pathlib import Path
        
        # 1. Create the file if it's missing
        if not Path(filepath).exists():
            print("Creating sample spam keyword dictionary...")
            self.keyword_manager.create_sample_dictionary(filepath)
        
        # 2. Always load the file after checking
        print(f"Loading spam keywords from {filepath}...")
        self.keyword_manager.load_from_file(filepath)
    
    def add_known_domains(self, domains_with_scores):   #Add known domains with reputation scores to the system.
        print("\nAdding known domains to reputation database...")
        for domain, score in domains_with_scores:
            self.domain_tree.insert_domain(domain, score)
        print(f"✓ Added {len(domains_with_scores)} domains\n")
    
    def extract_domain_from_email(self, email_address):    #Extract domain from email address.
        match = re.search(r'@([\w\.-]+)', email_address)
        return match.group(1) if match else None
    
    def get_gemini_analysis(self, subject, body):
        """
        Analyzes email content using the Gemini API.
        Returns a dictionary with 'spam_score' (0-100) and 'reasoning'.
        """
        if not self.gemini_client:
            return {'spam_score': -1, 'reasoning': 'Gemini client not available.'} # -1 indicates "not run"
            
        full_message = f"Subject: {subject}\n\nBody: {body}"
        
        prompt = f"""
        Analyze the following email for spam. Provide your response as a valid JSON object
        with exactly two keys:
        1. "spam_score": An integer from 0 (definitely not spam) to 100 (definitely spam).
        2. "reasoning": A brief, one-sentence explanation for your score.

        Email to analyze:
        ---
        {full_message}
        ---
        """
        
        try:
            generation_config = types.GenerateContentConfig(response_mime_type="application/json")
            response = self.gemini_client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=generation_config
            )
            result_json = json.loads(response.text)
            return {
                'spam_score': int(result_json.get('spam_score', 0)),
                'reasoning': result_json.get('reasoning', 'No reasoning provided.')
            }
        except Exception as e:
            print(f"Error during Gemini analysis: {e}")
            return {'spam_score': -1, 'reasoning': f'Analysis failed: {e}'} # -1 indicates "not run"
    
    def check_email(self, sender_email, subject, body):
        
        # --- 1. Bloom Filter Analysis (Fast Pre-check) ---
        full_message = f"{subject} {body}"
        keyword_result = self.keyword_manager.check_message(full_message)
        keyword_spam_score = keyword_result['spam_score']

        # --- 2. Gemini AI Analysis (Smart Check) ---
        # We only call the AI if the Bloom Filter isn't 100% sure it's spam.
        # This saves API calls and money!
        if keyword_spam_score < 90: # Tune this threshold
            gemini_result = self.get_gemini_analysis(subject, body)
            ai_spam_score = gemini_result['spam_score']
            ai_reasoning = gemini_result['reasoning']
        else:
            ai_spam_score = -1 # -1 means "skipped"
            ai_reasoning = "Skipped Gemini analysis, Bloom Filter score was high enough."

        # --- 3. Domain Reputation Analysis ---
        domain = self.extract_domain_from_email(sender_email)
        domain_score = 50  # Default neutral score
        domain_status = "unknown"
        
        if domain:
            domain_node = self.domain_tree.search_domain(domain)
            if domain_node:
                domain_score = domain_node.reputation_score
                if domain_score < 30: domain_status = "blacklisted"
                elif domain_score < 60: domain_status = "suspicious"
                elif domain_score < 80: domain_status = "neutral"
                else: domain_status = "trusted"
            else:
                self.domain_tree.insert_domain(domain, 40) # New domains are suspicious
                domain_status = "new (suspicious)"
        
        # --- 4. Final Combined Scoring ---
        
        # Use the AI score if we have it, otherwise use the Bloom Filter score
        if ai_spam_score != -1:
            content_score = ai_spam_score
            content_weight = 0.6 # AI is more reliable, weigh it heavily
        else:
            content_score = keyword_spam_score
            content_weight = 0.6 # Bloom filter was sure, so we trust it
            
        domain_weight = 0.4
        
        # (100 - domain_score) converts reputation (good) to risk (bad)
        combined_score = (
            content_score * content_weight +
            (100 - domain_score) * domain_weight
        )
        
        is_spam = combined_score > 55 # Tunable threshold

        result = {
            'sender_email': sender_email,
            'domain': domain,
            'is_spam': is_spam,
            'combined_spam_score': combined_score,
            'confidence': 'high' if combined_score > 75 or combined_score < 30 else 'medium',
            'keyword_analysis': {
                'spam_score': keyword_spam_score,
                'num_matches': len(keyword_result['matched_keywords']),
                'matched_keywords': keyword_result['matched_keywords']
            },
            'ai_analysis': {
                'spam_score': ai_spam_score,
                'reasoning': ai_reasoning
            },
            'domain_analysis': {
                'reputation_score': domain_score,
                'status': domain_status
            }
        }
        
        return result
    
    def print_email_result(self, result):
        """Print formatted email analysis result."""
        print("\n" + "=" * 70)
        print("EMAIL SPAM ANALYSIS RESULT")
        print("=" * 70)
        print(f"From: {result['sender_email']}")
        print(f"Domain: {result['domain']}")
        print(f"\n{'🚫 SPAM' if result['is_spam'] else '✓ LEGITIMATE'} "
              f"(Confidence: {result['confidence']})")
        print(f"Combined Spam Score: {result['combined_spam_score']:.2f}/100")
        
        print(f"\n--- 1. Keyword Pre-check (Bloom Filter) ---")
        print(f"Keyword Score: {result['keyword_analysis']['spam_score']}/100")
        print(f"Matches: {result['keyword_analysis']['num_matches']}")
        if result['keyword_analysis']['matched_keywords']:
            print(f"Keywords: {', '.join(result['keyword_analysis']['matched_keywords'][:5])}")

        print(f"\n--- 2. AI Content Analysis (Gemini) ---")
        ai_score_str = f"{result['ai_analysis']['spam_score']}/100" if result['ai_analysis']['spam_score'] != -1 else "SKIPPED"
        print(f"AI Spam Score: {ai_score_str}")
        print(f"AI Reasoning: {result['ai_analysis']['reasoning']}")
        
        print(f"\n--- 3. Domain Reputation (Red-Black Tree) ---")
        print(f"Reputation Score: {result['domain_analysis']['reputation_score']}/100")
        print(f"Status: {result['domain_analysis']['status'].upper()}")
        
        print("=" * 70 + "\n")
    
    def report_spam_email(self, sender_email, severity=3):     # Report an email as spam and update domain reputation.
        domain = self.extract_domain_from_email(sender_email)
        if domain:
            self.analytics.report_spam_domain(domain, severity)
    
    def whitelist_email(self, sender_email, boost=20):     #Whitelist an email domain.
        domain = self.extract_domain_from_email(sender_email)
        if domain:
            self.analytics.whitelist_domain(domain, boost)
    
    def generate_system_report(self):
        """Generate comprehensive system report."""
        print("\n" + "=" * 70)
        print("SPAM FILTER SYSTEM REPORT")
        print("=" * 70)
        
        # Keyword statistics
        keyword_stats = self.keyword_manager.get_statistics()
        print(f"\n--- Keyword Detection System ---")
        print(f"Total Keywords Loaded: {keyword_stats['total_keywords_loaded']}")
        print(f"Total Scans Performed: {keyword_stats['total_scans']}")
        print(f"Spam Detected: {keyword_stats['spam_detected']}")
        print(f"Ham Detected: {keyword_stats['ham_detected']}")
        
        # Bloom filter statistics
        bf_stats = self.bloom_filter.get_stats()
        print(f"\nBloom Filter Efficiency:")
        print(f"  Capacity Usage: {bf_stats['capacity_usage_percent']:.2f}%")
        print(f"  False Positive Rate: {bf_stats['actual_fp_rate']:.6f}")
        
        # Domain reputation report
        self.analytics.print_reputation_report()
    
    def run_benchmark(self):
        """Run performance benchmark on the system."""
        print("\n" + "=" * 70)
        print("RUNNING SYSTEM BENCHMARK")
        print("=" * 70)
        
        # Benchmark keyword detection
        keyword_bench = self.keyword_manager.benchmark_performance(1000)
        self.keyword_manager.print_benchmark_results(keyword_bench)

def main():
    """Main function demonstrating the complete hybrid spam filter system."""
    
    # 1. Initialize system
    print("=" * 70)
    print("INITIALIZING HYBRID SPAM FILTER...")
    print("=" * 70)
    spam_filter = EmailSpamFilter(expected_keywords=5000, fp_rate=0.01)
    
    # 2. Load Spam Keywords (for Bloom Filter)
    spam_filter.load_spam_keywords() # This loads spam_keywords.txt
    
    # 3. Load Domain Reputations (Persistence)
    print("\n--- Loading Domain Reputations ---")
    
    # Try to import saved data. This returns 'False' if the file doesn't exist.
    import_success = spam_filter.analytics.import_reputation_data("domain_reputation.json")
    
    # If import failed (first run), populate with default domains.
    if not import_success:
        print("No saved data found. Populating with default domains...")
        known_domains = [
            ("gmail.com", 95),
            ("yahoo.com", 90),
            ("outlook.com", 92),
            ("spam-domain.net", 10),
            ("phishing-site.org", 5),
            ("malware-host.ru", 8),
            ("suspicious-sender.info", 25),
            ("legitimate-bank.com", 98),
            ("trusted-service.edu", 100)
        ]
        spam_filter.add_known_domains(known_domains)

    # 4. Run Live Email Tests
    print("\n" + "=" * 70)
    print("RUNNING LIVE EMAIL TESTS")
    print("=" * 70)
    
    test_emails = [
        {
            "sender": "winner@spam-domain.net",
            "subject": "Congratulations! You won!",
            "body": "You won a lottery prize! Click here to claim your cash prize now! Act now, limited time offer!"
        },
        {
            "sender": "support@legitimate-bank.com",
            "subject": "Account Statement",
            "body": "Your monthly account statement is ready. Please log in to view your transactions."
        },
        {
            "sender": "new-scammer@unknown-domain.biz", # A brand new domain
            "subject": "URGENT: Verify Your Crypto Investment",
            "body": "Click here to verify your account or lose your funds. Make money fast."
        },
        {
            "sender": "friend@gmail.com", # A trusted domain
            "subject": "Lunch tomorrow?",
            "body": "Hey, are you free for lunch tomorrow? Let me know what time works for you."
        }
    ]
    
    for i, email in enumerate(test_emails, 1):
        print(f"\n--- Testing Email {i} ---")
        result = spam_filter.check_email(
            email['sender'],
            email['subject'],
            email['body']
        )
        spam_filter.print_email_result(result)
    
    # 5. Update Reputations (Demo)
    print("\n" + "=" * 70)
    print("UPDATING DOMAIN REPUTATIONS (DEMO)")
    print("=" * 70)
    
    spam_filter.report_spam_email("winner@spam-domain.net", severity=5)
    spam_filter.whitelist_email("support@legitimate-bank.com", boost=2)
    
    # 6. Generate Final System Reports
    spam_filter.generate_system_report()
    spam_filter.analytics.visualize_tree_structure()
    
    # 7. Save All Changes to Disk
    print("\n" + "=" * 70)
    print("SAVING SYSTEM STATE (Reputations & Blacklist)")
    print("=" * 70)
    spam_filter.analytics.export_blacklist("spam_blacklist.txt", threshold=30)
    spam_filter.analytics.export_reputation_data("domain_reputation.json")
    
    print("\nSPAM FILTER SYSTEM DEMO COMPLETE.")


if __name__ == "__main__":
    main()
