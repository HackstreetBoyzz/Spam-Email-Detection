from bloom_filter import BloomFilter
from bloom_application import SpamKeywordManager
from rbtree_core import RedBlackTree
from analytics_final import DomainAnalytics
import re

class EmailSpamFilter:     #Complete email spam filtering system combining:- Bloom Filter for keyword detection-Red-Black Tree for domain reputation management
    
    def __init__(self, expected_keywords=10000, fp_rate=0.01):  #Initialize the complete spam filter system.
        # Initialize Bloom Filter components (Members 1 & 2)
        self.bloom_filter = BloomFilter(expected_keywords, fp_rate)
        self.keyword_manager = SpamKeywordManager(self.bloom_filter)
        
        # Initialize Red-Black Tree components (Members 3 & 4)
        self.domain_tree = RedBlackTree()
        self.analytics = DomainAnalytics(self.domain_tree)
        
        print("=" * 70)
        print("EMAIL SPAM FILTER SYSTEM INITIALIZED")
        print("=" * 70)
        print(f"✓ Bloom Filter ready (size: {self.bloom_filter.size} bits)")
        print(f"✓ Red-Black Tree ready")
        print(f"✓ Keyword Manager ready")
        print(f"✓ Analytics Engine ready")
        print("=" * 70 + "\n")
    
    def load_spam_keywords(self, filepath=None):    # Load spam keywords from file or create sample dictionary.
        if filepath is None:
            print("Creating sample spam keyword dictionary...")
            filepath = self.keyword_manager.create_sample_dictionary()
        
        if filepath:
            self.keyword_manager.load_from_file(filepath)
    
    def add_known_domains(self, domains_with_scores):   #Add known domains with reputation scores to the system.
        print("\nAdding known domains to reputation database...")
        for domain, score in domains_with_scores:
            self.domain_tree.insert_domain(domain, score)
        print(f"✓ Added {len(domains_with_scores)} domains\n")
    
    def extract_domain_from_email(self, email_address):    #Extract domain from email address.
        match = re.search(r'@([\w\.-]+)', email_address)
        return match.group(1) if match else None
    
    def check_email(self, sender_email, subject, body):    #Complete spam check combining keyword and domain analysis.
        # Extract domain from sender
        domain = self.extract_domain_from_email(sender_email)
        
        # Check keywords in subject and body
        full_message = f"{subject} {body}"
        keyword_result = self.keyword_manager.check_message(full_message)
        
        # Check domain reputation
        domain_score = 50  # Default neutral score
        domain_status = "unknown"
        
        if domain:
            domain_node = self.domain_tree.search_domain(domain)
            if domain_node:
                domain_score = domain_node.reputation_score
                if domain_score < 30:
                    domain_status = "blacklisted"
                elif domain_score < 60:
                    domain_status = "suspicious"
                elif domain_score < 80:
                    domain_status = "neutral"
                else:
                    domain_status = "trusted"
            else:
                # Unknown domain - add with neutral score
                self.domain_tree.insert_domain(domain, 50)
                domain_status = "new"
        
        # Calculate combined spam score
        keyword_weight = 0.6
        domain_weight = 0.4
        
        combined_score = (
            keyword_result['spam_score'] * keyword_weight +
            (100 - domain_score) * domain_weight
        )
        
        # Determine if spam
        is_spam = combined_score > 50
        
        result = {
            'sender_email': sender_email,
            'domain': domain,
            'is_spam': is_spam,
            'combined_spam_score': combined_score,
            'confidence': 'high' if combined_score > 70 or combined_score < 30 else 'medium',
            'keyword_analysis': {
                'spam_score': keyword_result['spam_score'],
                'matched_keywords': keyword_result['matched_keywords'],
                'num_matches': len(keyword_result['matched_keywords'])
            },
            'domain_analysis': {
                'reputation_score': domain_score,
                'status': domain_status
            },
            'scan_time_ms': keyword_result['scan_time_ms']
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
        
        print(f"\n--- Keyword Analysis ---")
        print(f"Keyword Spam Score: {result['keyword_analysis']['spam_score']}/100")
        print(f"Matched Keywords: {result['keyword_analysis']['num_matches']}")
        if result['keyword_analysis']['matched_keywords']:
            print(f"Keywords: {', '.join(result['keyword_analysis']['matched_keywords'][:5])}")
        
        print(f"\n--- Domain Analysis ---")
        print(f"Reputation Score: {result['domain_analysis']['reputation_score']}/100")
        print(f"Status: {result['domain_analysis']['status'].upper()}")
        
        print(f"\nScan Time: {result['scan_time_ms']:.4f} ms")
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
    """Main function demonstrating the complete spam filter system."""
    
    # Initialize system
    spam_filter = EmailSpamFilter(expected_keywords=5000, fp_rate=0.01)
    
    # Load spam keywords
    spam_filter.load_spam_keywords()
    
    # Add known domains with reputation scores
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
    
    # Test emails
    print("\n" + "=" * 70)
    print("TESTING EMAIL SPAM DETECTION")
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
            "sender": "pharmacy@suspicious-sender.info",
            "subject": "Buy Viagra Online",
            "body": "Cheap viagra and cialis available. Guaranteed results. Order prescription medication online now!"
        },
        {
            "sender": "friend@gmail.com",
            "subject": "Lunch tomorrow?",
            "body": "Hey, are you free for lunch tomorrow? Let me know what time works for you."
        }
    ]
    
    # Check each email
    for i, email in enumerate(test_emails, 1):
        print(f"\n--- Testing Email {i} ---")
        result = spam_filter.check_email(
            email['sender'],
            email['subject'],
            email['body']
        )
        spam_filter.print_email_result(result)
    
    # Report spam and whitelist examples
    print("\n" + "=" * 70)
    print("UPDATING DOMAIN REPUTATIONS")
    print("=" * 70)
    
    spam_filter.report_spam_email("winner@spam-domain.net", severity=5)
    spam_filter.whitelist_email("support@legitimate-bank.com", boost=2)
    
    # Show top spammers and trusted domains
    print("\n--- TOP 5 SPAM DOMAINS ---")
    top_spammers = spam_filter.analytics.get_top_spammers(5)
    for i, (domain, score, spam_reports, _) in enumerate(top_spammers, 1):
        print(f"{i}. {domain:30s} Score: {score:3d}  Reports: {spam_reports}")
    
    print("\n--- TOP 5 TRUSTED DOMAINS ---")
    top_trusted = spam_filter.analytics.get_top_trusted(5)
    for i, (domain, score, _, legit_reports) in enumerate(top_trusted, 1):
        print(f"{i}. {domain:30s} Score: {score:3d}  Reports: {legit_reports}")
    
    # Generate complete system report
    spam_filter.generate_system_report()
    
    # Export data
    print("\n" + "=" * 70)
    print("EXPORTING DATA")
    print("=" * 70)
    spam_filter.analytics.export_blacklist("spam_blacklist.txt", threshold=30)
    spam_filter.analytics.export_reputation_data("domain_reputation.json")
    
    # Visualize tree structure
    spam_filter.analytics.visualize_tree_structure()
    
    # Run benchmark
    spam_filter.run_benchmark()
    
    print("\n" + "=" * 70)
    print("SPAM FILTER SYSTEM DEMO COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()