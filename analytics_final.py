import json
import os
from datetime import datetime
from collections import defaultdict

class DomainAnalytics:    #Analytics and reporting layer for domain reputation management.Provides administrative interface and statistical analysis.
    def __init__(self, red_black_tree):   #Initialize analytics with a Red-Black Tree instance.
        self.rbt = red_black_tree
        self.action_history = []
        self.domain_categories = defaultdict(list)
    
    def report_spam_domain(self, domain, severity=1):# Report a domain as spam and update reputation downward.
        # Check if domain exists
        node = self.rbt.search_domain(domain)
        
        if not node:
            # Create new domain with low reputation if it doesn't exist
            self.rbt.insert_domain(domain, reputation_score=40)
            node = self.rbt.search_domain(domain)
        
        # Decrease reputation based on severity
        reputation_decrease = severity * 10
        old_score = node.reputation_score
        new_score = max(0, node.reputation_score - reputation_decrease)
        self.rbt.update_reputation_score(domain, new_score)
        
        # Increment spam report counter
        self.rbt.increment_spam_reports(domain, severity)
        
        # Log action
        self._log_action("spam_report", domain, {
            "severity": severity,
            "old_score": old_score,
            "new_score": new_score
        })
        
        print(f"Reported {domain} as spam (severity {severity})")
        print(f"  Reputation: {old_score} → {new_score}")
        
        return new_score
    
    def whitelist_domain(self, domain, boost=20):#Whitelist a domain and update reputation upward.
        # Check if domain exists
        node = self.rbt.search_domain(domain)
        
        if not node:
            # Create new domain with high reputation
            self.rbt.insert_domain(domain, reputation_score=80)
            node = self.rbt.search_domain(domain)
        
        # Increase reputation
        old_score = node.reputation_score
        new_score = min(100, node.reputation_score + boost)
        self.rbt.update_reputation_score(domain, new_score)
        
        # Increment legitimate report counter
        self.rbt.increment_legitimate_reports(domain, boost // 3)
        
        # Log action
        self._log_action("whitelist", domain, {
            "boost": boost,
            "old_score": old_score,
            "new_score": new_score
        })
        
        print(f"Whitelisted {domain}")
        print(f"  Reputation: {old_score} → {new_score}")
        
        return new_score

    def import_reputation_data(self, filename="reputation_data.json"):
        """
        Load all reputation data from a JSON file into the Red-Black Tree.
        Returns True on success, False if file doesn't exist.
        """
        try:
            # Check if file exists. If not, it's the first run.
            if not os.path.exists(filename):
                print(f"Data file not found: {filename}. Starting with empty database.")
                return False
                
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            count = 0
            for item in data.get('domains', []):
                domain = item.get('domain')
                score = item.get('reputation_score', 50)
                spam_reports = item.get('spam_reports', 0)
                legit_reports = item.get('legitimate_reports', 0)
                
                if domain:
                    # Insert domain into the tree with its saved score
                    node = self.rbt.insert_domain(domain, score)
                    # Manually update the report counts
                    node.spam_reports = spam_reports
                    node.legitimate_reports = legit_reports
                    count += 1
            
            print(f"Successfully imported {count} domains from {filename}")
            return True
            
        except Exception as e:
            print(f"Error importing data: {e}")
            return False # Treat as a failure

    def get_top_spammers(self, limit=10):# Get domains with worst reputation scores using traversal.
        all_domains = []
        self._collect_domain_info(self.rbt.root, all_domains)
        
        # Sort by reputation score (ascending) and spam reports (descending)
        all_domains.sort(key=lambda x: (x[1], -x[2]))
        
        return all_domains[:limit]
    
    def get_top_trusted(self, limit=10):#Get domains with best reputation scores.
        all_domains = []
        self._collect_domain_info(self.rbt.root, all_domains)
        
        # Sort by reputation score (descending)
        all_domains.sort(key=lambda x: (-x[1], -x[3]))
        
        return all_domains[:limit]
    
    def _collect_domain_info(self, node, result):#  Helper to collect domain information via in-order traversal.
        if node == self.rbt.NIL:
            return
        
        self._collect_domain_info(node.left, result)
        result.append((
            node.domain,
            node.reputation_score,
            node.spam_reports,
            node.legitimate_reports
        ))
        self._collect_domain_info(node.right, result)
    
    def generate_reputation_report(self):# Generate comprehensive reputation statistics report.
        all_domains = []
        self._collect_domain_info(self.rbt.root, all_domains)
        
        if not all_domains:
            return {
                "total_domains": 0,
                "message": "No domains in database"
            }
        
        # Calculate statistics
        scores = [d[1] for d in all_domains]
        spam_reports = [d[2] for d in all_domains]
        legit_reports = [d[3] for d in all_domains]
        
        # Categorize domains
        blacklisted = [d for d in all_domains if d[1] < 30]
        suspicious = [d for d in all_domains if 30 <= d[1] < 60]
        neutral = [d for d in all_domains if 60 <= d[1] < 80]
        trusted = [d for d in all_domains if d[1] >= 80]
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_domains": len(all_domains),
            "reputation_stats": {
                "average_score": sum(scores) / len(scores) if scores else 0,
                "median_score": sorted(scores)[len(scores) // 2] if scores else 50,
                "min_score": min(scores) if scores else 0,
                "max_score": max(scores) if scores else 0
            },
            "categories": {
                "blacklisted": {
                    "count": len(blacklisted),
                    "percentage": (len(blacklisted) / len(all_domains)) * 100 if all_domains else 0,
                    "threshold": "< 30"
                },
                "suspicious": {
                    "count": len(suspicious),
                    "percentage": (len(suspicious) / len(all_domains)) * 100 if all_domains else 0,
                    "threshold": "30-59"
                },
                "neutral": {
                    "count": len(neutral),
                    "percentage": (len(neutral) / len(all_domains)) * 100 if all_domains else 0,
                    "threshold": "60-79"
                },
                "trusted": {
                    "count": len(trusted),
                    "percentage": (len(trusted) / len(all_domains)) * 100 if all_domains else 0,
                    "threshold": "≥ 80"
                }
            },
            "report_stats": {
                "total_spam_reports": sum(spam_reports),
                "total_legitimate_reports": sum(legit_reports),
                "avg_spam_reports_per_domain": sum(spam_reports) / len(spam_reports) if spam_reports else 0,
                "avg_legit_reports_per_domain": sum(legit_reports) / len(legit_reports) if legit_reports else 0
            },
            "tree_stats": {
                "height": self.rbt.get_height(),
                "is_balanced": self.rbt.verify_rb_properties()[0]
            },
            "action_history_count": len(self.action_history)
        }
        
        return report
    
    def print_reputation_report(self, report=None):#Print formatted reputation report to console.
        if report is None:
            report = self.generate_reputation_report()
        
        print("\n" + "=" * 60)
        print("DOMAIN REPUTATION REPORT")
        print("=" * 60)
        print(f"Generated: {report.get('timestamp', 'N/A')}")
        print(f"Total Domains: {report['total_domains']}")
        
        if report['total_domains'] == 0:
            print("\nNo domains in database.")
            print("=" * 60 + "\n")
            return
        
        print("\n--- REPUTATION STATISTICS ---")
        stats = report['reputation_stats']
        print(f"Average Score: {stats['average_score']:.2f}")
        print(f"Median Score:  {stats['median_score']:.2f}")
        print(f"Range:         {stats['min_score']} - {stats['max_score']}")
        
        print("\n--- DOMAIN CATEGORIES ---")
        for category, data in report['categories'].items():
            print(f"{category.upper():15s}: {data['count']:4d} domains "
                  f"({data['percentage']:5.2f}%) [{data['threshold']}]")
        
        print("\n--- REPORT STATISTICS ---")
        rstats = report['report_stats']
        print(f"Total Spam Reports:       {rstats['total_spam_reports']}")
        print(f"Total Legitimate Reports: {rstats['total_legitimate_reports']}")
        print(f"Avg Spam Reports/Domain:  {rstats['avg_spam_reports_per_domain']:.2f}")
        print(f"Avg Legit Reports/Domain: {rstats['avg_legit_reports_per_domain']:.2f}")
        
        print("\n--- TREE HEALTH ---")
        tstats = report['tree_stats']
        print(f"Tree Height:   {tstats['height']}")
        print(f"Is Balanced:   {'✓ Yes' if tstats['is_balanced'] else '✗ No'}")
        print(f"Total Actions: {report['action_history_count']}")
        
        print("=" * 60 + "\n")
    
    def export_blacklist(self, filename="blacklist.txt", threshold=30):#Export blacklisted domains to a file.
        blacklisted = self.rbt.get_blacklisted_domains(threshold)
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Spam Domain Blacklist\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Threshold: Reputation < {threshold}\n")
                f.write(f"# Total domains: {len(blacklisted)}\n\n")
                
                for domain, score in blacklisted:
                    f.write(f"{domain}\t{score}\n")
            
            print(f"Exported {len(blacklisted)} blacklisted domains to {filename}")
            return len(blacklisted)
            
        except Exception as e:
            print(f"Error exporting blacklist: {e}")
            return 0
    
    def export_reputation_data(self, filename="reputation_data.json"):#Export all reputation data to JSON file.
        all_domains = []
        self._collect_domain_info(self.rbt.root, all_domains)
        
        data = {
            "export_timestamp": datetime.now().isoformat(),
            "total_domains": len(all_domains),
            "domains": [
                {
                    "domain": d[0],
                    "reputation_score": d[1],
                    "spam_reports": d[2],
                    "legitimate_reports": d[3]
                }
                for d in all_domains
            ]
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            print(f"Exported reputation data to {filename}")
            return True
            
        except Exception as e:
            print(f"Error exporting data: {e}")
            return False
    
    def visualize_tree_structure(self):
        """
        Generate ASCII visualization of the tree structure.
        """
        print("\n" + "=" * 60)
        print("RED-BLACK TREE STRUCTURE")
        print("=" * 60)
        print("Legend: [R] = Red, [B] = Black")
        print()
        
        if self.rbt.root == self.rbt.NIL:
            print("(Empty tree)")
        else:
            self.rbt.print_tree()
        
        print("=" * 60 + "\n")
    
    def _log_action(self, action_type, domain, details):
        """Log an action to history."""
        self.action_history.append({
            "timestamp": datetime.now().isoformat(),
            "action": action_type,
            "domain": domain,
            "details": details
        })
    
    def get_action_history(self, limit=20):#Get recent action history.
        return self.action_history[-limit:]
    
    def print_action_history(self, limit=10):
        """Print recent action history."""
        print("\n--- RECENT ACTIONS ---")
        history = self.get_action_history(limit)
        
        if not history:
            print("No actions recorded.")
            return
        
        for action in history:
            print(f"[{action['timestamp']}] {action['action']}: {action['domain']}")
            for key, value in action['details'].items():
                print(f"    {key}: {value}")


# Demo usage
if __name__ == "__main__":
    from rbtree_core import RedBlackTree
    
    # Initialize
    rbt = RedBlackTree()
    analytics = DomainAnalytics(rbt)
    
    print("--- Testing Persistence ---")
    # 1. Try to load data (will fail on first run)
    analytics.import_reputation_data("demo_reputation.json")
    
    # 2. Add initial domains if tree is empty
    if rbt.size == 0:
        print("Setting up test domains...")
        test_domains = [
            ("example.com", 75),
            ("spam-central.net", 15),
            ("phishing-scam.org", 5),
            ("trusted-bank.com", 95),
            ("newsletter-service.io", 60),
            ("malware-host.ru", 10),
            ("legitimate-shop.com", 85)
        ]
        for domain, score in test_domains:
            rbt.insert_domain(domain, score)
    
    print("\n--- Reporting Spam Domains ---")
    analytics.report_spam_domain("spam-central.net", severity=3)
    analytics.report_spam_domain("phishing-scam.org", severity=5)
    
    print("\n--- Whitelisting Trusted Domains ---")
    analytics.whitelist_domain("trusted-bank.com", boost=5)
    analytics.whitelist_domain("legitimate-shop.com", boost=15)
    
    print("\n--- TOP 5 SPAM DOMAINS ---")
    top_spammers = analytics.get_top_spammers(5)
    for i, (domain, score, spam_reports, _) in enumerate(top_spammers, 1):
        print(f"{i}. {domain:30s} Score: {score:3d}  Reports: {spam_reports}")
    
    print("\n--- TOP 5 TRUSTED DOMAINS ---")
    top_trusted = analytics.get_top_trusted(5)
    for i, (domain, score, _, legit_reports) in enumerate(top_trusted, 1):
        print(f"{i}. {domain:30s} Score: {score:3d}  Reports: {legit_reports}")
    
    analytics.print_reputation_report()
    analytics.export_blacklist("spam_blacklist.txt")
    
    # 3. Export the data
    print("\n--- Saving Data for Persistence Demo ---")
    analytics.export_reputation_data("demo_reputation.json")
    
    analytics.visualize_tree_structure()
    analytics.print_action_history()
    
    print("\nRun this file again to see persistence in action.")
