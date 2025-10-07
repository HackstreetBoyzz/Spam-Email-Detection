

import json
from datetime import datetime
from collections import defaultdict


class DomainAnalytics:
    
    
    def __init__(self, red_black_tree):
        
        self.rbt = red_black_tree
        self.action_history = []
        self.domain_categories = defaultdict(list)
    
    def report_spam_domain(self, domain, severity=1):
       
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
    
    def whitelist_domain(self, domain, boost=20):
        
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
    
    def get_top_spammers(self, limit=10):
        
        all_domains = []
        self._collect_domain_info(self.rbt.root, all_domains)
        
        # Sort by reputation score (ascending) and spam reports (descending)
        all_domains.sort(key=lambda x: (x[1], -x[2]))
        
        return all_domains[:limit]
    
    def get_top_trusted(self, limit=10):
        
        all_domains = []
        self._collect_domain_info(self.rbt.root, all_domains)
        
        # Sort by reputation score (descending)
        all_domains.sort(key=lambda x: (-x[1], -x[3]))
        
        return all_domains[:limit]
    
    def _collect_domain_info(self, node, result):
        
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
    
    def generate_reputation_report(self):
        
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
                "average_score": sum(scores) / len(scores),
                "median_score": sorted(scores)[len(scores) // 2],
                "min_score": min(scores),
                "max_score": max(scores)
            },
            "categories": {
                "blacklisted": {
                    "count": len(blacklisted),
                    "percentage": (len(blacklisted) / len(all_domains)) * 100,
                    "threshold": "< 30"
                },
                "suspicious": {
                    "count": len(suspicious),
                    "percentage": (len(suspicious) / len(all_domains)) * 100,
                    "threshold": "30-59"
                },
                "neutral": {
                    "count": len(neutral),
                    "percentage": (len(neutral) / len(all_domains)) * 100,
                    "threshold": "60-79"
                },
                "trusted": {
                    "count": len(trusted),
                    "percentage": (len(trusted) / len(all_domains)) * 100,
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
    
    def print_reputation_report(self, report=None):
        
        if report is None:
            report = self.generate_reputation_report()
        
        print("\n" + "=" * 60)
        print("DOMAIN REPUTATION REPORT")
        print("=" * 60)
        print(f"Generated: {report.get('timestamp', 'N/A')}")
        print(f"Total Domains: {report['total_domains']}")
        
        if report['total_domains'] == 0:
            print("\nNo domains in database.")
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
    
    def export_blacklist(self, filename="blacklist.txt", threshold=30):
       
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
    
    def export_reputation_data(self, filename="reputation_data.json"):
        
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
        
        self.action_history.append({
            "timestamp": datetime.now().isoformat(),
            "action": action_type,
            "domain": domain,
            "details": details
        })
    
    def get_action_history(self, limit=20):
       
        return self.action_history[-limit:]
    
    def print_action_history(self, limit=10):
        
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
    # NOTE: You need member3_rbtree_core.py in the same directory
    from member3_rbtree_core import RedBlackTree
    
    # Initialize
    rbt = RedBlackTree()
    analytics = DomainAnalytics(rbt)
    
    # Add initial domains
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
    
    # Report spam domains
    print("\n--- Reporting Spam Domains ---")
    analytics.report_spam_domain("spam-central.net", severity=3)
    analytics.report_spam_domain("phishing-scam.org", severity=5)
    
    # Whitelist domains
    print("\n--- Whitelisting Trusted Domains ---")
    analytics.whitelist_domain("trusted-bank.com", boost=5)
    analytics.whitelist_domain("legitimate-shop.com", boost=15)
    
    # Get top spammers
    print("\n--- TOP 5 SPAM DOMAINS ---")
    top_spammers = analytics.get_top_spammers(5)
    for i, (domain, score, spam_reports, _) in enumerate(top_spammers, 1):
        print(f"{i}. {domain:30s} Score: {score:3d}  Reports: {spam_reports}")
    
    # Get top trusted
    print("\n--- TOP 5 TRUSTED DOMAINS ---")
    top_trusted = analytics.get_top_trusted(5)
    for i, (domain, score, _, legit_reports) in enumerate(top_trusted, 1):
        print(f"{i}. {domain:30s} Score: {score:3d}  Reports: {legit_reports}")
    
    # Generate full report
    analytics.print_reputation_report()
    
    # Export blacklist
    analytics.export_blacklist("spam_blacklist.txt", threshold=30)
    
    # Visualize tree
    analytics.visualize_tree_structure()
    
    # Print action history
    analytics.print_action_history()