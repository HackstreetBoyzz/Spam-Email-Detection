import time
import re
from pathlib import Path

class SpamKeywordManager:
    def __init__(self, bloom_filter):    #Application layer for spam detection using Bloom Filter.
        self.bloom_filter = bloom_filter     #Initialize the spam keyword manager.
        self.keyword_sources = []
        self.total_keywords_loaded = 0
        self.scan_history = []
    
    def load_from_file(self, filepath):   #Load spam keywords from a text file (one keyword per line).
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                keywords = [line.strip() for line in f if line.strip()]
            
            count = self.bulk_insert_keywords(keywords)
            self.keyword_sources.append(filepath)
            print(f"Loaded {count} keywords from {filepath}")
            return count
            
        except FileNotFoundError:
            print(f"Error: File not found - {filepath}")
            return 0
        except Exception as e:
            print(f"Error loading file {filepath}: {e}")
            return 0
    
    def load_from_list(self, keywords, source_name="manual"):  #Load spam keywords from a provided list.
        count = self.bulk_insert_keywords(keywords)
        self.keyword_sources.append(source_name)
        print(f"Loaded {count} keywords from {source_name}")
        return count
    
    def bulk_insert_keywords(self, keywords):   # Efficiently insert multiple keywords into bloom filter.
        count = 0
        for keyword in keywords:
            if keyword and isinstance(keyword, str):
                # Normalize keyword
                normalized = keyword.lower().strip()
                if normalized:
                    self.bloom_filter.add(normalized)
                    count += 1
        
        self.total_keywords_loaded += count
        return count
    
    def create_sample_dictionary(self, filepath="spam_keywords.txt"):   #Create a sample spam keyword dictionary file.
        sample_keywords = [
            # Financial spam
            "free money", "make money fast", "get rich quick", "guaranteed income",
            "work from home", "easy money", "cash bonus", "wire transfer",
            # Pharma spam
            "viagra", "cialis", "pharmacy", "prescription", "medication online",
            "weight loss", "diet pills", "male enhancement",
            # Prize/Lottery spam
            "you won", "claim prize", "winner", "congratulations winner",
            "lottery", "jackpot", "cash prize", "claim now",
            # Urgency/Pressure
            "act now", "limited time", "expires today", "urgent response",
            "immediate action", "don't wait", "hurry", "last chance",
            # Links/Actions
            "click here", "click below", "visit now", "download now",
            "open attachment", "verify account", "confirm identity",
            # Casino/Gambling
            "casino", "poker online", "slot machine", "betting",
            "gambling", "win big", "jackpot winner",
            # Suspicious requests
            "send money", "bank account", "credit card", "social security",
            "password reset", "verify information", "update payment",
            # Investment scams
            "investment opportunity", "guaranteed returns", "risk free",
            "double your money", "crypto investment", "forex trading"
        ]
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for keyword in sample_keywords:
                    f.write(keyword + '\n')
            print(f"Sample dictionary created: {filepath}")
            return filepath
        except Exception as e:
            print(f"Error creating sample file: {e}")
            return None
    
    def check_message(self, message):  # Scan entire message for spam keywords.
        start_time = time.time()    
        words = self._extract_words_and_phrases(message) # Extract words and phrases

        # Check each word/phrase
        matches = []
        for word in words:
            if self.bloom_filter.contains(word):
                matches.append(word)
        
        scan_time = time.time() - start_time
        
        # Calculate spam score (0-100)
        spam_score = min(100, len(matches) * 15)
        result = {
            'is_spam': len(matches) > 0,
            'spam_score': spam_score,
            'matched_keywords': matches,
            'total_words_checked': len(words),
            'scan_time_ms': scan_time * 1000,
            'message_length': len(message)
        }
        
        # Track in history
        self.scan_history.append({
            'timestamp': time.time(),
            'is_spam': result['is_spam'],
            'matches': len(matches)
        })
        
        return result
    
    def _extract_words_and_phrases(self, text):   #Extract individual words and common phrases from text.
        text_lower = text.lower()
        # Extract individual words
        words = re.findall(r'\b[a-z]+\b', text_lower)
        # Extract 2-word phrases
        two_word_phrases = re.findall(r'\b[a-z]+\s+[a-z]+\b', text_lower)
        # Extract 3-word phrases
        three_word_phrases = re.findall(r'\b[a-z]+\s+[a-z]+\s+[a-z]+\b', text_lower)
        # Combine all
        all_tokens = words + two_word_phrases + three_word_phrases
        
        return list(set(all_tokens))  # Remove duplicates
    
    def get_spam_keyword_matches(self, message):  #Return only the matched spam keywords from a message.
        result = self.check_message(message)
        return result['matched_keywords']
    
    def benchmark_performance(self, num_messages=1000):    # Performance benchmarking for spam detection.
        print(f"\n--- Running Benchmark ({num_messages} messages) ---")
        
        # Generate test messages
        test_messages = self._generate_test_messages(num_messages)
        
        start_time = time.time()
        spam_count = 0
        total_matches = 0
        
        for message in test_messages:
            result = self.check_message(message)
            if result['is_spam']:
                spam_count += 1
            total_matches += len(result['matched_keywords'])
        
        total_time = time.time() - start_time
        
        results = {
            'total_messages': num_messages,
            'spam_detected': spam_count,
            'ham_detected': num_messages - spam_count,
            'spam_percentage': (spam_count / num_messages) * 100,
            'total_time_seconds': total_time,
            'avg_time_per_message_ms': (total_time / num_messages) * 1000,
            'messages_per_second': num_messages / total_time,
            'total_keyword_matches': total_matches,
            'avg_matches_per_spam': total_matches / spam_count if spam_count > 0 else 0
        }
        
        return results
    
    def _generate_test_messages(self, count):   # Generate test messages for benchmarking.
        spam_templates = [
            "Congratulations! You won a prize. Click here to claim now!",
            "Free money waiting for you. Act now, limited time offer!",
            "Buy viagra online with guaranteed results. Order now!",
            "Work from home and make money fast. Visit our website today.",
            "Casino jackpot winner! Claim your cash prize immediately."
        ]
        
        ham_templates = [
            "Hello, how are you doing today? Let's meet for coffee.",
            "The project report is attached. Please review by Friday.",
            "Thank you for your email. I'll get back to you soon.",
            "Meeting scheduled for 3pm tomorrow in conference room.",
            "Happy birthday! Hope you have a wonderful day."
        ]
        
        messages = []
        for i in range(count):
            if i % 3 == 0:  # ~33% spam
                messages.append(spam_templates[i % len(spam_templates)])
            else:
                messages.append(ham_templates[i % len(ham_templates)])
        
        return messages
    
    def print_benchmark_results(self, results):
        """Print formatted benchmark results."""
        print("\n=== Benchmark Results ===")
        print(f"Total Messages: {results['total_messages']}")
        print(f"Spam Detected: {results['spam_detected']} ({results['spam_percentage']:.2f}%)")
        print(f"Ham Detected: {results['ham_detected']}")
        print(f"Total Time: {results['total_time_seconds']:.4f} seconds")
        print(f"Avg Time/Message: {results['avg_time_per_message_ms']:.4f} ms")
        print(f"Throughput: {results['messages_per_second']:.2f} messages/second")
        print(f"Total Keyword Matches: {results['total_keyword_matches']}")
        print(f"Avg Matches/Spam: {results['avg_matches_per_spam']:.2f}")
    
    def get_statistics(self):
        """Get comprehensive statistics about spam detection."""
        bf_stats = self.bloom_filter.get_stats()
        
        spam_scans = sum(1 for scan in self.scan_history if scan['is_spam'])
        
        return {
            'total_keywords_loaded': self.total_keywords_loaded,
            'keyword_sources': len(self.keyword_sources),
            'total_scans': len(self.scan_history),
            'spam_detected': spam_scans,
            'ham_detected': len(self.scan_history) - spam_scans,
            'bloom_filter_stats': bf_stats
        }


if __name__ == "__main__":
    # NOTE: You need to have member1_bloom_filter.py in the same directory
    # or modify the import below
    from bloom_filter import BloomFilter
    
    # Initialize
    bf = BloomFilter(expected_items=5000, false_positive_rate=0.01)
    manager = SpamKeywordManager(bf)
    
    # Create and load sample dictionary
    print("Creating sample spam dictionary...")
    dict_file = manager.create_sample_dictionary()
    
    if dict_file:
        manager.load_from_file(dict_file)
    
    # Test messages
    print("\n--- Scanning Test Messages ---")
    test_messages = [
        "Congratulations! You won $1000000! Click here to claim your prize now!",
        "Hi John, let's schedule a meeting for next week to discuss the project.",
        "Buy viagra online, guaranteed results! Act now, limited time offer!",
    ]
    
    for i, msg in enumerate(test_messages, 1):
        print(f"\nMessage {i}: {msg[:50]}...")
        result = manager.check_message(msg)
        print(f"Spam Score: {result['spam_score']}/100")
        print(f"Matched Keywords: {result['matched_keywords']}")
        print(f"Scan Time: {result['scan_time_ms']:.4f} ms")
    
    # Run benchmark
    benchmark = manager.benchmark_performance(1000)
    manager.print_benchmark_results(benchmark)