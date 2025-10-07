
import math
import hashlib


class BloomFilter:

    
    def __init__(self, expected_items=10000, false_positive_rate=0.01):

        self.expected_items = expected_items
        self.false_positive_rate = false_positive_rate
        
        # Calculate optimal bit array size
        self.size = self._calculate_optimal_size(expected_items, false_positive_rate)
        
        # Calculate optimal number of hash functions
        self.num_hashes = self._calculate_optimal_hash_count(self.size, expected_items)
        
        # Initialize bit array (using list of bools for simplicity)
        self.bit_array = [False] * self.size
        
        # Track number of items added
        self.items_added = 0
        
        print(f"Bloom Filter initialized:")
        print(f"  Size: {self.size} bits")
        print(f"  Hash functions: {self.num_hashes}")
        print(f"  Expected FP rate: {false_positive_rate:.4f}")
    
    def _calculate_optimal_size(self, n, p):

        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(math.ceil(m))
    
    def _calculate_optimal_hash_count(self, m, n):

        k = (m / n) * math.log(2)
        return int(math.ceil(k))
    
    def _murmur_hash(self, key, seed=0):

        key_bytes = key.encode('utf-8')
        hash_val = seed
        
        for byte in key_bytes:
            hash_val ^= byte
            hash_val *= 0x5bd1e995
            hash_val &= 0xFFFFFFFF
            hash_val ^= hash_val >> 15
        
        return hash_val % self.size
    
    def _fnv_hash(self, key, seed=0):

        fnv_prime = 0x01000193
        fnv_offset = 0x811c9dc5
        
        hash_val = (fnv_offset + seed) & 0xFFFFFFFF
        
        for char in key:
            hash_val ^= ord(char)
            hash_val = (hash_val * fnv_prime) & 0xFFFFFFFF
        
        return hash_val % self.size
    
    def _djb2_hash(self, key, seed=0):

        hash_val = 5381 + seed
        
        for char in key:
            hash_val = ((hash_val << 5) + hash_val) + ord(char)
            hash_val &= 0xFFFFFFFF
        
        return hash_val % self.size
    
    def _sdbm_hash(self, key, seed=0):

        hash_val = seed
        
        for char in key:
            hash_val = ord(char) + (hash_val << 6) + (hash_val << 16) - hash_val
            hash_val &= 0xFFFFFFFF
        
        return hash_val % self.size
    
    def _get_hash_values(self, item):

        item_lower = item.lower().strip()
        hash_functions = [self._murmur_hash, self._fnv_hash, self._djb2_hash, self._sdbm_hash]
        
        indices = []
        for i in range(self.num_hashes):
            # Use different hash functions or same function with different seeds
            func_idx = i % len(hash_functions)
            seed = i // len(hash_functions)
            hash_val = hash_functions[func_idx](item_lower, seed)
            indices.append(hash_val)
        
        return indices
    
    def add(self, item):

        if not isinstance(item, str) or not item.strip():
            return
        
        indices = self._get_hash_values(item)
        
        for idx in indices:
            self.bit_array[idx] = True
        
        self.items_added += 1
    
    def contains(self, item):

        if not isinstance(item, str) or not item.strip():
            return False
        
        indices = self._get_hash_values(item)
        
        # Item is present only if all corresponding bits are set
        for idx in indices:
            if not self.bit_array[idx]:
                return False
        
        return True
    
    def get_false_positive_rate(self):

        if self.items_added == 0:
            return 0.0
        
        # Calculate actual FP rate based on items added
        exponent = -self.num_hashes * self.items_added / self.size
        actual_fp_rate = (1 - math.exp(exponent)) ** self.num_hashes
        
        return actual_fp_rate
    
    def get_capacity_usage(self):

        return (self.items_added / self.expected_items) * 100
    
    def get_bit_usage(self):

        bits_set = sum(self.bit_array)
        return (bits_set / self.size) * 100
    
    def clear(self):
        """Reset the bloom filter to empty state."""
        self.bit_array = [False] * self.size
        self.items_added = 0
    
    def get_stats(self):

        return {
            'size_bits': self.size,
            'num_hash_functions': self.num_hashes,
            'items_added': self.items_added,
            'expected_items': self.expected_items,
            'capacity_usage_percent': self.get_capacity_usage(),
            'bits_set_percent': self.get_bit_usage(),
            'expected_fp_rate': self.false_positive_rate,
            'actual_fp_rate': self.get_false_positive_rate()
        }


# Demo usage
if __name__ == "__main__":
    # Create bloom filter for spam keywords
    bf = BloomFilter(expected_items=5000, false_positive_rate=0.01)
    
    # Add some spam keywords
    spam_keywords = [
        "viagra", "casino", "lottery", "winner", "claim",
        "free money", "click here", "limited time", "act now"
    ]
    
    print("\nAdding spam keywords...")
    for keyword in spam_keywords:
        bf.add(keyword)
    
    # Test membership
    print("\n--- Membership Tests ---")
    test_words = ["viagra", "casino", "hello", "python", "click here"]
    for word in test_words:
        result = bf.contains(word)
        print(f"'{word}': {'SPAM' if result else 'NOT SPAM'}")
    
    # Display statistics
    print("\n--- Bloom Filter Statistics ---")
    stats = bf.get_stats()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"{key}: {value:.6f}")
        else:
            print(f"{key}: {value}")