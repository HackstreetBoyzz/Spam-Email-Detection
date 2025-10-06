from enum import Enum

class Color(Enum):
    RED = 1
    BLACK = 2

class RBNode:
    def __init__(self, domain, reputation_score=90):
        self.domain = domain
        self.reputation_score = reputation_score
        self.spam_reports = 0
        self.legitimate_reports = 0
        self.last_updated = None
        self.color = Color.RED  # New nodes are always red
        self.left = None
        self.right = None
        self.parent = None
    def __str__(self):
        color_str = "R" if self.color == Color.RED else "B"
        return f"[{color_str}] {self.domain}: {self.reputation_score}"


class RedBlackTree:
    def __init__(self):
        self.NIL = RBNode(domain="NIL", reputation_score=0) #Initialize an empty Red-Black Tree.
        self.NIL.color = Color.BLACK
        self.NIL.left = self.NIL
        self.NIL.right = self.NIL
        self.root = self.NIL
        self.size = 0
    
    def insert_domain(self, domain, reputation_score=50):
        # Create new node
        new_node = RBNode(domain, reputation_score) # Insert a new domain with reputation score and maintain RB-Tree properties.
        new_node.left = self.NIL
        new_node.right = self.NIL
        
        # Standard BST insertion
        parent = None
        current = self.root
        
        while current != self.NIL:
            parent = current
            if new_node.domain < current.domain:
                current = current.left
            elif new_node.domain > current.domain:
                current = current.right
            else:
                # Domain already exists, update reputation
                current.reputation_score = reputation_score
                return current
        new_node.parent = parent
        
        if parent is None:
            self.root = new_node
        elif new_node.domain < parent.domain:
            parent.left = new_node
        else:
            parent.right = new_node
        
        new_node.color = Color.RED
        self.size += 1
        self._insert_fixup(new_node) # Fix RB-Tree violations
        return new_node
    
    def _insert_fixup(self, node):
        while node.parent and node.parent.color == Color.RED:# Fix Red-Black Tree properties after insertion.
            if node.parent == node.parent.parent.left:
                uncle = node.parent.parent.right
                
                if uncle.color == Color.RED:
                    # Case 1: Uncle is red
                    node.parent.color = Color.BLACK
                    uncle.color = Color.BLACK
                    node.parent.parent.color = Color.RED
                    node = node.parent.parent
                else:
                    if node == node.parent.right:
                        # Case 2: Node is right child
                        node = node.parent
                        self._left_rotate(node)
                    # Case 3: Node is left child
                    node.parent.color = Color.BLACK
                    node.parent.parent.color = Color.RED
                    self._right_rotate(node.parent.parent)
            else:
                uncle = node.parent.parent.left
                if uncle.color == Color.RED:
                    # Case 1: Uncle is red
                    node.parent.color = Color.BLACK
                    uncle.color = Color.BLACK
                    node.parent.parent.color = Color.RED
                    node = node.parent.parent
                else:
                    if node == node.parent.left:
                        # Case 2: Node is left child
                        node = node.parent
                        self._right_rotate(node)
                    # Case 3: Node is right child
                    node.parent.color = Color.BLACK
                    node.parent.parent.color = Color.RED
                    self._left_rotate(node.parent.parent)
        self.root.color = Color.BLACK
    
    def _left_rotate(self, x):
        y = x.right  #Perform left rotation around node x.
        x.right = y.left
        
        if y.left != self.NIL:
            y.left.parent = x
        
        y.parent = x.parent
        
        if x.parent is None:
            self.root = y
        elif x == x.parent.left:
            x.parent.left = y
        else:
            x.parent.right = y
        
        y.left = x
        x.parent = y
    
    def _right_rotate(self, y):
        x = y.left   #  Perform right rotation around node y.
        y.left = x.right
        
        if x.right != self.NIL:
            x.right.parent = y
        
        x.parent = y.parent
        
        if y.parent is None:
            self.root = x
        elif y == y.parent.right:
            y.parent.right = x
        else:
            y.parent.left = x
        
        x.right = y
        y.parent = x
    
    def search_domain(self, domain):
        current = self.root  # Search for a domain in the tree o(logn).
        
        while current != self.NIL:
            if domain == current.domain:
                return current
            elif domain < current.domain:
                current = current.left
            else:
                current = current.right
        
        return None
    
    def update_reputation_score(self, domain, new_score):
        node = self.search_domain(domain)   # Update reputation score for a domain.
        
        if node:
            node.reputation_score = max(0, min(100, new_score))
            return True
        return False
    
    def increment_spam_reports(self, domain, amount=1):
        node = self.search_domain(domain)   # Increment spam report count and decrease reputation.
        
        if node:
            node.spam_reports += amount
            # Decrease reputation (each report reduces by 5 points)
            node.reputation_score = max(0, node.reputation_score - (amount * 5))
            return node.reputation_score
        return None
    
    def increment_legitimate_reports(self, domain, amount=1):
        node = self.search_domain(domain)# Increment legitimate report count and increase reputation.
        
        if node:
            node.legitimate_reports += amount
            # Increase reputation (each report adds 3 points)
            node.reputation_score = min(100, node.reputation_score + (amount * 3))
            return node.reputation_score
        
        return None
    
    def get_blacklisted_domains(self, threshold=30):
        blacklisted = [] # Get all domains with reputation score below threshold (in-order traversal).
        self._inorder_collect_blacklisted(self.root, threshold, blacklisted)
        return blacklisted
    
    def _inorder_collect_blacklisted(self, node, threshold, result):
        """Helper for in-order traversal to collect blacklisted domains."""
        if node == self.NIL:
            return
        
        self._inorder_collect_blacklisted(node.left, threshold, result)
        
        if node.reputation_score < threshold:
            result.append((node.domain, node.reputation_score))
        
        self._inorder_collect_blacklisted(node.right, threshold, result)
    
    def get_all_domains(self):
        domains = []   #Get all domains with their reputation scores (in-order traversal).
        self._inorder_collect_all(self.root, domains)
        return domains
    
    def _inorder_collect_all(self, node, result):
        """Helper for in-order traversal."""
        if node == self.NIL:
            return
        
        self._inorder_collect_all(node.left, result)
        result.append((node.domain, node.reputation_score))
        self._inorder_collect_all(node.right, result)
    
    def get_height(self):
        """Calculate the height of the tree."""
        return self._calculate_height(self.root)
    
    def _calculate_height(self, node):
        """Helper to calculate tree height."""
        if node == self.NIL:
            return 0
        
        left_height = self._calculate_height(node.left)
        right_height = self._calculate_height(node.right)
        
        return 1 + max(left_height, right_height)
    
    def verify_rb_properties(self):
        errors = []  # Verify that all Red-Black Tree properties are maintained.
        
        # Property 1: Root is black
        if self.root != self.NIL and self.root.color != Color.BLACK:
            errors.append("Root is not black")
        
        # Property 2: No red node has red child
        if not self._verify_no_red_red(self.root):
            errors.append("Red-Red violation found")
        
        # Property 3: All paths have same black height
        black_height = self._get_black_height(self.root)
        if black_height == -1:
            errors.append("Black height violation found")
        
        return (len(errors) == 0, errors)
    
    def _verify_no_red_red(self, node):
        """Verify no red node has red children."""
        if node == self.NIL:
            return True
        
        if node.color == Color.RED:
            if (node.left != self.NIL and node.left.color == Color.RED) or \
               (node.right != self.NIL and node.right.color == Color.RED):
                return False
        
        return self._verify_no_red_red(node.left) and self._verify_no_red_red(node.right)
    
    def _get_black_height(self, node):
        """Get black height of node. Returns -1 if violation found."""
        if node == self.NIL:
            return 1
        
        left_height = self._get_black_height(node.left)
        right_height = self._get_black_height(node.right)
        
        if left_height == -1 or right_height == -1 or left_height != right_height:
            return -1
        
        if node.color == Color.BLACK:
            return left_height + 1
        else:
            return left_height
    
    def print_tree(self, node=None, prefix="", is_left=True):
        if node is None:#Print visual representation of the tree.
            node = self.root
        
        if node == self.NIL:
            return
        
        print(prefix + ("|-- " if is_left else "`-- ") + str(node))
        
        if node.left != self.NIL or node.right != self.NIL:
            if node.left != self.NIL:
                self.print_tree(node.left, prefix + ("|   " if is_left else "    "), True)
            if node.right != self.NIL:
                self.print_tree(node.right, prefix + ("|   " if is_left else "    "), False)
# Demo usage
if __name__ == "__main__":
    rbt = RedBlackTree()
    
    # Insert domains with initial reputation scores
    print("Inserting domains...")
    domains = [
        ("spam-domain.com", 10),
        ("trusted-site.org", 95),
        ("suspicious-email.net", 25),
        ("legitimate-bank.com", 90),
        ("phishing-site.info", 5),
        ("newsletter-service.com", 70),
        ("malware-host.ru", 0),
        ("verified-sender.edu", 100)
    ]
    
    for domain, score in domains:
        rbt.insert_domain(domain, score)
        print(f"  Added: {domain} (score: {score})")
    
    # Search for specific domains
    print("\n--- Domain Lookups ---")
    test_domains = ["spam-domain.com", "trusted-site.org", "nonexistent.com"]
    for domain in test_domains:
        result = rbt.search_domain(domain)
        if result:
            print(f"Found: {result.domain} - Reputation: {result.reputation_score}")
        else:
            print(f"Not found: {domain}")
    
    # Update reputation
    print("\n--- Updating Reputation ---")
    rbt.update_reputation_score("spam-domain.com", 5)
    print("Updated spam-domain.com to score 5")
    
    rbt.increment_spam_reports("suspicious-email.net", 3)
    print("Added 3 spam reports to suspicious-email.net")
    
    # Get blacklisted domains
    print("\n--- Blacklisted Domains (score < 30) ---")
    blacklisted = rbt.get_blacklisted_domains(threshold=30)
    for domain, score in blacklisted:
        print(f"  {domain}: {score}")
    
    # Verify RB properties
    print("\n--- Red-Black Tree Validation ---")
    is_valid, errors = rbt.verify_rb_properties()
    if is_valid:
        print("✓ All Red-Black Tree properties are satisfied")
    else:
        print("✗ Violations found:")
        for error in errors:
            print(f"  - {error}")
    
    print(f"\nTree height: {rbt.get_height()}")
    print(f"Total domains: {rbt.size}")
    
    # Print tree structure
    print("\n--- Tree Structure ---")
    rbt.print_tree()