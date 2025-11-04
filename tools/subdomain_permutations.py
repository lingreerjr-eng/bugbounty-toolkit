#!/usr/bin/env python3
"""
subdomain_permutations.py
Generate intelligent subdomain permutations for brute-forcing based on discovered subdomains
Usage: python3 subdomain_permutations.py <base_domain> <discovered_subdomains.txt> <output.txt>
"""

import sys
from pathlib import Path
from collections import Counter
import itertools

class PermutationGenerator:
    def __init__(self, base_domain: str):
        self.base_domain = base_domain
        self.permutations = set()
        
        # Common prefixes for bug bounties
        self.common_prefixes = [
            'dev', 'development', 'stage', 'staging', 'test', 'testing',
            'qa', 'uat', 'preprod', 'pre-prod', 'prod', 'production',
            'admin', 'administrator', 'panel', 'console', 'manage', 'management',
            'api', 'api-v1', 'api-v2', 'api1', 'api2', 'rest', 'graphql',
            'app', 'apps', 'mobile', 'ios', 'android',
            'old', 'new', 'v1', 'v2', 'beta', 'alpha',
            'internal', 'corp', 'vpn', 'remote', 'intranet',
            'backup', 'bak', 'old', 'legacy', 'archive',
            'cdn', 'static', 'assets', 'media', 'images', 'img',
            'www', 'www2', 'www3', 'm', 'mobile', 'wap',
            'mail', 'email', 'smtp', 'imap', 'webmail',
            'ftp', 'sftp', 'upload', 'download', 'files',
            'db', 'database', 'mysql', 'postgres', 'mongo',
            'cache', 'redis', 'memcache',
            'monitor', 'monitoring', 'metrics', 'grafana', 'prometheus',
            'log', 'logs', 'logging', 'elk', 'kibana',
            'jenkins', 'ci', 'cd', 'build', 'gitlab', 'github',
            'jira', 'confluence', 'wiki', 'docs', 'documentation',
            'portal', 'login', 'auth', 'sso', 'oauth', 'idp',
            'payment', 'pay', 'billing', 'invoice', 'checkout',
            'shop', 'store', 'ecommerce', 'cart',
            'support', 'help', 'helpdesk', 'ticket', 'zendesk',
            'status', 'health', 'ping', 'check',
            's3', 'bucket', 'storage', 'files',
        ]
        
        # Common suffixes
        self.common_suffixes = [
            'dev', 'test', 'staging', 'prod', 'uat',
            'api', 'app', 'web', 'mobile',
            'v1', 'v2', 'v3',
            '1', '2', '3',
            'old', 'new', 'bak',
        ]
        
        # Common separators
        self.separators = ['-', '_', '']
        
        # Environment indicators
        self.environments = ['dev', 'test', 'staging', 'stage', 'uat', 'prod', 'qa']
        
        # Geographic/regional
        self.regions = ['us', 'eu', 'asia', 'apac', 'uk', 'au', 'ca', 'de', 'fr', 
                       'us-east', 'us-west', 'eu-west', 'ap-south']
    
    def analyze_existing_patterns(self, discovered_subs: list) -> dict:
        """Analyze discovered subdomains to find patterns"""
        patterns = {
            'prefixes': Counter(),
            'suffixes': Counter(),
            'separators': Counter(),
            'word_counts': Counter(),
        }
        
        for sub in discovered_subs:
            if not sub.endswith(self.base_domain):
                continue
            
            # Get subdomain part only
            parts = sub.replace(f'.{self.base_domain}', '').split('.')
            
            for part in parts:
                # Count separators
                if '-' in part:
                    patterns['separators']['-'] += 1
                if '_' in part:
                    patterns['separators']['_'] += 1
                
                # Split by separators to get words
                words = part.replace('-', ' ').replace('_', ' ').split()
                patterns['word_counts'][len(words)] += 1
                
                # Track first/last words
                if words:
                    patterns['prefixes'][words[0]] += 1
                    patterns['suffixes'][words[-1]] += 1
        
        return patterns
    
    def generate_from_wordlist(self, wordlist: list):
        """Generate permutations from a wordlist of discovered subdomains"""
        patterns = self.analyze_existing_patterns(wordlist)
        
        # Extract unique words from discovered subdomains
        discovered_words = set()
        for sub in wordlist:
            if not sub.endswith(self.base_domain):
                continue
            parts = sub.replace(f'.{self.base_domain}', '').split('.')
            for part in parts:
                words = part.replace('-', '_').replace('_', ' ').split()
                discovered_words.update(w.lower() for w in words if len(w) > 1)
        
        print(f"[*] Extracted {len(discovered_words)} unique words from discovered subdomains")
        
        # Generate permutations
        self._generate_simple_permutations()
        self._generate_compound_permutations(discovered_words)
        self._generate_environment_permutations(discovered_words)
        self._generate_regional_permutations(discovered_words)
        self._generate_number_permutations(discovered_words)
    
    def _generate_simple_permutations(self):
        """Generate simple single-word subdomains"""
        for prefix in self.common_prefixes:
            self.permutations.add(f"{prefix}.{self.base_domain}")
    
    def _generate_compound_permutations(self, discovered_words):
        """Generate compound subdomains with discovered words"""
        all_words = list(discovered_words) + self.common_prefixes[:20]  # Top 20 common
        
        # Two-word combinations
        for w1, w2 in itertools.combinations(all_words, 2):
            for sep in self.separators:
                self.permutations.add(f"{w1}{sep}{w2}.{self.base_domain}")
        
        # Prefix + discovered word
        for prefix in self.common_prefixes[:30]:
            for word in discovered_words:
                for sep in self.separators:
                    self.permutations.add(f"{prefix}{sep}{word}.{self.base_domain}")
        
        # Discovered word + suffix
        for word in discovered_words:
            for suffix in self.common_suffixes:
                for sep in self.separators:
                    self.permutations.add(f"{word}{sep}{suffix}.{self.base_domain}")
    
    def _generate_environment_permutations(self, discovered_words):
        """Generate environment-based permutations"""
        for env in self.environments:
            # env-word
            for word in discovered_words:
                for sep in ['-', '_']:
                    self.permutations.add(f"{env}{sep}{word}.{self.base_domain}")
                    self.permutations.add(f"{word}{sep}{env}.{self.base_domain}")
    
    def _generate_regional_permutations(self, discovered_words):
        """Generate region-based permutations"""
        for region in self.regions:
            # region-word
            for word in list(discovered_words)[:20]:  # Top 20 words
                for sep in ['-', '']:
                    self.permutations.add(f"{region}{sep}{word}.{self.base_domain}")
                    self.permutations.add(f"{word}{sep}{region}.{self.base_domain}")
    
    def _generate_number_permutations(self, discovered_words):
        """Generate numbered variations"""
        for word in list(discovered_words)[:30]:
            for num in range(1, 10):
                self.permutations.add(f"{word}{num}.{self.base_domain}")
                self.permutations.add(f"{word}-{num}.{self.base_domain}")
                self.permutations.add(f"{word}_{num}.{self.base_domain}")
    
    def get_permutations(self) -> set:
        return self.permutations


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 subdomain_permutations.py <base_domain> <discovered_subdomains.txt> <output.txt>")
        print("\nGenerates intelligent subdomain permutations based on discovered patterns")
        sys.exit(1)
    
    base_domain = sys.argv[1]
    input_file = Path(sys.argv[2])
    output_file = Path(sys.argv[3])
    
    if not input_file.exists():
        print(f"[!] Input file not found: {input_file}")
        sys.exit(1)
    
    # Load discovered subdomains
    discovered = [line.strip() for line in input_file.read_text().splitlines() if line.strip()]
    print(f"[*] Loaded {len(discovered)} discovered subdomains")
    
    # Generate permutations
    generator = PermutationGenerator(base_domain)
    generator.generate_from_wordlist(discovered)
    
    permutations = generator.get_permutations()
    
    # Filter out already discovered
    new_perms = permutations - set(discovered)
    
    # Save
    output_file.write_text('\n'.join(sorted(new_perms)))
    print(f"[+] Generated {len(new_perms)} new permutations -> {output_file}")
    print(f"[*] Total candidates (including discovered): {len(permutations)}")
    print("\n[*] Use with tools like:")
    print(f"    massdns -r resolvers.txt -t A -o S {output_file}")
    print(f"    shuffledns -d {base_domain} -list {output_file} -r resolvers.txt")
    print(f"    puredns resolve {output_file} -r resolvers.txt")

if __name__ == "__main__":
    main()
