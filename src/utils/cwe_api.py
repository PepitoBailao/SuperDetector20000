import requests
import json
import time
from typing import Dict, List, Optional, Any
import os
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CWEAPIClient:
    """Client for MITRE CWE REST API - Optimized and reliable"""
    
    def __init__(self, base_url="https://cwe-api.mitre.org/api/v1"):
        self.base_url = base_url
        self.session = requests.Session()
        self.cache_dir = "cache/cwe_api"
        
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Configure session
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'SuperDetector20000/1.0',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
    def _get_cached_data(self, endpoint: str) -> Optional[Dict]:
        """Get cached API response"""
        cache_file = os.path.join(self.cache_dir, f"{endpoint.replace('/', '_')}.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return None
        return None
    
    def _cache_data(self, endpoint: str, data: Dict) -> None:
        """Cache API response"""
        cache_file = os.path.join(self.cache_dir, f"{endpoint.replace('/', '_')}.json")
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
    
    def _make_request(self, endpoint: str, params: Optional[Dict] = None, use_cache: bool = True) -> Optional[Dict]:
        """Make API request with intelligent caching and error handling"""
        if use_cache:
            cached = self._get_cached_data(endpoint)
            if cached:
                return cached
        
        url = f"{self.base_url}/{endpoint}"
        response = None  # Initialize response variable
        
        for attempt in range(2):  # Reduced retries
            try:
                time.sleep(0.15)  # Optimized rate limiting
                response = self.session.get(url, params=params, timeout=8)
                
                if response.status_code == 404:
                    return None  # Expected for non-existent CWEs
                
                response.raise_for_status()
                data = response.json()
                
                if use_cache:
                    self._cache_data(endpoint, data)
                
                return data
                    
            except requests.exceptions.HTTPError as e:
                if response and response.status_code == 404:
                    return None
                elif attempt == 0:
                    time.sleep(1)
                    
            except requests.exceptions.RequestException as e:
                if attempt == 0:
                    time.sleep(1)
        
        return None
    
    def get_version(self) -> Optional[str]:
        """Get CWE database version"""
        data = self._make_request("cwe/version")
        return data.get('version') if data else None
    
    def get_weakness(self, cwe_id: int) -> Optional[Dict]:
        """Get weakness details"""
        return self._make_request(f"cwe/weakness/{cwe_id}")
    
    def get_category(self, cwe_id: int) -> Optional[Dict]:
        """Get category details"""
        return self._make_request(f"cwe/category/{cwe_id}")
    
    def get_view(self, cwe_id: int) -> Optional[Dict]:
        """Get view details"""
        return self._make_request(f"cwe/view/{cwe_id}")
    
    def get_parents(self, cwe_id: int, view: int = 1000) -> List[int]:
        """Get parent CWEs"""
        data = self._make_request(f"cwe/{cwe_id}/parents", {"view": view})
        return data if data and isinstance(data, list) else []
    
    def get_children(self, cwe_id: int, view: int = 1000) -> List[int]:
        """Get child CWEs"""
        data = self._make_request(f"cwe/{cwe_id}/children", {"view": view})
        return data if data and isinstance(data, list) else []
    
    def extract_code_examples(self, cwe_data: Dict) -> List[str]:
        """Extract ALL code examples from CWE data"""
        examples = []
        
        if not cwe_data:
            return examples
        
        weakness = cwe_data.get('Weakness', {})
        
        # Primary source: Demonstrative_Examples
        demo_examples = weakness.get('Demonstrative_Examples', {})
        if isinstance(demo_examples, dict):
            demo_example = demo_examples.get('Demonstrative_Example', [])
            if not isinstance(demo_example, list):
                demo_example = [demo_example]
            
            for example in demo_example:
                if isinstance(example, dict):
                    example_code = example.get('Example_Code', {})
                    
                    if isinstance(example_code, dict):
                        # Try different text fields
                        code_text = (
                            example_code.get('#text', '') or
                            example_code.get('Body', {}).get('#text', '') or
                            (example_code.get('Body', '') if isinstance(example_code.get('Body'), str) else '')
                        )
                        
                        if code_text and code_text.strip():
                            examples.append(code_text.strip())
                    
                    elif isinstance(example_code, str) and example_code.strip():
                        examples.append(example_code.strip())
        
        # Secondary sources
        secondary_sources = [
            'Potential_Mitigations',
            'Content_History', 
            'Common_Consequences',
            'Detection_Methods',
            'Observed_Examples'
        ]
        
        for source in secondary_sources:
            section = weakness.get(source, {})
            if isinstance(section, dict):
                self._extract_nested_code(section, examples)
            elif isinstance(section, list):
                for item in section:
                    if isinstance(item, dict):
                        self._extract_nested_code(item, examples)
        
        return list(set(examples))  # Remove duplicates
    
    def _extract_nested_code(self, data: Dict, examples: List[str]) -> None:
        """Recursively extract code from nested structures"""
        if not isinstance(data, dict):
            return
            
        for key, value in data.items():
            if any(term in key.lower() for term in ['code', 'example']):
                if isinstance(value, str) and value.strip():
                    examples.append(value.strip())
                elif isinstance(value, dict):
                    text = value.get('#text', '')
                    if text and text.strip():
                        examples.append(text.strip())
            elif isinstance(value, dict):
                self._extract_nested_code(value, examples)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_nested_code(item, examples)
    
    def get_known_cwes(self) -> List[int]:
        """Get known high-value CWE ranges without full discovery"""
        # Focus on ranges known to contain many CWEs
        known_ranges = []
        
        # Core weakness ranges (high density)
        known_ranges.extend(range(1, 200))      # Primary weaknesses
        known_ranges.extend(range(200, 400))    # More weaknesses
        known_ranges.extend(range(400, 600))    # Additional weaknesses
        known_ranges.extend(range(600, 800))    # More categories
        known_ranges.extend(range(787, 830))    # Buffer/memory issues
        known_ranges.extend(range(862, 890))    # Auth/access issues
        known_ranges.extend(range(1000, 1100))  # Views and categories
        known_ranges.extend(range(1200, 1400))  # Extended categories
        
        return sorted(known_ranges)
    
    def discover_cwes_fast(self) -> List[int]:
        """Fast CWE discovery with minimal logging"""
        print("Discovering CWEs (optimized mode)...")
        
        available_cwes = []
        test_ranges = [
            (1, 500, "Core weaknesses"),
            (500, 1000, "Extended weaknesses"), 
            (1000, 1500, "Categories and views")
        ]
        
        for start, end, desc in test_ranges:
            print(f"  Testing {desc} ({start}-{end-1})...")
            range_found = 0
            
            for cwe_id in range(start, end):
                if cwe_id % 200 == 0:
                    print(f"    Progress: {cwe_id}/{end-1} - {range_found} found in range")
                
                # Test types in order of likelihood
                for cwe_type in ['weakness', 'category', 'view']:
                    data = self._make_request(f"cwe/{cwe_type}/{cwe_id}", use_cache=True)
                    if data:
                        available_cwes.append(cwe_id)
                        range_found += 1
                        break
                
                # Minimal delay
                if cwe_id % 20 == 0:
                    time.sleep(0.1)
            
            print(f"    {desc}: {range_found} CWEs found")
        
        print(f"Fast discovery complete: {len(available_cwes)} CWEs found")
        return sorted(available_cwes)
    
    def get_comprehensive_cwe_database(self, fast_mode: bool = True) -> Dict[int, Dict]:
        """Get comprehensive CWE database with optimizations"""
        print("Building comprehensive CWE database...")
        
        if fast_mode:
            print("Using fast mode with known CWE ranges...")
            all_cwe_ids = self.get_known_cwes()
        else:
            all_cwe_ids = self.discover_cwes_fast()
        
        print(f"Processing {len(all_cwe_ids)} CWEs...")
        
        cwe_details = {}
        total_examples = 0
        processed = 0
        
        for cwe_id in all_cwe_ids:
            processed += 1
            
            if processed % 25 == 0:
                print(f"  Progress: {processed}/{len(all_cwe_ids)} ({processed/len(all_cwe_ids)*100:.1f}%)")
            
            details = {
                'id': cwe_id,
                'name': '',
                'description': '',
                'code_examples': [],
                'parents': [],
                'children': [],
                'severity': 'Unknown',
                'type': 'unknown'
            }
            
            # Try different endpoint types
            found_data = False
            
            # 1. Try weakness (most likely to have examples)
            weakness_data = self.get_weakness(cwe_id)
            if weakness_data:
                weakness = weakness_data.get('Weakness', {})
                details.update({
                    'name': weakness.get('Name', f'CWE-{cwe_id}'),
                    'type': 'weakness',
                    'description': self._extract_description(weakness.get('Description', {})),
                    'code_examples': self.extract_code_examples(weakness_data),
                    'severity': weakness.get('Likelihood_Of_Exploit', 'Unknown')
                })
                total_examples += len(details['code_examples'])
                found_data = True
            
            # 2. Try category
            elif not found_data:
                category_data = self.get_category(cwe_id)
                if category_data:
                    category = category_data.get('Category', {})
                    details.update({
                        'name': category.get('Name', f'CWE-{cwe_id}'),
                        'type': 'category',
                        'description': self._extract_description(category.get('Summary', {}))
                    })
                    found_data = True
            
            # 3. Try view
            elif not found_data:
                view_data = self.get_view(cwe_id)
                if view_data:
                    view = view_data.get('View', {})
                    details.update({
                        'name': view.get('Name', f'CWE-{cwe_id}'),
                        'type': 'view',
                        'description': self._extract_description(view.get('Objective', {}))
                    })
                    found_data = True
            
            # Get relationships
            if found_data:
                details['parents'] = self.get_parents(cwe_id)
                details['children'] = self.get_children(cwe_id)
                cwe_details[cwe_id] = details
                
                if details['code_examples']:
                    print(f"    CWE-{cwe_id}: {len(details['code_examples'])} examples")
        
        print(f"\nDatabase build complete:")
        print(f"  Total CWEs: {len(cwe_details)}")
        print(f"  Total examples: {total_examples}")
        print(f"  CWEs with examples: {len([c for c in cwe_details.values() if c['code_examples']])}")
        if len(cwe_details) > 0:
            print(f"  Average examples per CWE: {total_examples/len(cwe_details):.1f}")
        
        return cwe_details
    
    def _extract_description(self, desc_data) -> str:
        """Extract description text from various formats"""
        if isinstance(desc_data, dict):
            return desc_data.get('#text', '')
        elif isinstance(desc_data, str):
            return desc_data
        return ''

def update_cwe_database(fast_mode: bool = True):
    """Update local CWE database with optimizations"""
    client = CWEAPIClient()
    
    mode_desc = "fast mode" if fast_mode else "discovery mode"
    print(f"Fetching comprehensive CWE database ({mode_desc})...")
    
    start_time = time.time()
    cwe_data = client.get_comprehensive_cwe_database(fast_mode=fast_mode)
    end_time = time.time()
    
    collection_time = end_time - start_time
    print(f"Data collection completed in {collection_time:.1f} seconds")
    
    # Prepare database file
    db_path = "cache/cwe_database.json"
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    # Calculate statistics
    total_examples = sum(len(data.get('code_examples', [])) for data in cwe_data.values())
    cwes_with_examples = len([cwe for cwe in cwe_data.values() if cwe.get('code_examples')])
    
    # Convert keys to strings for JSON compatibility
    cwe_data_str_keys = {str(k): v for k, v in cwe_data.items()}
    
    # Create comprehensive database info
    database_info = {
        'metadata': {
            'version': client.get_version() or 'unknown',
            'updated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'collection_method': 'optimized_fast' if fast_mode else 'discovery_mode',
            'collection_time_seconds': collection_time,
        },
        'statistics': {
            'total_cwes': len(cwe_data_str_keys),
            'total_examples': total_examples,
            'cwes_with_examples': cwes_with_examples,
            'average_examples_per_cwe': total_examples / len(cwe_data_str_keys) if cwe_data_str_keys else 0,
            'coverage_by_type': {
                'weakness': len([c for c in cwe_data.values() if c.get('type') == 'weakness']),
                'category': len([c for c in cwe_data.values() if c.get('type') == 'category']),
                'view': len([c for c in cwe_data.values() if c.get('type') == 'view'])
            }
        },
        'cwes': cwe_data_str_keys
    }
    
    # Save database
    with open(db_path, 'w', encoding='utf-8') as f:
        json.dump(database_info, f, indent=2, ensure_ascii=False)
    
    # Print summary
    print(f"\n✓ CWE database saved: {db_path}")
    print(f"  Total CWEs: {len(cwe_data_str_keys)}")
    print(f"  Total examples: {total_examples}")
    print(f"  CWEs with examples: {cwes_with_examples}")
    print(f"  Collection time: {collection_time:.1f} seconds")
    
    return db_path

def get_cwe_info(cwe_id: int) -> Dict:
    """Get CWE information from local database or API fallback"""
    db_path = "cache/cwe_database.json"
    if os.path.exists(db_path):
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                db = json.load(f)
                cwes = db.get('cwes', {})
                for key in [str(cwe_id), cwe_id]:
                    if key in cwes:
                        return cwes[key]
        except Exception:
            pass
    
    # Fallback to API
    client = CWEAPIClient()
    
    # Try weakness first
    weakness_data = client.get_weakness(cwe_id)
    if weakness_data:
        weakness = weakness_data.get('Weakness', {})
        return {
            'id': cwe_id,
            'name': weakness.get('Name', f'CWE-{cwe_id}'),
            'description': client._extract_description(weakness.get('Description', {})),
            'code_examples': client.extract_code_examples(weakness_data),
            'parents': client.get_parents(cwe_id),
            'children': client.get_children(cwe_id),
            'type': 'weakness'
        }
    
    # Try category
    category_data = client.get_category(cwe_id)
    if category_data:
        category = category_data.get('Category', {})
        return {
            'id': cwe_id,
            'name': category.get('Name', f'CWE-{cwe_id}'),
            'description': client._extract_description(category.get('Summary', {})),
            'code_examples': [],
            'parents': client.get_parents(cwe_id),
            'children': client.get_children(cwe_id),
            'type': 'category'
        }
    
    # Default fallback
    return {
        'id': cwe_id, 
        'name': f'CWE-{cwe_id}', 
        'description': 'No description available', 
        'code_examples': [],
        'parents': [],
        'children': [],
        'type': 'unknown'
    }

def get_database_stats() -> Dict:
    """Get statistics about the current CWE database"""
    db_path = "cache/cwe_database.json"
    
    if not os.path.exists(db_path):
        return {'error': 'No database found'}
    
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            db = json.load(f)
            return db.get('statistics', {})
    except Exception as e:
        return {'error': f'Failed to read database: {e}'}

if __name__ == "__main__":
    # Use fast mode by default for quicker setup
    update_cwe_database(fast_mode=True)