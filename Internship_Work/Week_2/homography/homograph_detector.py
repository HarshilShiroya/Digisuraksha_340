import unicodedata
import idna
import os
import json
import argparse
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional

class HomographDetector:
    _confusables_map: Dict[str, str] = {}
    _script_map: Dict[str, str] = {}
    _allowed_scripts: Set[str] = {'Latin'}
    _whitelist: Set[str] = set()
    _whitelist_skeletons: Dict[str, str] = {}
    
    def __init__(self, allowed_scripts: Set[str] = None, whitelist: Set[str] = None):
        self.load_data_files()
        if allowed_scripts:
            self._allowed_scripts = allowed_scripts
        if whitelist:
            self.update_whitelist(whitelist)

    @classmethod
    def load_data_files(cls):
        """Load confusables and script mapping data from bundled files"""
        # Load confusables mapping
        if not cls._confusables_map:
            cls._confusables_map = {}
            try:
                with open('confusables.txt', 'r', encoding='utf-8') as f:
                    for line in f:
                        if ';' in line and not line.startswith('#'):
                            parts = line.split(';')
                            if len(parts) >= 2:
                                source_char = chr(int(parts[0].strip(), 16))
                                target_str = ''.join(chr(int(x, 16)) for x in parts[1].split())
                                cls._confusables_map[source_char] = target_str
            except FileNotFoundError:
                pass  # Fallback to empty map

        # Load script mapping
        if not cls._script_map:
            cls._script_map = {}
            try:
                with open('Scripts.txt', 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.startswith('#'):
                            parts = line.split(';')
                            if len(parts) >= 2:
                                char_range = parts[0].strip()
                                script = parts[1].split('#')[0].strip()
                                if '..' in char_range:
                                    start, end = [int(x, 16) for x in char_range.split('..')]
                                    for cp in range(start, end + 1):
                                        cls._script_map[chr(cp)] = script
                                else:
                                    cp = int(char_range, 16)
                                    cls._script_map[chr(cp)] = script
            except FileNotFoundError:
                pass  # Fallback to empty map

    def update_whitelist(self, whitelist: Set[str]):
        """Update trusted strings and precompute their skeletons"""
        self._whitelist = whitelist
        self._whitelist_skeletons = {}
        for s in whitelist:
            self._whitelist_skeletons[s] = self._compute_skeleton(s)

    def _compute_skeleton(self, s: str) -> str:
        """Compute skeleton for a string through normalization, case folding, and confusable mapping"""
        # Normalize to NFC
        normalized = unicodedata.normalize('NFC', s)
        # Case fold
        folded = normalized.casefold()
        # Apply confusable mapping
        skeleton = ''.join(self._confusables_map.get(c, c) for c in folded)
        return skeleton

    def _remove_invisible_chars(self, s: str) -> Tuple[str, List[Tuple[int, str]]:
        """Remove zero-width/invisible characters and return cleaned string with removal info"""
        removed = []
        visible_chars = []
        for i, c in enumerate(s):
            # Check for control characters, format characters, and special invisibles
            category = unicodedata.category(c)
            if category in ('Cf', 'Cc', 'Mn', 'Me') or c in {
                '\u200B', '\u200C', '\u200D', '\u2060',  # ZWSP, ZWNJ, ZWJ, WJ
                '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',  # Directional controls
                '\uFEFF'  # BOM
            }:
                removed.append((i, c, f'U+{ord(c):04X}'))
            else:
                visible_chars.append(c)
        return ''.join(visible_chars), removed

    def _get_script(self, c: str) -> str:
        """Get script for a character with fallback"""
        return self._script_map.get(c, 'Unknown')

    def check_label(self, label: str) -> dict:
        """Check a single label for homograph attacks"""
        # Initialize result structure
        result = {
            'input': label,
            'is_suspicious': False,
            'skeleton': '',
            'matched_whitelist': None,
            'reasons': [],
            'disallowed_scripts': [],
            'mixed_scripts': [],
            'invisible_chars_removed': [],
            'confusable_mappings': []
        }

        # Punycode decoding
        decoded_label = label
        if label.lower().startswith('xn--'):
            try:
                decoded_label = idna.decode(label)
                result['decoded'] = decoded_label
            except idna.IDNAError:
                result['reasons'].append('Punycode decoding failed')

        # Remove invisible characters
        clean_label, removed = self._remove_invisible_chars(decoded_label)
        if removed:
            result['invisible_chars_removed'] = removed
            result['reasons'].extend(
                f"Removed invisible character at pos {i}: {desc}"
                for i, c, desc in removed
            )
            result['is_suspicious'] = True

        # Compute skeleton
        skeleton = self._compute_skeleton(clean_label)
        result['skeleton'] = skeleton

        # Script analysis
        scripts_found = defaultdict(list)
        for i, c in enumerate(clean_label):
            script = self._get_script(c)
            scripts_found[script].append(i)
            
            # Check allowed scripts
            if script not in self._allowed_scripts and script not in ['Common', 'Inherited']:
                result['disallowed_scripts'].append((i, c, script))
        
        # Report disallowed scripts
        if result['disallowed_scripts']:
            for i, c, script in result['disallowed_scripts']:
                result['reasons'].append(
                    f"Disallowed script at pos {i}: {c} (U+{ord(c):04X}, {script})"
                )
            result['is_suspicious'] = True
        
        # Check mixed scripts
        non_common_scripts = [
            script for script in scripts_found.keys()
            if script not in ['Common', 'Inherited', 'Unknown'] and script in self._allowed_scripts
        ]
        if len(non_common_scripts) > 1:
            result['mixed_scripts'] = non_common_scripts
            result['reasons'].append(
                f"Mixed scripts detected: {', '.join(non_common_scripts)}"
            )
            result['is_suspicious'] = True
        
        # Check against whitelist
        for trusted, trusted_skeleton in self._whitelist_skeletons.items():
            if skeleton == trusted_skeleton:
                result['matched_whitelist'] = trusted
                if label != trusted:
                    result['reasons'].append(
                        f"Skeleton matches trusted '{trusted}' but raw input differs"
                    )
                    result['is_suspicious'] = True
                break
        
        # Record confusable mappings
        for i, c in enumerate(clean_label):
            if c in self._confusables_map:
                original_char = f"U+{ord(c):04X}"
                mapped_to = self._confusables_map[c]
                result['confusable_mappings'].append((i, original_char, mapped_to))
                result['reasons'].append(
                    f"Confusable at pos {i}: {c} ({original_char}) → '{mapped_to}'"
                )
        
        return result

def main():
    parser = argparse.ArgumentParser(description='Detect Unicode homograph attacks')
    parser.add_argument('input', help='Input string to check')
    parser.add_argument('--whitelist', help='Path to JSON whitelist file')
    parser.add_argument('--update-data', action='store_true', help='Update Unicode data files')
    args = parser.parse_args()

    # Load whitelist if provided
    whitelist = set()
    if args.whitelist:
        try:
            with open(args.whitelist, 'r') as f:
                whitelist = set(json.load(f))
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    # Initialize detector
    detector = HomographDetector(
        allowed_scripts={'Latin', 'Common', 'Inherited'},
        whitelist=whitelist
    )

    # Check input
    result = detector.check_label(args.input)

    # Format output
    if result['is_suspicious']:
        print("WARNING: possible homograph attack!")
        for reason in result['reasons']:
            print(f"  • {reason}")
    else:
        print(f"OK: \"{args.input}\" is safe")

if __name__ == '__main__':
    main()