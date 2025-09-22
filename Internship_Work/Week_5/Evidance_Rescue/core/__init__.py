# EvidenceRescue core package
# core/__init__.py
"""
Core helpers for evidence_rescue.
Expose commonly-used helpers at package level.
"""
from .repo_utils import ensure_dir, safe_write_text
from .entropy import shannon_entropy
from .fs_parser import enumerate_filesystem, extract_file_by_meta
from .report import write_filesystem_tree, write_detailed_report, write_extensions_list, write_encrypted_report
from .analyze import detect_encrypted_candidates

__all__ = [
    'ensure_dir', 'safe_write_text',
    'shannon_entropy',
    'enumerate_filesystem', 'extract_file_by_meta',
    'write_filesystem_tree', 'write_detailed_report', 'write_extensions_list', 'write_encrypted_report',
    'detect_encrypted_candidates'
]

