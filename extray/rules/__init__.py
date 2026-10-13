import importlib
import inspect
import pkgutil

from extray.rules.base import Rule

PACKAGES = ("extray.rules.vulns", "extray.rules.malware")


def load_rules() -> list[Rule]:
    """Instantiate every Rule subclass defined in rules/vulns and rules/malware."""
    rules = []
    for package in PACKAGES:
        for module in pkgutil.iter_modules(importlib.import_module(package).__path__):
            mod = importlib.import_module(f"{package}.{module.name}")
            rules += [cls() for _, cls in inspect.getmembers(mod, inspect.isclass)
                      if issubclass(cls, Rule) and cls.__module__ == mod.__name__]
    return rules
