"""
plugins/__init__.py
Plugin loader and registry.
"""
import importlib

def load_plugins(config):
    plugins = {}
    for p in config.enabled_plugins:
        try:
            mod = importlib.import_module(f"plugins.{p}")
            plugin = getattr(mod, "Plugin")(config=config)
            plugins[p] = plugin
        except Exception as e:
            print(f"Failed to load plugin {p}: {e}")
    return plugins
