import os
import importlib.util
import sys

class PluginManager:
    def __init__(self, plugin_dir='plugins'):
        self.plugin_dir = plugin_dir
        self.plugins = []

    def load_plugins(self):
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py"):
                self.load_plugin(os.path.join(self.plugin_dir, filename))

    def load_plugin(self, path):
        name = os.path.basename(path).replace(".py", "")
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
                
                if hasattr(module, 'register'):
                    plugin_instance = module.register()
                    self.plugins.append(plugin_instance)
                    print(f"Loaded plugin: {name}")
        except Exception as e:
            print(f"Failed to load plugin {name}: {e}")

    def run_hook(self, hook_name, *args, **kwargs):
        results = []
        for plugin in self.plugins:
            if hasattr(plugin, hook_name):
                try:
                    func = getattr(plugin, hook_name)
                    res = func(*args, **kwargs)
                    results.append(res)
                except Exception as e:
                    print(f"Error in plugin {plugin}: {e}")
        return results
