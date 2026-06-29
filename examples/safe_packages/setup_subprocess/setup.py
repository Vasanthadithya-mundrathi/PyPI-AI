import subprocess

from setuptools import setup


def demo_install_surface() -> None:
    subprocess.call(["echo", "safe-demo-only"])


setup(name="setup-subprocess-demo", version="0.1.0")
