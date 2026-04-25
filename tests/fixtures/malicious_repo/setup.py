from setuptools import setup
from setuptools.command.install import install


class CustomInstall(install):
    def run(self):
        # Lifecycle hook would normally run shell here.
        super().run()


setup(
    name="evilpkg",
    version="0.0.1",
    cmdclass={"install": CustomInstall},
)
