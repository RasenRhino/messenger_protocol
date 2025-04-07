from setuptools import setup, find_packages

setup(
    name="crypto_utils",
    version="0.1",
    description="Shared cryptographic utilities for protocol implementation",
    author="SanDiego",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "cryptography",
        "base64"
    ],
    python_requires=">=3.7"
)
