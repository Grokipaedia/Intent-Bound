"""
Intent-Bound Authorization (IBA) - Setup Configuration
Author: IntentBound Research
License: Apache 2.0
Patent Pending: GB2603013.0 · Filed 5th February 2026
NIST Filed: NIST-2025-0035 · mls-ubpf-pryy
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="iba-agentic-security",
    version="0.1.0",
    author="IntentBound Research",
    author_email="IBA@intentbound.com",
    description="Intent-Bound Authorization (IBA) — cryptographic authorization for autonomous AI agents. Patent Pending GB2603013.0. NIST-2025-0035 filed.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Grokipaedia/Intent-Bound",
    project_urls={
        "Homepage": "https://intentbound.com",
        "Documentation": "https://intentbound.com/agents-html/",
        "Live Demos": "https://intentbound.com",
        "Bug Tracker": "https://github.com/Grokipaedia/Intent-Bound/issues",
        "NIST Filing": "https://intentbound.com/mandate-html/",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    packages=find_packages(exclude=["tests", "examples", "docs"]),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "iba=iba:quick_start",
        ],
    },
    keywords="intent authorization security ai agents autonomous governance agentic AI safety NIST",
    include_package_data=True,
    zip_safe=False,
)
